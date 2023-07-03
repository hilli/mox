// Package mtasts implements MTA-STS (SMTP MTA Strict Transport Security, RFC 8461)
// which allows a domain to specify SMTP TLS requirements.
//
// SMTP for message delivery to a remote mail server always starts out unencrypted,
// in plain text. STARTTLS allows upgrading the connection to TLS, but is optional
// and by default mail servers will fall back to plain text communication if
// STARTTLS does not work (which can be sabotaged by DNS manipulation or SMTP
// connection manipulation). MTA-STS can specify a policy for requiring STARTTLS to
// be used for message delivery. A TXT DNS record at "_mta-sts.<domain>" specifies
// the version of the policy, and
// "https://mta-sts.<domain>/.well-known/mta-sts.txt" serves the policy.
package mtasts

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"

	"github.com/mjl-/mox/dns"
	"github.com/mjl-/mox/metrics"
	"github.com/mjl-/mox/mlog"
	"github.com/mjl-/mox/moxio"
)

var xlog = mlog.New("mtasts")

var (
	metricGet = promauto.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "mox_mtasts_get_duration_seconds",
			Help:    "MTA-STS get of policy, including lookup, duration and result.",
			Buckets: []float64{0.01, 0.05, 0.100, 0.5, 1, 5, 10, 20},
		},
		[]string{
			"result", // ok, lookuperror, fetcherror
		},
	)
)

// Pair is an extension key/value pair in a MTA-STS DNS record or policy.
type Pair struct {
	Key   string
	Value string
}

// Record is an MTA-STS DNS record, served under "_mta-sts.<domain>" as a TXT
// record.
//
// Example:
//
//	v=STSv1; id=20160831085700Z
type Record struct {
	Version    string // "STSv1", for "v=". Required.
	ID         string // Record version, for "id=". Required.
	Extensions []Pair // Optional extensions.
}

// String returns a textual version of the MTA-STS record for use as DNS TXT
// record.
func (r Record) String() string {
	b := &strings.Builder{}
	fmt.Fprint(b, "v="+r.Version)
	fmt.Fprint(b, "; id="+r.ID)
	for _, p := range r.Extensions {
		fmt.Fprint(b, "; "+p.Key+"="+p.Value)
	}
	return b.String()
}

// Mode indicates how the policy should be interpreted.
type Mode string

// ../rfc/8461:655

const (
	ModeEnforce Mode = "enforce" // Policy must be followed, i.e. deliveries must fail if a TLS connection cannot be made.
	ModeTesting Mode = "testing" // In case TLS cannot be negotiated, plain SMTP can be used, but failures must be reported, e.g. with TLS-RPT.
	ModeNone    Mode = "none"    // In case MTA-STS is not or no longer implemented.
)

// STSMX is an allowlisted MX host name/pattern.
// todo: find a way to name this just STSMX without getting duplicate names for "MX" in the sherpa api.
type STSMX struct {
	// "*." wildcard, e.g. if a subdomain matches. A wildcard must match exactly one
	// label. *.example.com matches mail.example.com, but not example.com, and not
	// foor.bar.example.com.
	Wildcard bool

	Domain dns.Domain
}

// LogString returns a loggable string representing the host, with both unicode
// and ascii version for IDNA domains.
func (s STSMX) LogString() string {
	pre := ""
	if s.Wildcard {
		pre = "*."
	}
	if s.Domain.Unicode == "" {
		return pre + s.Domain.ASCII
	}
	return pre + s.Domain.Unicode + "/" + pre + s.Domain.ASCII
}

// Policy is an MTA-STS policy as served at "https://mta-sts.<domain>/.well-known/mta-sts.txt".
type Policy struct {
	Version       string // "STSv1"
	Mode          Mode
	MX            []STSMX
	MaxAgeSeconds int // How long this policy can be cached. Suggested values are in weeks or more.
	Extensions    []Pair
}

// String returns a textual representation for serving at the well-known URL.
func (p Policy) String() string {
	b := &strings.Builder{}
	line := func(k, v string) {
		fmt.Fprint(b, k+": "+v+"\n")
	}
	line("version", p.Version)
	line("mode", string(p.Mode))
	line("max_age", fmt.Sprintf("%d", p.MaxAgeSeconds))
	for _, mx := range p.MX {
		s := mx.Domain.Name()
		if mx.Wildcard {
			s = "*." + s
		}
		line("mx", s)
	}
	return b.String()
}

// Matches returns whether the hostname matches the mx list in the policy.
func (p *Policy) Matches(host dns.Domain) bool {
	// ../rfc/8461:636
	for _, mx := range p.MX {
		if mx.Wildcard {
			v := strings.SplitN(host.ASCII, ".", 2)
			if len(v) == 2 && v[1] == mx.Domain.ASCII {
				return true
			}
		} else if host == mx.Domain {
			return true
		}
	}
	return false
}

// Lookup errors.
var (
	ErrNoRecord        = errors.New("mtasts: no mta-sts dns txt record") // Domain does not implement MTA-STS. If a cached non-expired policy is available, it should still be used.
	ErrMultipleRecords = errors.New("mtasts: multiple mta-sts records")  // Should be treated as if domain does not implement MTA-STS, unless a cached non-expired policy is available.
	ErrDNS             = errors.New("mtasts: dns lookup")                // For temporary DNS errors.
	ErrRecordSyntax    = errors.New("mtasts: record syntax error")
)

// LookupRecord looks up the MTA-STS TXT DNS record at "_mta-sts.<domain>",
// following CNAME records, and returns the parsed MTA-STS record, the DNS TXT
// record and any CNAMEs that were followed.
func LookupRecord(ctx context.Context, resolver dns.Resolver, domain dns.Domain) (rrecord *Record, rtxt string, rcnames []string, rerr error) {
	log := xlog.WithContext(ctx)
	start := time.Now()
	defer func() {
		log.Debugx("mtasts lookup result", rerr, mlog.Field("domain", domain), mlog.Field("record", rrecord), mlog.Field("cnames", rcnames), mlog.Field("duration", time.Since(start)))
	}()

	// ../rfc/8461:289
	// ../rfc/8461:351
	// We lookup the txt record, but must follow CNAME records when the TXT does not exist.
	var cnames []string
	name := "_mta-sts." + domain.ASCII + "."
	var txts []string
	for {
		var err error
		txts, err = dns.WithPackage(resolver, "mtasts").LookupTXT(ctx, name)
		if dns.IsNotFound(err) {
			// DNS has no specified limit on how many CNAMEs to follow. Chains of 10 CNAMEs
			// have been seen on the internet.
			if len(cnames) > 16 {
				return nil, "", cnames, fmt.Errorf("too many cnames")
			}
			cname, err := dns.WithPackage(resolver, "mtasts").LookupCNAME(ctx, name)
			if dns.IsNotFound(err) {
				return nil, "", cnames, ErrNoRecord
			}
			if err != nil {
				return nil, "", cnames, fmt.Errorf("%w: %s", ErrDNS, err)
			}
			cnames = append(cnames, cname)
			name = cname
			continue
		} else if err != nil {
			return nil, "", cnames, fmt.Errorf("%w: %s", ErrDNS, err)
		} else {
			break
		}
	}

	var text string
	var record *Record
	for _, txt := range txts {
		r, ismtasts, err := ParseRecord(txt)
		if !ismtasts {
			// ../rfc/8461:331 says we should essentially treat a record starting with e.g.
			// "v=STSv1 ;" (note the space) as a non-STS record too in case of multiple TXT
			// records. We treat it as an STS record that is invalid, which is possibly more
			// reasonable.
			continue
		}
		if err != nil {
			return nil, "", cnames, err
		}
		if record != nil {
			return nil, "", cnames, ErrMultipleRecords
		}
		record = r
		text = txt
	}
	if record == nil {
		return nil, "", cnames, ErrNoRecord
	}
	return record, text, cnames, nil
}

// Policy fetch errors.
var (
	ErrNoPolicy     = errors.New("mtasts: no policy served")    // If the name "mta-sts.<domain>" does not exist in DNS or if webserver returns HTTP status 404 "File not found".
	ErrPolicyFetch  = errors.New("mtasts: cannot fetch policy") // E.g. for HTTP request errors.
	ErrPolicySyntax = errors.New("mtasts: policy syntax error")
)

// HTTPClient is used by FetchPolicy for HTTP requests.
var HTTPClient = &http.Client{
	CheckRedirect: func(req *http.Request, via []*http.Request) error {
		return fmt.Errorf("redirect not allowed for MTA-STS policies") // ../rfc/8461:549
	},
}

// FetchPolicy fetches a new policy for the domain, at
// https://mta-sts.<domain>/.well-known/mta-sts.txt.
//
// FetchPolicy returns the parsed policy and the literal policy text as fetched
// from the server. If a policy was fetched but could not be parsed, the policyText
// return value will be set.
//
// Policies longer than 64KB result in a syntax error.
//
// If an error is returned, callers should back off for 5 minutes until the next
// attempt.
func FetchPolicy(ctx context.Context, domain dns.Domain) (policy *Policy, policyText string, rerr error) {
	log := xlog.WithContext(ctx)
	start := time.Now()
	defer func() {
		log.Debugx("mtasts fetch policy result", rerr, mlog.Field("domain", domain), mlog.Field("policy", policy), mlog.Field("policytext", policyText), mlog.Field("duration", time.Since(start)))
	}()

	// Timeout of 1 minute. ../rfc/8461:569
	ctx, cancel := context.WithTimeout(ctx, time.Minute)
	defer cancel()

	// TLS requirements are what the Go standard library checks: trusted, non-expired,
	// hostname validated against DNS-ID supporting wildcard. ../rfc/8461:524
	url := "https://mta-sts." + domain.Name() + "/.well-known/mta-sts.txt"
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, "", fmt.Errorf("%w: http request: %s", ErrPolicyFetch, err)
	}
	// We are not likely to reuse a connection: we cache policies and negative DNS
	// responses. So don't keep connections open unnecessarily.
	req.Close = true

	resp, err := HTTPClient.Do(req)
	if dns.IsNotFound(err) {
		return nil, "", ErrNoPolicy
	}
	if err != nil {
		return nil, "", fmt.Errorf("%w: http get: %s", ErrPolicyFetch, err)
	}
	metrics.HTTPClientObserve(ctx, "mtasts", req.Method, resp.StatusCode, err, start)
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		return nil, "", ErrNoPolicy
	}
	if resp.StatusCode != http.StatusOK {
		// ../rfc/8461:548
		return nil, "", fmt.Errorf("%w: http status %s while status 200 is required", ErrPolicyFetch, resp.Status)
	}

	// We don't look at Content-Type and charset. It should be ASCII or UTF-8, we'll
	// just always whatever is sent as UTF-8. ../rfc/8461:367

	// ../rfc/8461:570
	buf, err := io.ReadAll(&moxio.LimitReader{R: resp.Body, Limit: 64 * 1024})
	if err != nil {
		return nil, "", fmt.Errorf("%w: reading policy: %s", ErrPolicySyntax, err)
	}
	policyText = string(buf)
	policy, err = ParsePolicy(policyText)
	if err != nil {
		return nil, policyText, fmt.Errorf("parsing policy: %w", err)
	}
	return policy, policyText, nil
}

// Get looks up the MTA-STS DNS record and fetches the policy.
//
// Errors can be those returned by LookupRecord and FetchPolicy.
//
// If a valid policy cannot be retrieved, a sender must treat the domain as not
// implementing MTA-STS. If a sender has a non-expired cached policy, that policy
// would still apply.
//
// If a record was retrieved, but a policy could not be retrieved/parsed, the
// record is still returned.
//
// Also see Get in package mtastsdb.
func Get(ctx context.Context, resolver dns.Resolver, domain dns.Domain) (record *Record, policy *Policy, err error) {
	log := xlog.WithContext(ctx)
	start := time.Now()
	result := "lookuperror"
	defer func() {
		metricGet.WithLabelValues(result).Observe(float64(time.Since(start)) / float64(time.Second))
		log.Debugx("mtasts get result", err, mlog.Field("domain", domain), mlog.Field("record", record), mlog.Field("policy", policy), mlog.Field("duration", time.Since(start)))
	}()

	record, _, _, err = LookupRecord(ctx, resolver, domain)
	if err != nil {
		return nil, nil, err
	}

	result = "fetcherror"
	policy, _, err = FetchPolicy(ctx, domain)
	if err != nil {
		return record, nil, err
	}

	result = "ok"
	return record, policy, nil
}

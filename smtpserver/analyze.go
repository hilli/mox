package smtpserver

import (
	"context"
	"fmt"
	"net"
	"os"
	"time"

	"github.com/mjl-/bstore"

	"github.com/mjl-/mox/dkim"
	"github.com/mjl-/mox/dmarc"
	"github.com/mjl-/mox/dmarcrpt"
	"github.com/mjl-/mox/dns"
	"github.com/mjl-/mox/dnsbl"
	"github.com/mjl-/mox/iprev"
	"github.com/mjl-/mox/mlog"
	"github.com/mjl-/mox/mox-"
	"github.com/mjl-/mox/smtp"
	"github.com/mjl-/mox/store"
	"github.com/mjl-/mox/subjectpass"
	"github.com/mjl-/mox/tlsrpt"
)

type delivery struct {
	m           *store.Message
	dataFile    *os.File
	rcptAcc     rcptAccount
	acc         *store.Account
	msgFrom     smtp.Address
	dnsBLs      []dns.Domain
	dmarcUse    bool
	dmarcResult dmarc.Result
	dkimResults []dkim.Result
	iprevStatus iprev.Status
}

type analysis struct {
	accept      bool
	code        int
	secode      string
	userError   bool
	errmsg      string
	err         error              // For our own logging, not sent to remote.
	dmarcReport *dmarcrpt.Feedback // Validated dmarc aggregate report, not yet stored.
	tlsReport   *tlsrpt.Report     // Validated TLS report, not yet stored.
	reason      string             // If non-empty, reason for this decision. Can be one of reputationMethod and a few other tokens.
}

const (
	reasonListAllow         = "list-allow"
	reasonDMARCPolicy       = "dmarc-policy"
	reasonReputationError   = "reputation-error"
	reasonReporting         = "reporting"
	reasonSPFPolicy         = "spf-policy"
	reasonJunkClassifyError = "junk-classify-error"
	reasonJunkFilterError   = "junk-filter-error"
	reasonGiveSubjectpass   = "give-subjectpass"
	reasonNoBadSignals      = "no-bad-signals"
	reasonJunkContent       = "junk-content"
	reasonJunkContentStrict = "junk-content-strict"
	reasonDNSBlocklisted    = "dns-blocklisted"
	reasonSubjectpass       = "subjectpass"
	reasonSubjectpassError  = "subjectpass-error"
	reasonIPrev             = "iprev" // No or mil junk reputation signals, and bad iprev.
)

func analyze(ctx context.Context, log *mlog.Log, resolver dns.Resolver, d delivery) analysis {
	reject := func(code int, secode string, errmsg string, err error, reason string) analysis {
		return analysis{false, code, secode, err == nil, errmsg, err, nil, nil, reason}
	}

	// If destination mailbox has a mailing list domain (for SPF/DKIM) configured,
	// check it for a pass.
	// todo: should use this evaluation for final delivery as well
	rs := store.MessageRuleset(log, d.rcptAcc.destination, d.m, d.m.MsgPrefix, d.dataFile)
	if rs != nil && !rs.ListAllowDNSDomain.IsZero() {
		ld := rs.ListAllowDNSDomain
		// todo: on temporary failures, reject temporarily?
		if d.m.MailFromValidated && ld.Name() == d.m.MailFromDomain {
			return analysis{accept: true, reason: reasonListAllow}
		}
		for _, r := range d.dkimResults {
			if r.Status == dkim.StatusPass && r.Sig.Domain == ld {
				return analysis{accept: true, reason: reasonListAllow}
			}
		}
	}

	if d.dmarcUse && d.dmarcResult.Reject {
		return reject(smtp.C550MailboxUnavail, smtp.SePol7MultiAuthFails26, "rejecting per dmarc policy", nil, reasonDMARCPolicy)
	}
	// todo: should we also reject messages that have a dmarc pass but an spf record "v=spf1 -all"? suggested by m3aawg best practices.

	// If destination is the DMARC reporting mailbox, do additional checks and keep
	// track of the report. We'll check reputation, defaulting to accept.
	var dmarcReport *dmarcrpt.Feedback
	if d.rcptAcc.destination.DMARCReports {
		// Messages with DMARC aggregate reports must have a dmarc pass. ../rfc/7489:1866
		if d.dmarcResult.Status != dmarc.StatusPass {
			log.Info("received dmarc report without dmarc pass, not processing as dmarc report")
		} else if report, err := dmarcrpt.ParseMessageReport(store.FileMsgReader(d.m.MsgPrefix, d.dataFile)); err != nil {
			log.Infox("parsing dmarc report", err)
		} else if d, err := dns.ParseDomain(report.PolicyPublished.Domain); err != nil {
			log.Infox("parsing domain in dmarc report", err)
		} else if _, ok := mox.Conf.Domain(d); !ok {
			log.Info("dmarc report for domain not configured, ignoring", mlog.Field("domain", d))
		} else if report.ReportMetadata.DateRange.End > time.Now().Unix()+60 {
			log.Info("dmarc report with end date in the future, ignoring", mlog.Field("domain", d), mlog.Field("end", time.Unix(report.ReportMetadata.DateRange.End, 0)))
		} else {
			dmarcReport = report
		}
	}

	// Similar to DMARC reporting, we check for the required DKIM. We'll check
	// reputation, defaulting to accept.
	var tlsReport *tlsrpt.Report
	if d.rcptAcc.destination.TLSReports {
		// Valid DKIM signature for domain must be present. We take "valid" to assume
		// "passing", not "syntactically valid". We also check for "tlsrpt" as service.
		// This check is optional, but if anyone goes through the trouble to explicitly
		// list allowed services, they would be surprised to see them ignored.
		// ../rfc/8460:320
		ok := false
		for _, r := range d.dkimResults {
			if r.Status == dkim.StatusPass && r.Sig.Domain == d.msgFrom.Domain && r.Sig.Length < 0 && r.Record.ServiceAllowed("tlsrpt") {
				ok = true
				break
			}
		}

		if !ok {
			log.Info("received mail to tlsrpt without acceptable DKIM signature, not processing as tls report")
		} else if report, err := tlsrpt.ParseMessage(store.FileMsgReader(d.m.MsgPrefix, d.dataFile)); err != nil {
			log.Infox("parsing tls report", err)
		} else {
			var known bool
			for _, p := range report.Policies {
				log.Info("tlsrpt policy domain", mlog.Field("domain", p.Policy.Domain))
				if d, err := dns.ParseDomain(p.Policy.Domain); err != nil {
					log.Infox("parsing domain in tls report", err)
				} else if _, ok := mox.Conf.Domain(d); ok {
					known = true
					break
				}
			}
			if !known {
				log.Info("tls report without one of configured domains, ignoring")
			} else {
				tlsReport = report
			}
		}
	}

	// Determine if message is acceptable based on DMARC domain, DKIM identities, or
	// host-based reputation.
	var isjunk *bool
	var conclusive bool
	var method reputationMethod
	var reason string
	var err error
	d.acc.WithRLock(func() {
		err = d.acc.DB.Read(ctx, func(tx *bstore.Tx) error {
			// Set message MailboxID to which mail will be delivered. Reputation is
			// per-mailbox. If referenced mailbox is not found (e.g. does not yet exist), we
			// can still determine a reputation because we also base it on outgoing
			// messages and those are account-global.
			mailbox := d.rcptAcc.destination.Mailbox
			if mailbox == "" {
				mailbox = "Inbox"
			}
			if rs != nil {
				mailbox = rs.Mailbox
			}
			mb, err := d.acc.MailboxFind(tx, mailbox)
			if err != nil {
				return fmt.Errorf("finding destination mailbox: %w", err)
			}
			if mb != nil {
				// We want to deliver to mb.ID, but this message may be rejected and sent to the
				// Rejects mailbox instead, which MailboxID overwritten. Record the ID in
				// MailboxDestinedID too. If the message is later moved out of the Rejects mailbox,
				// we'll adjust the MailboxOrigID so it gets taken into account during reputation
				// calculating in future deliveries. If we end up delivering to the intended
				// mailbox (i.e. not rejecting), MailboxDestinedID is cleared during delivery so we
				// don't store it unnecessarily.
				d.m.MailboxID = mb.ID
				d.m.MailboxDestinedID = mb.ID
			} else {
				log.Debug("mailbox not found in database", mlog.Field("mailbox", mailbox))
			}

			isjunk, conclusive, method, err = reputation(tx, log, d.m)
			reason = string(method)
			return err
		})
	})
	if err != nil {
		log.Infox("determining reputation", err, mlog.Field("message", d.m))
		return reject(smtp.C451LocalErr, smtp.SeSys3Other0, "error processing", err, reasonReputationError)
	}
	log.Info("reputation analyzed", mlog.Field("conclusive", conclusive), mlog.Field("isjunk", isjunk), mlog.Field("method", string(method)))
	if conclusive {
		if !*isjunk {
			return analysis{accept: true, dmarcReport: dmarcReport, tlsReport: tlsReport, reason: reason}
		}
		return reject(smtp.C451LocalErr, smtp.SeSys3Other0, "error processing", err, string(method))
	} else if dmarcReport != nil || tlsReport != nil {
		log.Info("accepting dmarc reporting or tlsrpt message without reputation")
		return analysis{accept: true, dmarcReport: dmarcReport, tlsReport: tlsReport, reason: reasonReporting}
	}
	// If there was no previous message from sender or its domain, and we have an SPF
	// (soft)fail, reject the message.
	switch method {
	case methodDKIMSPF, methodIP1, methodIP2, methodIP3, methodNone:
		switch d.m.MailFromValidation {
		case store.ValidationFail, store.ValidationSoftfail:
			return reject(smtp.C451LocalErr, smtp.SeSys3Other0, "error processing", nil, reasonSPFPolicy)
		}
	}

	// Senders without reputation and without iprev pass, are likely spam.
	var suspiciousIPrevFail bool
	switch method {
	case methodDKIMSPF, methodIP1, methodIP2, methodIP3, methodNone:
		suspiciousIPrevFail = d.iprevStatus != iprev.StatusPass
	}

	// With already a mild junk signal, an iprev fail on top is enough to reject.
	if suspiciousIPrevFail && isjunk != nil && *isjunk {
		return reject(smtp.C451LocalErr, smtp.SeSys3Other0, "error processing", nil, reasonIPrev)
	}

	var subjectpassKey string
	conf, _ := d.acc.Conf()
	if conf.SubjectPass.Period > 0 {
		subjectpassKey, err = d.acc.Subjectpass(d.rcptAcc.canonicalAddress)
		if err != nil {
			log.Errorx("get key for verifying subject token", err)
			return reject(smtp.C451LocalErr, smtp.SeSys3Other0, "error processing", err, reasonSubjectpassError)
		}
		err = subjectpass.Verify(d.dataFile, []byte(subjectpassKey), conf.SubjectPass.Period)
		pass := err == nil
		log.Infox("pass by subject token", err, mlog.Field("pass", pass))
		if pass {
			return analysis{accept: true, reason: reasonSubjectpass}
		}
	}

	reason = reasonNoBadSignals
	accept := true
	var junkSubjectpass bool
	f, jf, err := d.acc.OpenJunkFilter(ctx, log)
	if err == nil {
		defer func() {
			err := f.Close()
			log.Check(err, "closing junkfilter")
		}()
		contentProb, _, _, _, err := f.ClassifyMessageReader(ctx, store.FileMsgReader(d.m.MsgPrefix, d.dataFile), d.m.Size)
		if err != nil {
			log.Errorx("testing for spam", err)
			return reject(smtp.C451LocalErr, smtp.SeSys3Other0, "error processing", err, reasonJunkClassifyError)
		}
		// todo: if isjunk is not nil (i.e. there was inconclusive reputation), use it in the probability calculation. give reputation a score of 0.25 or .75 perhaps?
		// todo: if there aren't enough historic messages, we should just let messages in.
		// todo: we could require nham and nspam to be above a certain number when there were plenty of words in the message, and in the database. can indicate a spammer is misspelling words. however, it can also mean a message in a different language/script...

		// If we don't accept, we may still respond with a "subjectpass" hint below.
		// We add some jitter to the threshold we use. So we don't act as too easy an
		// oracle for words that are a strong indicator of haminess.
		// todo: we should rate-limit uses of the junkfilter.
		jitter := (jitterRand.Float64() - 0.5) / 10
		threshold := jf.Threshold + jitter

		// With an iprev fail, we set a higher bar for content.
		reason = reasonJunkContent
		if suspiciousIPrevFail && threshold > 0.25 {
			threshold = 0.25
			log.Info("setting junk threshold due to iprev fail", mlog.Field("threshold", 0.25))
			reason = reasonJunkContentStrict
		}
		accept = contentProb <= threshold
		junkSubjectpass = contentProb < threshold-0.2
		log.Info("content analyzed", mlog.Field("accept", accept), mlog.Field("contentprob", contentProb), mlog.Field("subjectpass", junkSubjectpass))
	} else if err != store.ErrNoJunkFilter {
		log.Errorx("open junkfilter", err)
		return reject(smtp.C451LocalErr, smtp.SeSys3Other0, "error processing", err, reasonJunkFilterError)
	}

	// If content looks good, we'll still look at DNS block lists for a reason to
	// reject. We normally won't get here if we've communicated with this sender
	// before.
	var dnsblocklisted bool
	if accept {
		blocked := func(zone dns.Domain) bool {
			dnsblctx, dnsblcancel := context.WithTimeout(ctx, 30*time.Second)
			defer dnsblcancel()
			if !checkDNSBLHealth(dnsblctx, resolver, zone) {
				log.Info("dnsbl not healthy, skipping", mlog.Field("zone", zone))
				return false
			}

			status, expl, err := dnsbl.Lookup(dnsblctx, resolver, zone, net.ParseIP(d.m.RemoteIP))
			dnsblcancel()
			if status == dnsbl.StatusFail {
				log.Info("rejecting due to listing in dnsbl", mlog.Field("zone", zone), mlog.Field("explanation", expl))
				return true
			} else if err != nil {
				log.Infox("dnsbl lookup", err, mlog.Field("zone", zone), mlog.Field("status", status))
			}
			return false
		}

		// Note: We don't check in parallel, we are in no hurry to accept possible spam.
		for _, zone := range d.dnsBLs {
			if blocked(zone) {
				accept = false
				dnsblocklisted = true
				reason = reasonDNSBlocklisted
				break
			}
		}
	}

	if accept {
		return analysis{accept: true, reason: reasonNoBadSignals}
	}

	if subjectpassKey != "" && d.dmarcResult.Status == dmarc.StatusPass && method == methodNone && (dnsblocklisted || junkSubjectpass) {
		log.Info("permanent reject with subjectpass hint of moderately spammy email without reputation")
		pass := subjectpass.Generate(d.msgFrom, []byte(subjectpassKey), time.Now())
		return reject(smtp.C550MailboxUnavail, smtp.SePol7DeliveryUnauth1, subjectpass.Explanation+pass, nil, reasonGiveSubjectpass)
	}

	return reject(smtp.C451LocalErr, smtp.SeSys3Other0, "error processing", nil, reason)
}

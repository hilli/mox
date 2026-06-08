// Package srs implements the Sender Rewriting Scheme (SRS) used when a mail
// server forwards a message to a third party.
//
// When mox forwards a message (e.g. via a Sieve "redirect" action), the message
// leaves mox with the original envelope sender (MAIL FROM) intact. The receiving
// server then evaluates SPF for that original sender domain against mox's IP and,
// because mox is not listed in the original domain's SPF record, the check fails.
// SRS works around this by rewriting the envelope sender into a local address at
// a domain mox is authoritative for (and lists in its own SPF record), while
// encoding the original sender so that bounces (DSNs) can be decoded and relayed
// back to it.
//
// The scheme implemented here is the de-facto "Guarded" SRS by Shevek
// (https://www.libsrs2.org/srs/srs.pdf), the same wire format used by libsrs2,
// postsrsd and Exim/Postfix integrations, so rewritten addresses interoperate
// with other SRS-aware forwarders:
//
//		SRS0=HHHH=TT=origdomain=origlocal@forwarder.example
//		SRS1=HHHH=firsthop=SRS0content...@forwarder.example   (re-forwarded mail)
//
//	  - HHHH is a truncated, base64-encoded HMAC over the encoded fields, keyed by
//	    a server-wide secret. It authenticates the address so third parties cannot
//	    forge a rewritten sender and use mox as an open relay for bounces.
//	  - TT is a 2-character base32 day timestamp (modulo 1024 days). Reversal
//	    rejects addresses older than MaxAge, bounding the replay window.
//
// SRS only ever rewrites the SMTP envelope sender. It never touches the message
// headers, in particular not the "From:" header, so DKIM signatures and DMARC
// alignment of the original message are unaffected.
package srs

import (
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/mjl-/mox/dns"
	"github.com/mjl-/mox/smtp"
)

// Errors returned by Reverse. Callers distinguish ErrNotSRS (the address is a
// normal local address, fall through to regular delivery) from the verification
// failures (ErrInvalidHash/ErrExpired/ErrSyntax), which indicate a tampered or
// stale SRS address that must be rejected, not delivered.
var (
	// ErrNotSRS means the localpart is not an SRS-encoded address. The caller
	// should treat the recipient as an ordinary local address.
	ErrNotSRS = errors.New("srs: not an SRS address")
	// ErrInvalidHash means the HMAC did not verify: the address was forged or
	// corrupted. The bounce must be rejected to avoid acting as an open relay.
	ErrInvalidHash = errors.New("srs: invalid hash")
	// ErrExpired means the embedded timestamp is older than the allowed window.
	ErrExpired = errors.New("srs: address expired")
	// ErrSyntax means the address has the SRS prefix but is malformed.
	ErrSyntax = errors.New("srs: malformed SRS address")
)

const (
	prefix0 = "SRS0"
	prefix1 = "SRS1"

	// hashLength is the number of base64 characters of HMAC kept in the address.
	// This matches the libsrs2 default and balances address length against
	// forgery resistance (4 base64 chars ~= 24 bits).
	hashLength = 4

	// secondsPerDay is the SRS timestamp precision: timestamps count days.
	secondsPerDay = 60 * 60 * 24

	// timeSlots is the modulus for the 2-character base32 day timestamp
	// (32*32 = 1024). Roughly 2.8 years before the counter wraps.
	timeSlots = 1024

	// futureSlopDays tolerates a small amount of clock skew between the
	// rewriting and reversing hosts when validating timestamps.
	futureSlopDays = 1

	// timeAlphabet is the base32 alphabet for the 2-character day timestamp
	// (RFC 4648, no padding), matching the libsrs2 wire format.
	timeAlphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
)

// Config is the resolved SRS configuration: the signing secret and the domain
// rewritten senders are anchored at. MaxAge bounds how long a rewritten address
// remains valid for bounce reversal.
type Config struct {
	Secret []byte     // HMAC key, shared server-wide. Must be non-empty when enabled.
	Domain dns.Domain // Envelope-rewrite domain; must publish SPF authorising mox and have DKIM configured.
	MaxAge time.Duration
}

func (c Config) maxAgeDays() int64 {
	d := int64(c.MaxAge / (secondsPerDay * time.Second))
	if d <= 0 {
		d = 21 // libsrs2 default validity window.
	}
	return d
}

// Forward rewrites orig into an SRS sender anchored at cfg.Domain. The returned
// address is suitable as the new envelope MAIL FROM for a forwarded message.
//
// If orig is already an SRS address (a message that was itself forwarded to us),
// it is re-wrapped: an SRS0 becomes an SRS1 preserving the original first hop, so
// the bounce path can unwind multiple forwarding hops. orig must not be the null
// sender; callers must skip SRS rewriting for bounces (empty MAIL FROM).
func Forward(orig smtp.Address, cfg Config) (smtp.Address, error) {
	if len(cfg.Secret) == 0 {
		return smtp.Address{}, errors.New("srs: empty secret")
	}
	if orig.Localpart == "" {
		return smtp.Address{}, errors.New("srs: refusing to rewrite null sender")
	}

	local := string(orig.Localpart)
	origDomain := orig.Domain.Name()

	// Re-forwarding: rewrap an existing SRS address so we stay a single,
	// verifiable hop while preserving the original return path.
	if up := strings.ToUpper(local); strings.HasPrefix(up, prefix1+"=") || strings.HasPrefix(up, prefix0+"=") {
		return forwardExisting(local, origDomain, cfg)
	}

	ts := encodeTime(time.Now())
	payload := ts + "=" + origDomain + "=" + local
	h := computeHash(cfg.Secret, payload)
	lp := prefix0 + "=" + h + "=" + payload
	return smtp.Address{Localpart: smtp.Localpart(lp), Domain: cfg.Domain}, nil
}

// forwardExisting handles the re-forwarding case (de-facto SRS1). An SRS0 from an
// upstream forwarder at domain D is wrapped as SRS1=hash=D=<original SRS0 body>,
// so a bounce to us can be peeled one hop and relayed back to the upstream SRS0,
// which in turn decodes to the true sender.
func forwardExisting(local, origDomain string, cfg Config) (smtp.Address, error) {
	up := strings.ToUpper(local)
	switch {
	case strings.HasPrefix(up, prefix0+"="):
		body := local[len(prefix0)+1:] // strip "SRS0="
		payload := origDomain + "=" + body
		h := computeHash(cfg.Secret, payload)
		lp := prefix1 + "=" + h + "=" + payload
		return smtp.Address{Localpart: smtp.Localpart(lp), Domain: cfg.Domain}, nil
	case strings.HasPrefix(up, prefix1+"="):
		// Already an SRS1: re-sign the inner (firsthop + SRS0 body) for our domain
		// without adding another layer.
		rest := local[len(prefix1)+1:] // strip "SRS1="
		parts := strings.SplitN(rest, "=", 2)
		if len(parts) != 2 {
			return smtp.Address{}, ErrSyntax
		}
		payload := parts[1]
		h := computeHash(cfg.Secret, payload)
		lp := prefix1 + "=" + h + "=" + payload
		return smtp.Address{Localpart: smtp.Localpart(lp), Domain: cfg.Domain}, nil
	}
	return smtp.Address{}, ErrSyntax
}

// Reverse decodes an SRS recipient address (the RCPT TO of an inbound bounce)
// back to the address the bounce should be relayed to. For an SRS0 that is the
// original sender; for an SRS1 it is the upstream forwarder's SRS0 address (which
// that forwarder will reverse in turn).
//
// Reverse verifies the HMAC and the timestamp window. Callers MUST treat
// ErrNotSRS as "ordinary local address" and every other error as "reject": a bad
// hash or expired timestamp means the address is forged or stale and relaying it
// would make mox an open relay for backscatter.
func Reverse(rcpt smtp.Address, cfg Config) (smtp.Address, error) {
	if len(cfg.Secret) == 0 {
		return smtp.Address{}, errors.New("srs: empty secret")
	}
	local := string(rcpt.Localpart)
	up := strings.ToUpper(local)

	switch {
	case strings.HasPrefix(up, prefix0+"="):
		return reverseSRS0(local[len(prefix0)+1:], cfg)
	case strings.HasPrefix(up, prefix1+"="):
		return reverseSRS1(local[len(prefix1)+1:], cfg)
	default:
		return smtp.Address{}, ErrNotSRS
	}
}

// reverseSRS0 parses "hash=TT=origdomain=origlocal" (the SRS0 body) and returns
// origlocal@origdomain after verification.
func reverseSRS0(body string, cfg Config) (smtp.Address, error) {
	// hash, TT, origdomain, origlocal — origlocal may itself contain "=", so
	// split into at most 4 fields and keep the remainder as the localpart.
	parts := strings.SplitN(body, "=", 4)
	if len(parts) != 4 {
		return smtp.Address{}, ErrSyntax
	}
	hash, ts, origDomain, origLocal := parts[0], parts[1], parts[2], parts[3]

	payload := ts + "=" + origDomain + "=" + origLocal
	if !verifyHash(cfg.Secret, payload, hash) {
		return smtp.Address{}, ErrInvalidHash
	}
	if err := checkTime(ts, cfg.maxAgeDays()); err != nil {
		return smtp.Address{}, err
	}

	dom, err := dns.ParseDomain(origDomain)
	if err != nil {
		return smtp.Address{}, fmt.Errorf("%w: domain: %v", ErrSyntax, err)
	}
	return smtp.Address{Localpart: smtp.Localpart(origLocal), Domain: dom}, nil
}

// reverseSRS1 parses "hash=firsthop=SRS0body" and returns the reconstructed
// SRS0 address at the first-hop forwarder, which that host will reverse in turn.
// SRS1 carries no timestamp of its own; freshness is enforced by the upstream
// SRS0 when the relayed bounce reaches the first hop.
func reverseSRS1(body string, cfg Config) (smtp.Address, error) {
	parts := strings.SplitN(body, "=", 3)
	if len(parts) != 3 {
		return smtp.Address{}, ErrSyntax
	}
	hash, firstHop, srs0body := parts[0], parts[1], parts[2]

	if !verifyHash(cfg.Secret, firstHop+"="+srs0body, hash) {
		return smtp.Address{}, ErrInvalidHash
	}
	dom, err := dns.ParseDomain(firstHop)
	if err != nil {
		return smtp.Address{}, fmt.Errorf("%w: firsthop: %v", ErrSyntax, err)
	}
	return smtp.Address{Localpart: smtp.Localpart(prefix0 + "=" + srs0body), Domain: dom}, nil
}

// IsSRS reports whether lp is an SRS-encoded localpart. Used as a cheap guard
// before attempting Reverse, and to avoid treating SRS bounces as new accounts.
func IsSRS(lp smtp.Localpart) bool {
	up := strings.ToUpper(string(lp))
	return strings.HasPrefix(up, prefix0+"=") || strings.HasPrefix(up, prefix1+"=")
}

func computeHash(secret []byte, payload string) string {
	mac := hmac.New(sha1.New, secret)
	// SRS hashing is case-insensitive on the payload so address canonicalisation
	// by intermediate hops does not break verification.
	mac.Write([]byte(strings.ToLower(payload)))
	sum := mac.Sum(nil)
	enc := base64.StdEncoding.EncodeToString(sum)
	if len(enc) > hashLength {
		enc = enc[:hashLength]
	}
	return enc
}

func verifyHash(secret []byte, payload, got string) bool {
	want := computeHash(secret, payload)
	// Compare case-insensitively (some hops lowercase the localpart) in constant
	// time over a fixed-length, lowercased representation.
	return hmac.Equal([]byte(strings.ToLower(want)), []byte(strings.ToLower(got)))
}

func encodeTime(t time.Time) string {
	day := t.Unix() / secondsPerDay
	slot := uint16(day % timeSlots)
	// Two base32 chars encode 10 bits; emit high then low for stable ordering.
	hi := timeAlphabet[slot>>5&0x1f]
	lo := timeAlphabet[slot&0x1f]
	return string([]byte{hi, lo})
}

func decodeTime(ts string) (int64, error) {
	if len(ts) != 2 {
		return 0, ErrSyntax
	}
	hi := indexBase32(ts[0])
	lo := indexBase32(ts[1])
	if hi < 0 || lo < 0 {
		return 0, ErrSyntax
	}
	return int64(hi)*32 + int64(lo), nil
}

func indexBase32(c byte) int {
	c = byte(strings.ToUpper(string(c))[0])
	return strings.IndexByte(timeAlphabet, c)
}

// checkTime validates the embedded day timestamp against now, allowing messages
// up to maxAgeDays old and a small amount of clock skew into the future.
func checkTime(ts string, maxAgeDays int64) error {
	slot, err := decodeTime(ts)
	if err != nil {
		return err
	}
	nowDay := time.Now().Unix() / secondsPerDay
	// The stored value is the day modulo timeSlots; recover the smallest
	// non-negative age, then interpret values near the modulus as slight future.
	age := (nowDay - slot) % timeSlots
	if age < 0 {
		age += timeSlots
	}
	if age <= maxAgeDays {
		return nil
	}
	if timeSlots-age <= futureSlopDays {
		return nil // clock skew: timestamp slightly in the future.
	}
	return ErrExpired
}

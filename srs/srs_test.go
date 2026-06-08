package srs

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/mjl-/mox/dns"
	"github.com/mjl-/mox/smtp"
)

func mustDomain(t *testing.T, s string) dns.Domain {
	t.Helper()
	d, err := dns.ParseDomain(s)
	if err != nil {
		t.Fatalf("parse domain %q: %v", s, err)
	}
	return d
}

func testConfig(t *testing.T) Config {
	return Config{
		Secret: []byte("test-secret-do-not-use"),
		Domain: mustDomain(t, "forwarder.example"),
		MaxAge: 21 * 24 * time.Hour,
	}
}

func TestForwardReverseRoundTrip(t *testing.T) {
	cfg := testConfig(t)
	orig := smtp.Address{Localpart: "alice", Domain: mustDomain(t, "sender.example")}

	fwd, err := Forward(orig, cfg)
	if err != nil {
		t.Fatalf("Forward: %v", err)
	}
	if fwd.Domain.Name() != "forwarder.example" {
		t.Fatalf("rewritten domain = %q, want forwarder.example", fwd.Domain.Name())
	}
	if !strings.HasPrefix(string(fwd.Localpart), "SRS0=") {
		t.Fatalf("rewritten localpart = %q, want SRS0= prefix", fwd.Localpart)
	}
	if !IsSRS(fwd.Localpart) {
		t.Fatalf("IsSRS(%q) = false, want true", fwd.Localpart)
	}

	got, err := Reverse(fwd, cfg)
	if err != nil {
		t.Fatalf("Reverse: %v", err)
	}
	if got.Localpart != orig.Localpart || got.Domain.Name() != orig.Domain.Name() {
		t.Fatalf("round trip = %s@%s, want %s", got.Localpart, got.Domain.Name(), orig.String())
	}
}

func TestReverseRejectsForgedHash(t *testing.T) {
	cfg := testConfig(t)
	orig := smtp.Address{Localpart: "alice", Domain: mustDomain(t, "sender.example")}
	fwd, err := Forward(orig, cfg)
	if err != nil {
		t.Fatalf("Forward: %v", err)
	}

	// Tamper with the encoded original domain; the HMAC must no longer verify.
	tampered := strings.Replace(string(fwd.Localpart), "sender.example", "attacker.example", 1)
	rcpt := smtp.Address{Localpart: smtp.Localpart(tampered), Domain: cfg.Domain}
	if _, err := Reverse(rcpt, cfg); !errors.Is(err, ErrInvalidHash) {
		t.Fatalf("Reverse(tampered) err = %v, want ErrInvalidHash", err)
	}
}

func TestReverseRejectsWrongSecret(t *testing.T) {
	cfg := testConfig(t)
	orig := smtp.Address{Localpart: "alice", Domain: mustDomain(t, "sender.example")}
	fwd, err := Forward(orig, cfg)
	if err != nil {
		t.Fatalf("Forward: %v", err)
	}

	other := cfg
	other.Secret = []byte("a-different-secret")
	if _, err := Reverse(fwd, other); !errors.Is(err, ErrInvalidHash) {
		t.Fatalf("Reverse(wrong secret) err = %v, want ErrInvalidHash", err)
	}
}

func TestReverseExpired(t *testing.T) {
	cfg := testConfig(t)
	cfg.MaxAge = 1 * 24 * time.Hour

	// Hand-build an SRS0 address with a timestamp ~30 days old.
	old := time.Now().Add(-30 * 24 * time.Hour)
	ts := encodeTime(old)
	payload := ts + "=sender.example=alice"
	h := computeHash(cfg.Secret, payload)
	lp := "SRS0=" + h + "=" + payload
	rcpt := smtp.Address{Localpart: smtp.Localpart(lp), Domain: cfg.Domain}

	if _, err := Reverse(rcpt, cfg); !errors.Is(err, ErrExpired) {
		t.Fatalf("Reverse(old) err = %v, want ErrExpired", err)
	}
}

func TestReverseNotSRS(t *testing.T) {
	cfg := testConfig(t)
	rcpt := smtp.Address{Localpart: "postmaster", Domain: cfg.Domain}
	if _, err := Reverse(rcpt, cfg); !errors.Is(err, ErrNotSRS) {
		t.Fatalf("Reverse(plain) err = %v, want ErrNotSRS", err)
	}
}

func TestForwardNullSenderRefused(t *testing.T) {
	cfg := testConfig(t)
	if _, err := Forward(smtp.Address{Domain: mustDomain(t, "sender.example")}, cfg); err == nil {
		t.Fatal("Forward(null sender) = nil error, want refusal")
	}
}

func TestLocalpartWithEquals(t *testing.T) {
	cfg := testConfig(t)
	// Localpart containing the SRS field separator must survive the round trip.
	orig := smtp.Address{Localpart: "a=b=c", Domain: mustDomain(t, "sender.example")}
	fwd, err := Forward(orig, cfg)
	if err != nil {
		t.Fatalf("Forward: %v", err)
	}
	got, err := Reverse(fwd, cfg)
	if err != nil {
		t.Fatalf("Reverse: %v", err)
	}
	if got.Localpart != orig.Localpart {
		t.Fatalf("localpart round trip = %q, want %q", got.Localpart, orig.Localpart)
	}
}

func TestDoubleForwardSRS1(t *testing.T) {
	// Two independent forwarders. A message sender.example -> hopA -> hopB.
	cfgA := Config{Secret: []byte("secret-A"), Domain: mustDomain(t, "hopa.example"), MaxAge: 21 * 24 * time.Hour}
	cfgB := Config{Secret: []byte("secret-B"), Domain: mustDomain(t, "hopb.example"), MaxAge: 21 * 24 * time.Hour}

	orig := smtp.Address{Localpart: "alice", Domain: mustDomain(t, "sender.example")}

	// hopA rewrites to its own SRS0.
	a, err := Forward(orig, cfgA)
	if err != nil {
		t.Fatalf("Forward A: %v", err)
	}
	// hopB receives a@hopa.example and re-forwards: SRS0 -> SRS1 at hopB.
	b, err := Forward(a, cfgB)
	if err != nil {
		t.Fatalf("Forward B: %v", err)
	}
	if !strings.HasPrefix(string(b.Localpart), "SRS1=") {
		t.Fatalf("re-forward localpart = %q, want SRS1= prefix", b.Localpart)
	}
	if b.Domain.Name() != "hopb.example" {
		t.Fatalf("re-forward domain = %q, want hopb.example", b.Domain.Name())
	}

	// A bounce comes back to hopB. hopB reverses SRS1 -> the SRS0 at hopA.
	backToA, err := Reverse(b, cfgB)
	if err != nil {
		t.Fatalf("Reverse B: %v", err)
	}
	if backToA.Domain.Name() != "hopa.example" {
		t.Fatalf("SRS1 reverse domain = %q, want hopa.example", backToA.Domain.Name())
	}
	if !strings.HasPrefix(string(backToA.Localpart), "SRS0=") {
		t.Fatalf("SRS1 reverse localpart = %q, want SRS0= prefix", backToA.Localpart)
	}

	// hopA reverses its SRS0 back to the true sender.
	final, err := Reverse(backToA, cfgA)
	if err != nil {
		t.Fatalf("Reverse A: %v", err)
	}
	if final.Localpart != orig.Localpart || final.Domain.Name() != orig.Domain.Name() {
		t.Fatalf("final reverse = %s, want %s", final.String(), orig.String())
	}
}

func TestTimeRoundTrip(t *testing.T) {
	now := time.Now()
	ts := encodeTime(now)
	if err := checkTime(ts, 21); err != nil {
		t.Fatalf("checkTime(now) = %v, want nil", err)
	}
	got, err := decodeTime(ts)
	if err != nil {
		t.Fatalf("decodeTime: %v", err)
	}
	want := (now.Unix() / secondsPerDay) % timeSlots
	if got != want {
		t.Fatalf("decodeTime = %d, want %d", got, want)
	}
}

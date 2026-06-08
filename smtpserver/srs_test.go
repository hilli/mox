package smtpserver

import (
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/mjl-/mox/config"
	"github.com/mjl-/mox/dns"
	"github.com/mjl-/mox/mox-"
	"github.com/mjl-/mox/queue"
	"github.com/mjl-/mox/smtp"
	"github.com/mjl-/mox/smtpclient"
	"github.com/mjl-/mox/srs"
)

// enableServerSRS turns on SRS server-wide with a deterministic secret anchored
// at the test hostname domain (mox.example), and returns the matching srs.Config
// so tests can mint/verify addresses the same way the server does.
func enableServerSRS(t *testing.T) srs.Config {
	t.Helper()
	secret := []byte("test-srs-secret-do-not-use")
	dom := dns.Domain{ASCII: "mox.example"}
	mox.Conf.Static.SRS = &config.SRS{
		Enabled:   true,
		Secret:    secret,
		DNSDomain: dom,
		MaxAge:    21 * 24 * time.Hour,
	}
	return srs.Config{Secret: secret, Domain: dom, MaxAge: 21 * 24 * time.Hour}
}

// TestSRSForwardOnRedirect verifies that a Sieve redirect to a third party gets
// its envelope sender rewritten via SRS: the queued message is addressed to the
// redirect target but carries an SRS0 sender at the SRS domain, not the original
// sender.
func TestSRSForwardOnRedirect(t *testing.T) {
	ts := newTestServer(t, filepath.FromSlash("../testdata/smtp/mox.conf"), sieveResolver())
	defer ts.close()

	enableServerSieve(t)
	enableServerSRS(t)
	installActiveScript(t, ts.acc, "redirect", `redirect "external@remote.example";
`)

	ts.run(func(client *smtpclient.Client) {
		err := client.Deliver(ctxbg, "remote@example.org", "mjl@mox.example", int64(len(sieveMessage)), strings.NewReader(sieveMessage), false, false, false)
		tcheck(t, err, "deliver")
	})

	// redirect-only cancels the implicit keep, so nothing is stored locally.
	ts.checkCount("Inbox", 0)

	msgs, err := queue.List(ctxbg, queue.Filter{}, queue.Sort{})
	tcheck(t, err, "listing queue")
	if len(msgs) != 1 {
		t.Fatalf("queue has %d messages, want 1 (the forwarded message)", len(msgs))
	}
	m := msgs[0]
	if got := m.Recipient().XString(true); got != "external@remote.example" {
		t.Fatalf("forwarded recipient = %q, want external@remote.example", got)
	}
	if m.SenderDomain.Domain.Name() != "mox.example" {
		t.Fatalf("forwarded sender domain = %q, want mox.example (SRS domain)", m.SenderDomain.Domain.Name())
	}
	if !srs.IsSRS(m.SenderLocalpart) {
		t.Fatalf("forwarded sender localpart = %q, want SRS-encoded", m.SenderLocalpart)
	}

	// The rewritten sender must decode back to the original sender.
	orig, err := srs.Reverse(smtp.Address{Localpart: m.SenderLocalpart, Domain: m.SenderDomain.Domain}, enableServerSRS(t))
	tcheck(t, err, "reverse rewritten sender")
	if got := orig.String(); got != "remote@example.org" {
		t.Fatalf("decoded original sender = %q, want remote@example.org", got)
	}
}

// TestSRSForwardSkipsLocalSender verifies that a redirect of a message whose
// envelope sender is at a domain we host is NOT rewritten: our own SPF already
// authorises this server for it, so the original sender is preserved (this is
// also the per-domain opt-out). The decision lives in senderIsLocal; we assert it
// directly because the incoming-delivery test harness has no MX for the local
// domain, so a local-domain MAIL FROM can't traverse a full SMTP transaction.
func TestSRSForwardSkipsLocalSender(t *testing.T) {
	ts := newTestServer(t, filepath.FromSlash("../testdata/smtp/mox.conf"), sieveResolver())
	defer ts.close()

	local := smtp.Path{Localpart: "local", IPDomain: dns.IPDomain{Domain: dns.Domain{ASCII: "mox.example"}}}
	if !senderIsLocal(local) {
		t.Fatalf("senderIsLocal(%s) = false, want true (configured local domain)", local.XString(true))
	}

	hostname := smtp.Path{Localpart: "x", IPDomain: dns.IPDomain{Domain: mox.Conf.Static.HostnameDomain}}
	if !senderIsLocal(hostname) {
		t.Fatalf("senderIsLocal(hostname) = false, want true")
	}

	remote := smtp.Path{Localpart: "remote", IPDomain: dns.IPDomain{Domain: dns.Domain{ASCII: "example.org"}}}
	if senderIsLocal(remote) {
		t.Fatalf("senderIsLocal(%s) = true, want false (external domain must be rewritten)", remote.XString(true))
	}

	null := smtp.Path{}
	if senderIsLocal(null) {
		t.Fatalf("senderIsLocal(null sender) = true, want false")
	}
}

// TestSRSReverseRelaysBounce verifies that a bounce addressed to an SRS address
// mox minted is decoded and relayed onward to the original sender, with the null
// envelope sender preserved, and nothing stored locally.
func TestSRSReverseRelaysBounce(t *testing.T) {
	ts := newTestServer(t, filepath.FromSlash("../testdata/smtp/mox.conf"), sieveResolver())
	defer ts.close()

	cfg := enableServerSRS(t)

	// Mint the SRS address mox would have used when forwarding mail from alice.
	srsAddr, err := srs.Forward(smtp.Address{Localpart: "alice", Domain: dns.Domain{ASCII: "sender.example"}}, cfg)
	tcheck(t, err, "mint srs address")

	bounce := strings.ReplaceAll(`From: <mailer-daemon@example.org>
To: <`+srsAddr.String()+`>
Subject: Undelivered Mail Returned to Sender
Message-Id: <bounce@remote.example>

your message could not be delivered
`, "\n", "\r\n")

	ts.run(func(client *smtpclient.Client) {
		err := client.Deliver(ctxbg, "mailer-daemon@example.org", srsAddr.String(), int64(len(bounce)), strings.NewReader(bounce), false, false, false)
		tcheck(t, err, "deliver bounce to srs address")
	})

	ts.checkCount("Inbox", 0)

	msgs, err := queue.List(ctxbg, queue.Filter{}, queue.Sort{})
	tcheck(t, err, "listing queue")
	if len(msgs) != 1 {
		t.Fatalf("queue has %d messages, want 1 (the relayed bounce)", len(msgs))
	}
	m := msgs[0]
	if got := m.Recipient().XString(true); got != "alice@sender.example" {
		t.Fatalf("relayed bounce recipient = %q, want alice@sender.example", got)
	}
	if !m.Sender().IsZero() {
		t.Fatalf("relayed bounce sender = %q, want null sender", m.Sender().XString(true))
	}
}

// TestSRSReverseRejectsForged verifies that a bounce to a tampered/forged SRS
// address is rejected (anti-backscatter), not relayed or stored.
func TestSRSReverseRejectsForged(t *testing.T) {
	ts := newTestServer(t, filepath.FromSlash("../testdata/smtp/mox.conf"), sieveResolver())
	defer ts.close()

	cfg := enableServerSRS(t)

	srsAddr, err := srs.Forward(smtp.Address{Localpart: "alice", Domain: dns.Domain{ASCII: "sender.example"}}, cfg)
	tcheck(t, err, "mint srs address")
	// Tamper with the encoded original domain so the HMAC no longer verifies.
	forged := strings.Replace(srsAddr.String(), "sender.example", "attacker.example", 1)

	bounce := strings.ReplaceAll(`From: <mailer-daemon@example.org>
To: <`+forged+`>
Subject: Undelivered Mail Returned to Sender
Message-Id: <bounce@remote.example>

your message could not be delivered
`, "\n", "\r\n")

	ts.run(func(client *smtpclient.Client) {
		err := client.Deliver(ctxbg, "mailer-daemon@example.org", forged, int64(len(bounce)), strings.NewReader(bounce), false, false, false)
		if err == nil {
			t.Fatalf("expected rejection of forged SRS address, got nil")
		}
		var cerr smtpclient.Error
		if !errors.As(err, &cerr) {
			t.Fatalf("expected smtpclient.Error, got %#v", err)
		}
		if cerr.Code != smtp.C550MailboxUnavail {
			t.Fatalf("expected smtp code %d, got %d (%q)", smtp.C550MailboxUnavail, cerr.Code, err)
		}
	})

	msgs, err := queue.List(ctxbg, queue.Filter{}, queue.Sort{})
	tcheck(t, err, "listing queue")
	if len(msgs) != 0 {
		t.Fatalf("queue has %d messages, want 0 (forged bounce rejected)", len(msgs))
	}
	ts.checkCount("Inbox", 0)
}

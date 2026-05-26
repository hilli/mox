package smtpserver

import (
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/mjl-/bstore"

	"github.com/mjl-/mox/config"
	"github.com/mjl-/mox/dns"
	"github.com/mjl-/mox/mox-"
	"github.com/mjl-/mox/smtp"
	"github.com/mjl-/mox/smtpclient"
	"github.com/mjl-/mox/store"
)

// sieveResolver provides PTR for delivery to succeed (iprev).
func sieveResolver() dns.MockResolver {
	return dns.MockResolver{
		A: map[string][]string{
			"example.org.": {"127.0.0.10"},
		},
		PTR: map[string][]string{
			"127.0.0.10": {"example.org."},
		},
	}
}

// sieveMessage is a deliverable message addressed to mjl@mox.example.
var sieveMessage = strings.ReplaceAll(`From: <remote@example.org>
To: <mjl@mox.example>
Subject: sieve test
Message-Id: <sieve-test@example.org>

sieve test email
`, "\n", "\r\n")

// enableServerSieve sets the server-wide Sieve policy to Enabled=true.
func enableServerSieve(t *testing.T) {
	t.Helper()
	yes := true
	mox.Conf.Static.Sieve = &config.Sieve{
		Enabled: &yes,
	}
}

// installActiveScript stores a script on the account and makes it active.
func installActiveScript(t *testing.T, acc *store.Account, name, content string) {
	t.Helper()
	tcheck(t, acc.SievePutScript(name, []byte(content)), "put sieve script")
	tcheck(t, acc.SieveSetActive(name), "set active sieve script")
}

// totalMessageCount returns the number of non-expunged messages in the account
// across all mailboxes.
func totalMessageCount(t *testing.T, acc *store.Account) int {
	t.Helper()
	q := bstore.QueryDB[store.Message](ctxbg, acc.DB)
	q.FilterEqual("Expunged", false)
	n, err := q.Count()
	tcheck(t, err, "count messages")
	return n
}

// waitForDelivery waits for a change notification (or timeout) so we know the
// delivery pipeline finished.
func waitForDelivery(t *testing.T, ts *testserver) {
	t.Helper()
	changes := make(chan []store.Change, 1)
	go func() {
		_, l := ts.comm.Get()
		changes <- l
	}()
	timer := time.NewTimer(2 * time.Second)
	defer timer.Stop()
	select {
	case <-changes:
	case <-timer.C:
		// No change is OK for discard, caller decides.
	}
}

func TestSieveFileInto(t *testing.T) {
	ts := newTestServer(t, filepath.FromSlash("../testdata/smtp/mox.conf"), sieveResolver())
	defer ts.close()

	enableServerSieve(t)
	installActiveScript(t, ts.acc, "fileinto", `require ["fileinto"];
fileinto "FilteredBox";
`)

	ts.run(func(client *smtpclient.Client) {
		err := client.Deliver(ctxbg, "remote@example.org", "mjl@mox.example", int64(len(sieveMessage)), strings.NewReader(sieveMessage), false, false, false)
		tcheck(t, err, "deliver")
		waitForDelivery(t, ts)
	})

	ts.checkCount("FilteredBox", 1)
	ts.checkCount("Inbox", 0)
}

func TestSieveDiscard(t *testing.T) {
	ts := newTestServer(t, filepath.FromSlash("../testdata/smtp/mox.conf"), sieveResolver())
	defer ts.close()

	enableServerSieve(t)
	installActiveScript(t, ts.acc, "discard", `discard;
`)

	ts.run(func(client *smtpclient.Client) {
		err := client.Deliver(ctxbg, "remote@example.org", "mjl@mox.example", int64(len(sieveMessage)), strings.NewReader(sieveMessage), false, false, false)
		tcheck(t, err, "deliver")
	})

	// Brief settle period for any background work.
	time.Sleep(50 * time.Millisecond)

	n := totalMessageCount(t, ts.acc)
	if n != 0 {
		t.Fatalf("after sieve discard: %d messages in account, want 0", n)
	}
}

func TestSieveReject(t *testing.T) {
	ts := newTestServer(t, filepath.FromSlash("../testdata/smtp/mox.conf"), sieveResolver())
	defer ts.close()

	enableServerSieve(t)
	installActiveScript(t, ts.acc, "reject", `require ["reject"];
reject "no thanks";
`)

	ts.run(func(client *smtpclient.Client) {
		err := client.Deliver(ctxbg, "remote@example.org", "mjl@mox.example", int64(len(sieveMessage)), strings.NewReader(sieveMessage), false, false, false)
		if err == nil {
			t.Fatalf("expected smtp reject error, got nil")
		}
		var cerr smtpclient.Error
		if !errors.As(err, &cerr) {
			t.Fatalf("expected smtpclient.Error, got %#v", err)
		}
		if cerr.Code != smtp.C550MailboxUnavail {
			t.Fatalf("expected smtp code %d, got %d (%q)", smtp.C550MailboxUnavail, cerr.Code, err)
		}
		if cerr.Secode != smtp.SePol7DeliveryUnauth1 {
			t.Fatalf("expected secode %q, got %q", smtp.SePol7DeliveryUnauth1, cerr.Secode)
		}
		if !strings.Contains(err.Error(), "no thanks") {
			t.Fatalf("expected reject reason %q in error, got %q", "no thanks", err.Error())
		}
	})

	if n := totalMessageCount(t, ts.acc); n != 0 {
		t.Fatalf("after sieve reject: %d messages in account, want 0", n)
	}
}

func TestSieveDisabledByDefault(t *testing.T) {
	ts := newTestServer(t, filepath.FromSlash("../testdata/smtp/mox.conf"), sieveResolver())
	defer ts.close()

	// Do NOT enable server-wide Sieve. Install a script that would otherwise
	// reject the message; with Sieve disabled it should not run.
	mox.Conf.Static.Sieve = nil
	installActiveScript(t, ts.acc, "reject", `require ["reject"];
reject "would block";
`)

	ts.run(func(client *smtpclient.Client) {
		err := client.Deliver(ctxbg, "remote@example.org", "mjl@mox.example", int64(len(sieveMessage)), strings.NewReader(sieveMessage), false, false, false)
		tcheck(t, err, "deliver with sieve disabled")
		waitForDelivery(t, ts)
	})

	ts.checkCount("Inbox", 1)
}

func TestSieveEditHeaderAddAtTop(t *testing.T) {
	ts := newTestServer(t, filepath.FromSlash("../testdata/smtp/mox.conf"), sieveResolver())
	defer ts.close()

	enableServerSieve(t)
	installActiveScript(t, ts.acc, "editheader", `require ["editheader"];
addheader "X-Mox-Sieve" "applied";
`)

	ts.run(func(client *smtpclient.Client) {
		err := client.Deliver(ctxbg, "remote@example.org", "mjl@mox.example", int64(len(sieveMessage)), strings.NewReader(sieveMessage), false, false, false)
		tcheck(t, err, "deliver")
		waitForDelivery(t, ts)
	})

	ts.checkCount("Inbox", 1)

	// Verify the message MsgPrefix contains the new header.
	q := bstore.QueryDB[store.Message](ctxbg, ts.acc.DB)
	q.FilterEqual("Expunged", false)
	msgs, err := q.List()
	tcheck(t, err, "list messages")
	if len(msgs) != 1 {
		t.Fatalf("expected 1 message, got %d", len(msgs))
	}
	if !strings.Contains(string(msgs[0].MsgPrefix), "X-Mox-Sieve: applied") {
		t.Fatalf("expected X-Mox-Sieve header in MsgPrefix, got:\n%s", msgs[0].MsgPrefix)
	}
}

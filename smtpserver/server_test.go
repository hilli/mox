package smtpserver

// todo: test delivery with failing spf/dkim/dmarc
// todo: test delivering a message to multiple recipients, and with some of them failing.

import (
	"bytes"
	"context"
	"crypto/ed25519"
	cryptorand "crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"math/big"
	"mime/quotedprintable"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/mjl-/bstore"

	"github.com/mjl-/mox/config"
	"github.com/mjl-/mox/dkim"
	"github.com/mjl-/mox/dmarcdb"
	"github.com/mjl-/mox/dns"
	"github.com/mjl-/mox/mlog"
	"github.com/mjl-/mox/mox-"
	"github.com/mjl-/mox/queue"
	"github.com/mjl-/mox/sasl"
	"github.com/mjl-/mox/smtp"
	"github.com/mjl-/mox/smtpclient"
	"github.com/mjl-/mox/store"
	"github.com/mjl-/mox/subjectpass"
	"github.com/mjl-/mox/tlsrptdb"
)

var ctxbg = context.Background()

func init() {
	// Don't make tests slow.
	badClientDelay = 0
	authFailDelay = 0
	unknownRecipientsDelay = 0
}

func tcheck(t *testing.T, err error, msg string) {
	if err != nil {
		t.Helper()
		t.Fatalf("%s: %s", msg, err)
	}
}

var submitMessage = strings.ReplaceAll(`From: <mjl@mox.example>
To: <remote@example.org>
Subject: test
Message-Id: <test@mox.example>

test email
`, "\n", "\r\n")

var deliverMessage = strings.ReplaceAll(`From: <remote@example.org>
To: <mjl@mox.example>
Subject: test
Message-Id: <test@example.org>

test email
`, "\n", "\r\n")

type testserver struct {
	t          *testing.T
	acc        *store.Account
	switchDone chan struct{}
	comm       *store.Comm
	cid        int64
	resolver   dns.Resolver
	auth       []sasl.Client
	user, pass string
	submission bool
	dnsbls     []dns.Domain
	tlsmode    smtpclient.TLSMode
}

func newTestServer(t *testing.T, configPath string, resolver dns.Resolver) *testserver {
	limitersInit() // Reset rate limiters.

	ts := testserver{t: t, cid: 1, resolver: resolver, tlsmode: smtpclient.TLSOpportunistic}

	mox.Context = ctxbg
	mox.ConfigStaticPath = configPath
	mox.MustLoadConfig(true, false)
	dataDir := mox.ConfigDirPath(mox.Conf.Static.DataDir)
	os.RemoveAll(dataDir)
	var err error
	ts.acc, err = store.OpenAccount("mjl")
	tcheck(t, err, "open account")
	err = ts.acc.SetPassword("testtest")
	tcheck(t, err, "set password")
	ts.switchDone = store.Switchboard()
	err = queue.Init()
	tcheck(t, err, "queue init")

	ts.comm = store.RegisterComm(ts.acc)

	return &ts
}

func (ts *testserver) close() {
	ts.comm.Unregister()
	queue.Shutdown()
	close(ts.switchDone)
	ts.acc.Close()
}

func (ts *testserver) run(fn func(helloErr error, client *smtpclient.Client)) {
	ts.t.Helper()

	ts.cid += 2

	serverConn, clientConn := net.Pipe()
	defer serverConn.Close()
	// clientConn is closed as part of closing client.
	serverdone := make(chan struct{})
	defer func() { <-serverdone }()

	go func() {
		tlsConfig := &tls.Config{
			Certificates: []tls.Certificate{fakeCert(ts.t)},
		}
		serve("test", ts.cid-2, dns.Domain{ASCII: "mox.example"}, tlsConfig, serverConn, ts.resolver, ts.submission, false, 100<<20, false, false, ts.dnsbls, 0)
		close(serverdone)
	}()

	var auth []sasl.Client
	if len(ts.auth) > 0 {
		auth = ts.auth
	} else if ts.user != "" {
		auth = append(auth, sasl.NewClientPlain(ts.user, ts.pass))
	}

	ourHostname := mox.Conf.Static.HostnameDomain
	remoteHostname := dns.Domain{ASCII: "mox.example"}
	client, err := smtpclient.New(ctxbg, xlog.WithCid(ts.cid-1), clientConn, ts.tlsmode, ourHostname, remoteHostname, auth)
	if err != nil {
		clientConn.Close()
	} else {
		defer client.Close()
	}
	fn(err, client)
}

// Just a cert that appears valid. SMTP client will not verify anything about it
// (that is opportunistic TLS for you, "better some than none"). Let's enjoy this
// one moment where it makes life easier.
func fakeCert(t *testing.T) tls.Certificate {
	privKey := ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize)) // Fake key, don't use this for real!
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1), // Required field...
	}
	localCertBuf, err := x509.CreateCertificate(cryptorand.Reader, template, template, privKey.Public(), privKey)
	if err != nil {
		t.Fatalf("making certificate: %s", err)
	}
	cert, err := x509.ParseCertificate(localCertBuf)
	if err != nil {
		t.Fatalf("parsing generated certificate: %s", err)
	}
	c := tls.Certificate{
		Certificate: [][]byte{localCertBuf},
		PrivateKey:  privKey,
		Leaf:        cert,
	}
	return c
}

// Test submission from authenticated user.
func TestSubmission(t *testing.T) {
	ts := newTestServer(t, "../testdata/smtp/mox.conf", dns.MockResolver{})
	defer ts.close()

	// Set DKIM signing config.
	dom, _ := mox.Conf.Domain(dns.Domain{ASCII: "mox.example"})
	sel := config.Selector{
		HashEffective:    "sha256",
		HeadersEffective: []string{"From", "To", "Subject"},
		Key:              ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize)), // Fake key, don't use for real.
		Domain:           dns.Domain{ASCII: "mox.example"},
	}
	dom.DKIM = config.DKIM{
		Selectors: map[string]config.Selector{"testsel": sel},
		Sign:      []string{"testsel"},
	}
	mox.Conf.Dynamic.Domains["mox.example"] = dom

	testAuth := func(authfn func(user, pass string) sasl.Client, user, pass string, expErr *smtpclient.Error) {
		t.Helper()
		if authfn != nil {
			ts.auth = []sasl.Client{authfn(user, pass)}
		} else {
			ts.auth = nil
		}
		ts.run(func(err error, client *smtpclient.Client) {
			t.Helper()
			mailFrom := "mjl@mox.example"
			rcptTo := "remote@example.org"
			if err == nil {
				err = client.Deliver(ctxbg, mailFrom, rcptTo, int64(len(submitMessage)), strings.NewReader(submitMessage), false, false)
			}
			var cerr smtpclient.Error
			if expErr == nil && err != nil || expErr != nil && (err == nil || !errors.As(err, &cerr) || cerr.Secode != expErr.Secode) {
				t.Fatalf("got err %#v (%q), expected %#v", err, err, expErr)
			}
		})
	}

	ts.submission = true
	testAuth(nil, "", "", &smtpclient.Error{Permanent: true, Code: smtp.C530SecurityRequired, Secode: smtp.SePol7Other0})
	authfns := []func(user, pass string) sasl.Client{
		sasl.NewClientPlain,
		sasl.NewClientCRAMMD5,
		sasl.NewClientSCRAMSHA1,
		sasl.NewClientSCRAMSHA256,
	}
	for _, fn := range authfns {
		testAuth(fn, "mjl@mox.example", "test", &smtpclient.Error{Secode: smtp.SePol7AuthBadCreds8})         // Bad (short) password.
		testAuth(fn, "mjl@mox.example", "testtesttest", &smtpclient.Error{Secode: smtp.SePol7AuthBadCreds8}) // Bad password.
		testAuth(fn, "mjl@mox.example", "testtest", nil)
	}
}

// Test delivery from external MTA.
func TestDelivery(t *testing.T) {
	resolver := dns.MockResolver{
		A: map[string][]string{
			"example.org.": {"127.0.0.10"}, // For mx check.
		},
		PTR: map[string][]string{},
	}
	ts := newTestServer(t, "../testdata/smtp/mox.conf", resolver)
	defer ts.close()

	ts.run(func(err error, client *smtpclient.Client) {
		mailFrom := "remote@example.org"
		rcptTo := "mjl@127.0.0.10"
		if err == nil {
			err = client.Deliver(ctxbg, mailFrom, rcptTo, int64(len(deliverMessage)), strings.NewReader(deliverMessage), false, false)
		}
		var cerr smtpclient.Error
		if err == nil || !errors.As(err, &cerr) || cerr.Code != smtp.C550MailboxUnavail {
			t.Fatalf("deliver to ip address, got err %v, expected smtpclient.Error with code %d", err, smtp.C550MailboxUnavail)
		}
	})

	ts.run(func(err error, client *smtpclient.Client) {
		mailFrom := "remote@example.org"
		rcptTo := "mjl@test.example" // Not configured as destination.
		if err == nil {
			err = client.Deliver(ctxbg, mailFrom, rcptTo, int64(len(deliverMessage)), strings.NewReader(deliverMessage), false, false)
		}
		var cerr smtpclient.Error
		if err == nil || !errors.As(err, &cerr) || cerr.Code != smtp.C550MailboxUnavail {
			t.Fatalf("deliver to unknown domain, got err %v, expected smtpclient.Error with code %d", err, smtp.C550MailboxUnavail)
		}
	})

	ts.run(func(err error, client *smtpclient.Client) {
		mailFrom := "remote@example.org"
		rcptTo := "unknown@mox.example" // User unknown.
		if err == nil {
			err = client.Deliver(ctxbg, mailFrom, rcptTo, int64(len(deliverMessage)), strings.NewReader(deliverMessage), false, false)
		}
		var cerr smtpclient.Error
		if err == nil || !errors.As(err, &cerr) || cerr.Code != smtp.C550MailboxUnavail {
			t.Fatalf("deliver to unknown user for known domain, got err %v, expected smtpclient.Error with code %d", err, smtp.C550MailboxUnavail)
		}
	})

	ts.run(func(err error, client *smtpclient.Client) {
		mailFrom := "remote@example.org"
		rcptTo := "mjl@mox.example"
		if err == nil {
			err = client.Deliver(ctxbg, mailFrom, rcptTo, int64(len(deliverMessage)), strings.NewReader(deliverMessage), false, false)
		}
		var cerr smtpclient.Error
		if err == nil || !errors.As(err, &cerr) || cerr.Code != smtp.C451LocalErr {
			t.Fatalf("deliver from user without reputation, valid iprev required, got err %v, expected smtpclient.Error with code %d", err, smtp.C451LocalErr)
		}
	})

	// Set up iprev to get delivery from unknown user to be accepted.
	resolver.PTR["127.0.0.10"] = []string{"example.org."}
	ts.run(func(err error, client *smtpclient.Client) {
		mailFrom := "remote@example.org"
		rcptTo := "mjl@mox.example"
		if err == nil {
			err = client.Deliver(ctxbg, mailFrom, rcptTo, int64(len(deliverMessage)), strings.NewReader(deliverMessage), false, false)
		}
		tcheck(t, err, "deliver to remote")

		changes := make(chan []store.Change)
		go func() {
			changes <- ts.comm.Get()
		}()

		timer := time.NewTimer(time.Second)
		defer timer.Stop()
		select {
		case <-changes:
		case <-timer.C:
			t.Fatalf("no delivery in 1s")
		}
	})
}

func tinsertmsg(t *testing.T, acc *store.Account, mailbox string, m *store.Message, msg string) {
	mf, err := store.CreateMessageTemp("queue-dsn")
	tcheck(t, err, "temp message")
	_, err = mf.Write([]byte(msg))
	tcheck(t, err, "write message")
	err = acc.DeliverMailbox(xlog, mailbox, m, mf, true)
	tcheck(t, err, "deliver message")
	err = mf.Close()
	tcheck(t, err, "close message")
}

func tretrain(t *testing.T, acc *store.Account) {
	t.Helper()

	// Fresh empty junkfilter.
	basePath := mox.DataDirPath("accounts")
	dbPath := filepath.Join(basePath, acc.Name, "junkfilter.db")
	bloomPath := filepath.Join(basePath, acc.Name, "junkfilter.bloom")
	os.Remove(dbPath)
	os.Remove(bloomPath)
	jf, _, err := acc.OpenJunkFilter(ctxbg, xlog)
	tcheck(t, err, "open junk filter")
	defer jf.Close()

	// Fetch messags to retrain on.
	q := bstore.QueryDB[store.Message](ctxbg, acc.DB)
	q.FilterFn(func(m store.Message) bool {
		return m.Flags.Junk || m.Flags.Notjunk
	})
	msgs, err := q.List()
	tcheck(t, err, "fetch messages")

	// Retrain the messages.
	for _, m := range msgs {
		ham := m.Flags.Notjunk

		f, err := os.Open(acc.MessagePath(m.ID))
		tcheck(t, err, "open message")
		r := store.FileMsgReader(m.MsgPrefix, f)

		jf.TrainMessage(ctxbg, r, m.Size, ham)

		err = r.Close()
		tcheck(t, err, "close message")
	}

	err = jf.Save()
	tcheck(t, err, "save junkfilter")
}

// Test accept/reject with DMARC reputation and with spammy content.
func TestSpam(t *testing.T) {
	resolver := &dns.MockResolver{
		A: map[string][]string{
			"example.org.": {"127.0.0.1"}, // For mx check.
		},
		TXT: map[string][]string{
			"example.org.":        {"v=spf1 ip4:127.0.0.10 -all"},
			"_dmarc.example.org.": {"v=DMARC1;p=reject"},
		},
	}
	ts := newTestServer(t, "../testdata/smtp/junk/mox.conf", resolver)
	defer ts.close()

	// Insert spammy messages. No junkfilter training yet.
	m := store.Message{
		RemoteIP:          "127.0.0.10",
		RemoteIPMasked1:   "127.0.0.10",
		RemoteIPMasked2:   "127.0.0.0",
		RemoteIPMasked3:   "127.0.0.0",
		MailFrom:          "remote@example.org",
		MailFromLocalpart: smtp.Localpart("remote"),
		MailFromDomain:    "example.org",
		RcptToLocalpart:   smtp.Localpart("mjl"),
		RcptToDomain:      "mox.example",
		MsgFromLocalpart:  smtp.Localpart("remote"),
		MsgFromDomain:     "example.org",
		MsgFromOrgDomain:  "example.org",
		MsgFromValidated:  true,
		MsgFromValidation: store.ValidationStrict,
		Flags:             store.Flags{Seen: true, Junk: true},
	}
	for i := 0; i < 3; i++ {
		nm := m
		tinsertmsg(t, ts.acc, "Inbox", &nm, deliverMessage)
	}

	checkRejectsCount := func(expect int) {
		t.Helper()
		q := bstore.QueryDB[store.Mailbox](ctxbg, ts.acc.DB)
		q.FilterNonzero(store.Mailbox{Name: "Rejects"})
		mb, err := q.Get()
		tcheck(t, err, "get rejects mailbox")
		qm := bstore.QueryDB[store.Message](ctxbg, ts.acc.DB)
		qm.FilterNonzero(store.Message{MailboxID: mb.ID})
		n, err := qm.Count()
		tcheck(t, err, "count messages in rejects mailbox")
		if n != expect {
			t.Fatalf("messages in rejects mailbox, found %d, expected %d", n, expect)
		}
	}

	// Delivery from sender with bad reputation should fail.
	ts.run(func(err error, client *smtpclient.Client) {
		mailFrom := "remote@example.org"
		rcptTo := "mjl@mox.example"
		if err == nil {
			err = client.Deliver(ctxbg, mailFrom, rcptTo, int64(len(deliverMessage)), strings.NewReader(deliverMessage), false, false)
		}
		var cerr smtpclient.Error
		if err == nil || !errors.As(err, &cerr) || cerr.Code != smtp.C451LocalErr {
			t.Fatalf("delivery by bad sender, got err %v, expected smtpclient.Error with code %d", err, smtp.C451LocalErr)
		}

		// Message should now be in Rejects mailbox.
		checkRejectsCount(1)
	})

	// Mark the messages as having good reputation.
	q := bstore.QueryDB[store.Message](ctxbg, ts.acc.DB)
	_, err := q.UpdateFields(map[string]any{"Junk": false, "Notjunk": true})
	tcheck(t, err, "update junkiness")

	// Message should now be accepted.
	ts.run(func(err error, client *smtpclient.Client) {
		mailFrom := "remote@example.org"
		rcptTo := "mjl@mox.example"
		if err == nil {
			err = client.Deliver(ctxbg, mailFrom, rcptTo, int64(len(deliverMessage)), strings.NewReader(deliverMessage), false, false)
		}
		tcheck(t, err, "deliver")

		// Message should now be removed from Rejects mailbox.
		checkRejectsCount(0)
	})

	// Undo dmarc pass, mark messages as junk, and train the filter.
	resolver.TXT = nil
	q = bstore.QueryDB[store.Message](ctxbg, ts.acc.DB)
	_, err = q.UpdateFields(map[string]any{"Junk": true, "Notjunk": false})
	tcheck(t, err, "update junkiness")
	tretrain(t, ts.acc)

	// Message should be refused for spammy content.
	ts.run(func(err error, client *smtpclient.Client) {
		mailFrom := "remote@example.org"
		rcptTo := "mjl@mox.example"
		if err == nil {
			err = client.Deliver(ctxbg, mailFrom, rcptTo, int64(len(deliverMessage)), strings.NewReader(deliverMessage), false, false)
		}
		var cerr smtpclient.Error
		if err == nil || !errors.As(err, &cerr) || cerr.Code != smtp.C451LocalErr {
			t.Fatalf("attempt to deliver spamy message, got err %v, expected smtpclient.Error with code %d", err, smtp.C451LocalErr)
		}
	})
}

// Messages that we sent to, that have passing DMARC, but that are otherwise spammy, should be accepted.
func TestDMARCSent(t *testing.T) {
	resolver := &dns.MockResolver{
		A: map[string][]string{
			"example.org.": {"127.0.0.1"}, // For mx check.
		},
		TXT: map[string][]string{
			"example.org.":        {"v=spf1 ip4:127.0.0.10 -all"},
			"_dmarc.example.org.": {"v=DMARC1;p=reject"},
		},
	}
	ts := newTestServer(t, "../testdata/smtp/junk/mox.conf", resolver)
	defer ts.close()

	// Insert spammy messages not related to the test message.
	m := store.Message{
		MailFrom:        "remote@test.example",
		RcptToLocalpart: smtp.Localpart("mjl"),
		RcptToDomain:    "mox.example",
		Flags:           store.Flags{Seen: true, Junk: true},
	}
	for i := 0; i < 3; i++ {
		nm := m
		tinsertmsg(t, ts.acc, "Archive", &nm, deliverMessage)
	}
	tretrain(t, ts.acc)

	// Baseline, message should be refused for spammy content.
	ts.run(func(err error, client *smtpclient.Client) {
		mailFrom := "remote@example.org"
		rcptTo := "mjl@mox.example"
		if err == nil {
			err = client.Deliver(ctxbg, mailFrom, rcptTo, int64(len(deliverMessage)), strings.NewReader(deliverMessage), false, false)
		}
		var cerr smtpclient.Error
		if err == nil || !errors.As(err, &cerr) || cerr.Code != smtp.C451LocalErr {
			t.Fatalf("attempt to deliver spamy message, got err %v, expected smtpclient.Error with code %d", err, smtp.C451LocalErr)
		}
	})

	// Insert a message that we sent to the address that is about to send to us.
	var sentMsg store.Message
	tinsertmsg(t, ts.acc, "Sent", &sentMsg, deliverMessage)
	err := ts.acc.DB.Insert(ctxbg, &store.Recipient{MessageID: sentMsg.ID, Localpart: "remote", Domain: "example.org", OrgDomain: "example.org", Sent: time.Now()})
	tcheck(t, err, "inserting message recipient")

	// We should now be accepting the message because we recently sent a message.
	ts.run(func(err error, client *smtpclient.Client) {
		mailFrom := "remote@example.org"
		rcptTo := "mjl@mox.example"
		if err == nil {
			err = client.Deliver(ctxbg, mailFrom, rcptTo, int64(len(deliverMessage)), strings.NewReader(deliverMessage), false, false)
		}
		tcheck(t, err, "deliver")
	})
}

// Test DNSBL, then getting through with subjectpass.
func TestBlocklistedSubjectpass(t *testing.T) {
	// Set up a DNSBL on dnsbl.example, and get DMARC pass.
	resolver := &dns.MockResolver{
		A: map[string][]string{
			"example.org.":              {"127.0.0.10"}, // For mx check.
			"2.0.0.127.dnsbl.example.":  {"127.0.0.2"},  // For healthcheck.
			"10.0.0.127.dnsbl.example.": {"127.0.0.10"}, // Where our connection pretends to come from.
		},
		TXT: map[string][]string{
			"10.0.0.127.dnsbl.example.": {"blocklisted"},
			"example.org.":              {"v=spf1 ip4:127.0.0.10 -all"},
			"_dmarc.example.org.":       {"v=DMARC1;p=reject"},
		},
		PTR: map[string][]string{
			"127.0.0.10": {"example.org."}, // For iprev check.
		},
	}
	ts := newTestServer(t, "../testdata/smtp/mox.conf", resolver)
	ts.dnsbls = []dns.Domain{{ASCII: "dnsbl.example"}}
	defer ts.close()

	// Message should be refused softly (temporary error) due to DNSBL.
	ts.run(func(err error, client *smtpclient.Client) {
		mailFrom := "remote@example.org"
		rcptTo := "mjl@mox.example"
		if err == nil {
			err = client.Deliver(ctxbg, mailFrom, rcptTo, int64(len(deliverMessage)), strings.NewReader(deliverMessage), false, false)
		}
		var cerr smtpclient.Error
		if err == nil || !errors.As(err, &cerr) || cerr.Code != smtp.C451LocalErr {
			t.Fatalf("attempted deliver from dnsblocklisted ip, got err %v, expected smtpclient.Error with code %d", err, smtp.C451LocalErr)
		}
	})

	// Set up subjectpass on account.
	acc := mox.Conf.Dynamic.Accounts[ts.acc.Name]
	acc.SubjectPass.Period = time.Hour
	mox.Conf.Dynamic.Accounts[ts.acc.Name] = acc

	// Message should be refused quickly (permanent error) due to DNSBL and Subjectkey.
	var pass string
	ts.run(func(err error, client *smtpclient.Client) {
		mailFrom := "remote@example.org"
		rcptTo := "mjl@mox.example"
		if err == nil {
			err = client.Deliver(ctxbg, mailFrom, rcptTo, int64(len(deliverMessage)), strings.NewReader(deliverMessage), false, false)
		}
		var cerr smtpclient.Error
		if err == nil || !errors.As(err, &cerr) || cerr.Code != smtp.C550MailboxUnavail {
			t.Fatalf("attempted deliver from dnsblocklisted ip, got err %v, expected smtpclient.Error with code %d", err, smtp.C550MailboxUnavail)
		}
		i := strings.Index(cerr.Line, subjectpass.Explanation)
		if i < 0 {
			t.Fatalf("got error line %q, expected error line with subjectpass", cerr.Line)
		}
		pass = cerr.Line[i+len(subjectpass.Explanation):]
	})

	ts.run(func(err error, client *smtpclient.Client) {
		mailFrom := "remote@example.org"
		rcptTo := "mjl@mox.example"
		passMessage := strings.Replace(deliverMessage, "Subject: test", "Subject: test "+pass, 1)
		if err == nil {
			err = client.Deliver(ctxbg, mailFrom, rcptTo, int64(len(passMessage)), strings.NewReader(passMessage), false, false)
		}
		tcheck(t, err, "deliver with subjectpass")
	})
}

// Test accepting a DMARC report.
func TestDMARCReport(t *testing.T) {
	resolver := &dns.MockResolver{
		A: map[string][]string{
			"example.org.": {"127.0.0.10"}, // For mx check.
		},
		TXT: map[string][]string{
			"example.org.":        {"v=spf1 ip4:127.0.0.10 -all"},
			"_dmarc.example.org.": {"v=DMARC1;p=reject"},
		},
		PTR: map[string][]string{
			"127.0.0.10": {"example.org."}, // For iprev check.
		},
	}
	ts := newTestServer(t, "../testdata/smtp/dmarcreport/mox.conf", resolver)
	defer ts.close()

	run := func(report string, n int) {
		t.Helper()
		ts.run(func(err error, client *smtpclient.Client) {
			t.Helper()

			tcheck(t, err, "run")

			mailFrom := "remote@example.org"
			rcptTo := "mjl@mox.example"

			msgb := &bytes.Buffer{}
			_, xerr := fmt.Fprintf(msgb, "From: %s\r\nTo: %s\r\nSubject: dmarc report\r\nMIME-Version: 1.0\r\nContent-Type: text/xml\r\n\r\n", mailFrom, rcptTo)
			tcheck(t, xerr, "write msg headers")
			w := quotedprintable.NewWriter(msgb)
			_, xerr = w.Write([]byte(strings.ReplaceAll(report, "\n", "\r\n")))
			tcheck(t, xerr, "write message")
			msg := msgb.String()

			if err == nil {
				err = client.Deliver(ctxbg, mailFrom, rcptTo, int64(len(msg)), strings.NewReader(msg), false, false)
			}
			tcheck(t, err, "deliver")

			records, err := dmarcdb.Records(ctxbg)
			tcheck(t, err, "dmarcdb records")
			if len(records) != n {
				t.Fatalf("got %d dmarcdb records, expected %d or more", len(records), n)
			}
		})
	}

	run(dmarcReport, 0)
	run(strings.ReplaceAll(dmarcReport, "xmox.nl", "mox.example"), 1)
}

const dmarcReport = `<?xml version="1.0" encoding="UTF-8" ?>
<feedback>
  <report_metadata>
    <org_name>example.org</org_name>
    <email>postmaster@example.org</email>
    <report_id>1</report_id>
    <date_range>
      <begin>1596412800</begin>
      <end>1596499199</end>
    </date_range>
  </report_metadata>
  <policy_published>
    <domain>xmox.nl</domain>
    <adkim>r</adkim>
    <aspf>r</aspf>
    <p>reject</p>
    <sp>reject</sp>
    <pct>100</pct>
  </policy_published>
  <record>
    <row>
      <source_ip>127.0.0.10</source_ip>
      <count>1</count>
      <policy_evaluated>
        <disposition>none</disposition>
        <dkim>pass</dkim>
        <spf>pass</spf>
      </policy_evaluated>
    </row>
    <identifiers>
      <header_from>xmox.nl</header_from>
    </identifiers>
    <auth_results>
      <dkim>
        <domain>xmox.nl</domain>
        <result>pass</result>
        <selector>testsel</selector>
      </dkim>
      <spf>
        <domain>xmox.nl</domain>
        <result>pass</result>
      </spf>
    </auth_results>
  </record>
</feedback>
`

// Test accepting a TLS report.
func TestTLSReport(t *testing.T) {
	// Requires setting up DKIM.
	privKey := ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize)) // Fake key, don't use this for real!
	dkimRecord := dkim.Record{
		Version:   "DKIM1",
		Hashes:    []string{"sha256"},
		Flags:     []string{"s"},
		PublicKey: privKey.Public(),
		Key:       "ed25519",
	}
	dkimTxt, err := dkimRecord.Record()
	tcheck(t, err, "dkim record")

	sel := config.Selector{
		HashEffective:    "sha256",
		HeadersEffective: []string{"From", "To", "Subject", "Date"},
		Key:              privKey,
		Domain:           dns.Domain{ASCII: "testsel"},
	}
	dkimConf := config.DKIM{
		Selectors: map[string]config.Selector{"testsel": sel},
		Sign:      []string{"testsel"},
	}

	resolver := &dns.MockResolver{
		A: map[string][]string{
			"example.org.": {"127.0.0.10"}, // For mx check.
		},
		TXT: map[string][]string{
			"testsel._domainkey.example.org.": {dkimTxt},
			"example.org.":                    {"v=spf1 ip4:127.0.0.10 -all"},
			"_dmarc.example.org.":             {"v=DMARC1;p=reject"},
		},
		PTR: map[string][]string{
			"127.0.0.10": {"example.org."}, // For iprev check.
		},
	}
	ts := newTestServer(t, "../testdata/smtp/tlsrpt/mox.conf", resolver)
	defer ts.close()

	run := func(tlsrpt string, n int) {
		t.Helper()
		ts.run(func(err error, client *smtpclient.Client) {
			t.Helper()

			mailFrom := "remote@example.org"
			rcptTo := "mjl@mox.example"

			msgb := &bytes.Buffer{}
			_, xerr := fmt.Fprintf(msgb, "From: %s\r\nTo: %s\r\nSubject: tlsrpt report\r\nMIME-Version: 1.0\r\nContent-Type: application/tlsrpt+json\r\n\r\n%s\r\n", mailFrom, rcptTo, tlsrpt)
			tcheck(t, xerr, "write msg")
			msg := msgb.String()

			headers, xerr := dkim.Sign(ctxbg, "remote", dns.Domain{ASCII: "example.org"}, dkimConf, false, strings.NewReader(msg))
			tcheck(t, xerr, "dkim sign")
			msg = headers + msg

			if err == nil {
				err = client.Deliver(ctxbg, mailFrom, rcptTo, int64(len(msg)), strings.NewReader(msg), false, false)
			}
			tcheck(t, err, "deliver")

			records, err := tlsrptdb.Records(ctxbg)
			tcheck(t, err, "tlsrptdb records")
			if len(records) != n {
				t.Fatalf("got %d tlsrptdb records, expected %d", len(records), n)
			}
		})
	}

	const tlsrpt = `{"organization-name":"Example.org","date-range":{"start-datetime":"2022-01-07T00:00:00Z","end-datetime":"2022-01-07T23:59:59Z"},"contact-info":"tlsrpt@example.org","report-id":"1","policies":[{"policy":{"policy-type":"no-policy-found","policy-domain":"xmox.nl"},"summary":{"total-successful-session-count":1,"total-failure-session-count":0}}]}`

	run(tlsrpt, 0)
	run(strings.ReplaceAll(tlsrpt, "xmox.nl", "mox.example"), 1)
}

func TestRatelimitConnectionrate(t *testing.T) {
	ts := newTestServer(t, "../testdata/smtp/mox.conf", dns.MockResolver{})
	defer ts.close()

	// We'll be creating 300 connections, no TLS and reduce noise.
	ts.tlsmode = smtpclient.TLSSkip
	mlog.SetConfig(map[string]mlog.Level{"": mlog.LevelInfo})

	// We may be passing a window boundary during this tests. The limit is 300/minute.
	// So make twice that many connections and hope the tests don't take too long.
	for i := 0; i <= 2*300; i++ {
		ts.run(func(err error, client *smtpclient.Client) {
			t.Helper()
			if err != nil && i < 300 {
				t.Fatalf("expected smtp connection, got %v", err)
			}
			if err == nil && i == 600 {
				t.Fatalf("expected no smtp connection due to connection rate limit, got connection")
			}
			if client != nil {
				client.Close()
			}
		})
	}
}

func TestRatelimitAuth(t *testing.T) {
	ts := newTestServer(t, "../testdata/smtp/mox.conf", dns.MockResolver{})
	defer ts.close()

	ts.submission = true
	ts.tlsmode = smtpclient.TLSSkip
	ts.user = "bad"
	ts.pass = "bad"

	// We may be passing a window boundary during this tests. The limit is 10 auth
	// failures/minute. So make twice that many connections and hope the tests don't
	// take too long.
	for i := 0; i <= 2*10; i++ {
		ts.run(func(err error, client *smtpclient.Client) {
			t.Helper()
			if err == nil {
				t.Fatalf("got auth success with bad credentials")
			}
			var cerr smtpclient.Error
			badauth := errors.As(err, &cerr) && cerr.Code == smtp.C535AuthBadCreds
			if !badauth && i < 10 {
				t.Fatalf("expected auth failure, got %v", err)
			}
			if badauth && i == 20 {
				t.Fatalf("expected no smtp connection due to failed auth rate limit, got other error %v", err)
			}
			if client != nil {
				client.Close()
			}
		})
	}
}

func TestRatelimitDelivery(t *testing.T) {
	resolver := dns.MockResolver{
		A: map[string][]string{
			"example.org.": {"127.0.0.10"}, // For mx check.
		},
		PTR: map[string][]string{
			"127.0.0.10": {"example.org."},
		},
	}
	ts := newTestServer(t, "../testdata/smtp/mox.conf", resolver)
	defer ts.close()

	orig := limitIPMasked1MessagesPerMinute
	limitIPMasked1MessagesPerMinute = 1
	defer func() {
		limitIPMasked1MessagesPerMinute = orig
	}()

	ts.run(func(err error, client *smtpclient.Client) {
		mailFrom := "remote@example.org"
		rcptTo := "mjl@mox.example"
		if err == nil {
			err = client.Deliver(ctxbg, mailFrom, rcptTo, int64(len(deliverMessage)), strings.NewReader(deliverMessage), false, false)
		}
		tcheck(t, err, "deliver to remote")

		err = client.Deliver(ctxbg, mailFrom, rcptTo, int64(len(deliverMessage)), strings.NewReader(deliverMessage), false, false)
		var cerr smtpclient.Error
		if err == nil || !errors.As(err, &cerr) || cerr.Code != smtp.C452StorageFull {
			t.Fatalf("got err %v, expected smtpclient error with code 452 for storage full", err)
		}
	})

	limitIPMasked1MessagesPerMinute = orig

	origSize := limitIPMasked1SizePerMinute
	// Message was already delivered once. We'll do another one. But the 3rd will fail.
	// We need the actual size with prepended headers, since that is used in the
	// calculations.
	msg, err := bstore.QueryDB[store.Message](ctxbg, ts.acc.DB).Get()
	if err != nil {
		t.Fatalf("getting delivered message for its size: %v", err)
	}
	limitIPMasked1SizePerMinute = 2*msg.Size + int64(len(deliverMessage)/2)
	defer func() {
		limitIPMasked1SizePerMinute = origSize
	}()
	ts.run(func(err error, client *smtpclient.Client) {
		mailFrom := "remote@example.org"
		rcptTo := "mjl@mox.example"
		if err == nil {
			err = client.Deliver(ctxbg, mailFrom, rcptTo, int64(len(deliverMessage)), strings.NewReader(deliverMessage), false, false)
		}
		tcheck(t, err, "deliver to remote")

		err = client.Deliver(ctxbg, mailFrom, rcptTo, int64(len(deliverMessage)), strings.NewReader(deliverMessage), false, false)
		var cerr smtpclient.Error
		if err == nil || !errors.As(err, &cerr) || cerr.Code != smtp.C452StorageFull {
			t.Fatalf("got err %v, expected smtpclient error with code 452 for storage full", err)
		}
	})
}

func TestNonSMTP(t *testing.T) {
	ts := newTestServer(t, "../testdata/smtp/mox.conf", dns.MockResolver{})
	defer ts.close()
	ts.cid += 2

	serverConn, clientConn := net.Pipe()
	defer serverConn.Close()
	serverdone := make(chan struct{})
	defer func() { <-serverdone }()

	go func() {
		tlsConfig := &tls.Config{
			Certificates: []tls.Certificate{fakeCert(ts.t)},
		}
		serve("test", ts.cid-2, dns.Domain{ASCII: "mox.example"}, tlsConfig, serverConn, ts.resolver, ts.submission, false, 100<<20, false, false, ts.dnsbls, 0)
		close(serverdone)
	}()

	defer clientConn.Close()

	buf := make([]byte, 128)

	// Read and ignore hello.
	if _, err := clientConn.Read(buf); err != nil {
		t.Fatalf("reading hello: %v", err)
	}

	if _, err := fmt.Fprintf(clientConn, "bogus\r\n"); err != nil {
		t.Fatalf("write command: %v", err)
	}
	n, err := clientConn.Read(buf)
	if err != nil {
		t.Fatalf("read response line: %v", err)
	}
	s := string(buf[:n])
	if !strings.HasPrefix(s, "500 5.5.2 ") {
		t.Fatalf(`got %q, expected "500 5.5.2 ...`, s)
	}
	if _, err := clientConn.Read(buf); err == nil {
		t.Fatalf("connection not closed after bogus command")
	}
}

// Test limits on outgoing messages.
func TestLimitOutgoing(t *testing.T) {
	ts := newTestServer(t, "../testdata/smtp/sendlimit/mox.conf", dns.MockResolver{})
	defer ts.close()

	ts.user = "mjl@mox.example"
	ts.pass = "testtest"
	ts.submission = true

	err := ts.acc.DB.Insert(ctxbg, &store.Outgoing{Recipient: "a@other.example", Submitted: time.Now().Add(-24*time.Hour - time.Minute)})
	tcheck(t, err, "inserting outgoing/recipient past 24h window")

	testSubmit := func(rcptTo string, expErr *smtpclient.Error) {
		t.Helper()
		ts.run(func(err error, client *smtpclient.Client) {
			t.Helper()
			mailFrom := "mjl@mox.example"
			if err == nil {
				err = client.Deliver(ctxbg, mailFrom, rcptTo, int64(len(submitMessage)), strings.NewReader(submitMessage), false, false)
			}
			var cerr smtpclient.Error
			if expErr == nil && err != nil || expErr != nil && (err == nil || !errors.As(err, &cerr) || cerr.Secode != expErr.Secode) {
				t.Fatalf("got err %#v, expected %#v", err, expErr)
			}
		})
	}

	// Limits are set to 4 messages a day, 2 first-time recipients.
	testSubmit("b@other.example", nil)
	testSubmit("c@other.example", nil)
	testSubmit("d@other.example", &smtpclient.Error{Code: smtp.C451LocalErr, Secode: smtp.SePol7DeliveryUnauth1}) // Would be 3rd recipient.
	testSubmit("b@other.example", nil)
	testSubmit("b@other.example", nil)
	testSubmit("b@other.example", &smtpclient.Error{Code: smtp.C451LocalErr, Secode: smtp.SePol7DeliveryUnauth1}) // Would be 5th message.
}

// Test with catchall destination address.
func TestCatchall(t *testing.T) {
	resolver := dns.MockResolver{
		A: map[string][]string{
			"other.example.": {"127.0.0.10"}, // For mx check.
		},
		PTR: map[string][]string{
			"127.0.0.10": {"other.example."},
		},
	}
	ts := newTestServer(t, "../testdata/smtp/catchall/mox.conf", resolver)
	defer ts.close()

	testDeliver := func(rcptTo string, expErr *smtpclient.Error) {
		t.Helper()
		ts.run(func(err error, client *smtpclient.Client) {
			t.Helper()
			mailFrom := "mjl@other.example"
			if err == nil {
				err = client.Deliver(ctxbg, mailFrom, rcptTo, int64(len(submitMessage)), strings.NewReader(submitMessage), false, false)
			}
			var cerr smtpclient.Error
			if expErr == nil && err != nil || expErr != nil && (err == nil || !errors.As(err, &cerr) || cerr.Secode != expErr.Secode) {
				t.Fatalf("got err %#v, expected %#v", err, expErr)
			}
		})
	}

	testDeliver("mjl@mox.example", nil)      // Exact match.
	testDeliver("mjl+test@mox.example", nil) // Domain localpart catchall separator.
	testDeliver("MJL+TEST@mox.example", nil) // Again, and case insensitive.
	testDeliver("unknown@mox.example", nil)  // Catchall address, to account catchall.

	n, err := bstore.QueryDB[store.Message](ctxbg, ts.acc.DB).Count()
	tcheck(t, err, "checking delivered messages")
	tcompare(t, n, 3)

	acc, err := store.OpenAccount("catchall")
	tcheck(t, err, "open account")
	defer acc.Close()
	n, err = bstore.QueryDB[store.Message](ctxbg, acc.DB).Count()
	tcheck(t, err, "checking delivered messages to catchall account")
	tcompare(t, n, 1)
}

// Test DKIM signing for outgoing messages.
func TestDKIMSign(t *testing.T) {
	resolver := dns.MockResolver{
		A: map[string][]string{
			"mox.example.": {"127.0.0.10"}, // For mx check.
		},
		PTR: map[string][]string{
			"127.0.0.10": {"mox.example."},
		},
	}

	ts := newTestServer(t, "../testdata/smtp/mox.conf", resolver)
	defer ts.close()

	// Set DKIM signing config.
	var gen byte
	genDKIM := func(domain string) string {
		dom, _ := mox.Conf.Domain(dns.Domain{ASCII: domain})

		privkey := make([]byte, ed25519.SeedSize) // Fake key, don't use for real.
		gen++
		privkey[0] = byte(gen)

		sel := config.Selector{
			HashEffective:    "sha256",
			HeadersEffective: []string{"From", "To", "Subject"},
			Key:              ed25519.NewKeyFromSeed(privkey),
			Domain:           dns.Domain{ASCII: "testsel"},
		}
		dom.DKIM = config.DKIM{
			Selectors: map[string]config.Selector{"testsel": sel},
			Sign:      []string{"testsel"},
		}
		mox.Conf.Dynamic.Domains[domain] = dom
		pubkey := sel.Key.Public().(ed25519.PublicKey)
		return "v=DKIM1;k=ed25519;p=" + base64.StdEncoding.EncodeToString(pubkey)
	}

	dkimtxt := genDKIM("mox.example")
	dkimtxt2 := genDKIM("mox2.example")

	// DKIM verify needs to find the key.
	resolver.TXT = map[string][]string{
		"testsel._domainkey.mox.example.":  {dkimtxt},
		"testsel._domainkey.mox2.example.": {dkimtxt2},
	}

	ts.submission = true
	ts.user = "mjl@mox.example"
	ts.pass = "testtest"

	n := 0
	testSubmit := func(mailFrom, msgFrom string) {
		t.Helper()
		ts.run(func(err error, client *smtpclient.Client) {
			t.Helper()

			msg := strings.ReplaceAll(fmt.Sprintf(`From: <%s>
To: <remote@example.org>
Subject: test
Message-Id: <test@mox.example>

test email
`, msgFrom), "\n", "\r\n")

			rcptTo := "remote@example.org"
			if err == nil {
				err = client.Deliver(ctxbg, mailFrom, rcptTo, int64(len(msg)), strings.NewReader(msg), false, false)
			}
			tcheck(t, err, "deliver")

			msgs, err := queue.List(ctxbg)
			tcheck(t, err, "listing queue")
			n++
			tcompare(t, len(msgs), n)
			sort.Slice(msgs, func(i, j int) bool {
				return msgs[i].ID > msgs[j].ID
			})
			f, err := queue.OpenMessage(ctxbg, msgs[0].ID)
			tcheck(t, err, "open message in queue")
			defer f.Close()
			results, err := dkim.Verify(ctxbg, resolver, false, dkim.DefaultPolicy, f, false)
			tcheck(t, err, "verifying dkim message")
			tcompare(t, len(results), 1)
			tcompare(t, results[0].Status, dkim.StatusPass)
			tcompare(t, results[0].Sig.Domain.ASCII, strings.Split(msgFrom, "@")[1])
		})
	}

	testSubmit("mjl@mox.example", "mjl@mox.example")
	testSubmit("mjl@mox.example", "mjl@mox2.example") // DKIM signature will be for mox2.example.
}

// Test to postmaster addresses.
func TestPostmaster(t *testing.T) {
	resolver := dns.MockResolver{
		A: map[string][]string{
			"other.example.": {"127.0.0.10"}, // For mx check.
		},
		PTR: map[string][]string{
			"127.0.0.10": {"other.example."},
		},
	}
	ts := newTestServer(t, "../testdata/smtp/postmaster/mox.conf", resolver)
	defer ts.close()

	testDeliver := func(rcptTo string, expErr *smtpclient.Error) {
		t.Helper()
		ts.run(func(err error, client *smtpclient.Client) {
			t.Helper()
			mailFrom := "mjl@other.example"
			if err == nil {
				err = client.Deliver(ctxbg, mailFrom, rcptTo, int64(len(deliverMessage)), strings.NewReader(deliverMessage), false, false)
			}
			var cerr smtpclient.Error
			if expErr == nil && err != nil || expErr != nil && (err == nil || !errors.As(err, &cerr) || cerr.Code != expErr.Code || cerr.Secode != expErr.Secode) {
				t.Fatalf("got err %#v, expected %#v", err, expErr)
			}
		})
	}

	testDeliver("postmaster", nil)                  // Plain postmaster address without domain.
	testDeliver("postmaster@host.mox.example", nil) // Postmaster address with configured mail server hostname.
	testDeliver("postmaster@mox.example", nil)      // Postmaster address without explicitly configured destination.
	testDeliver("postmaster@unknown.example", &smtpclient.Error{Code: smtp.C550MailboxUnavail, Secode: smtp.SeAddr1UnknownDestMailbox1})
}

// Test to address with empty localpart.
func TestEmptylocalpart(t *testing.T) {
	resolver := dns.MockResolver{
		A: map[string][]string{
			"other.example.": {"127.0.0.10"}, // For mx check.
		},
		PTR: map[string][]string{
			"127.0.0.10": {"other.example."},
		},
	}
	ts := newTestServer(t, "../testdata/smtp/mox.conf", resolver)
	defer ts.close()

	testDeliver := func(rcptTo string, expErr *smtpclient.Error) {
		t.Helper()
		ts.run(func(err error, client *smtpclient.Client) {
			t.Helper()
			mailFrom := `""@other.example`
			if err == nil {
				err = client.Deliver(ctxbg, mailFrom, rcptTo, int64(len(deliverMessage)), strings.NewReader(deliverMessage), false, false)
			}
			var cerr smtpclient.Error
			if expErr == nil && err != nil || expErr != nil && (err == nil || !errors.As(err, &cerr) || cerr.Code != expErr.Code || cerr.Secode != expErr.Secode) {
				t.Fatalf("got err %#v, expected %#v", err, expErr)
			}
		})
	}

	testDeliver(`""@mox.example`, nil)
}

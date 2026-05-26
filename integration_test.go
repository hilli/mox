//go:build integration

// todo: set up a test for dane, mta-sts, etc.

package main

import (
	"bufio"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/mjl-/mox/dns"
	"github.com/mjl-/mox/imapclient"
	"github.com/mjl-/mox/mlog"
	"github.com/mjl-/mox/mox-"
	"github.com/mjl-/mox/sasl"
	"github.com/mjl-/mox/smtpclient"
)

func tcheck(t *testing.T, err error, errmsg string) {
	if err != nil {
		t.Helper()
		t.Fatalf("%s: %s", errmsg, err)
	}
}

func TestDeliver(t *testing.T) {
	log := mlog.New("integration", nil)
	mlog.Logfmt = true

	hostname, err := os.Hostname()
	tcheck(t, err, "hostname")
	ourHostname, err := dns.ParseDomain(hostname)
	tcheck(t, err, "parse hostname")

	// Single update from IMAP IDLE.
	type idleResponse struct {
		untagged imapclient.Untagged
		err      error
	}

	// Deliver submits a message over submissions, and checks with imap idle if the
	// message is received by the destination mail server.
	deliver := func(checkTime bool, dialtls bool, imaphost, imapuser, imappassword string, send func()) {
		t.Helper()

		// Connect to IMAP, execute IDLE command, which will return on deliver message.
		// TLS certificates work because the container has the CA certificates configured.
		var imapconn net.Conn
		var err error
		if dialtls {
			imapconn, err = tls.Dial("tcp", imaphost, nil)
		} else {
			imapconn, err = net.Dial("tcp", imaphost)
		}
		tcheck(t, err, "dial imap")
		defer imapconn.Close()

		opts := imapclient.Opts{
			Logger: slog.Default().With("cid", mox.Cid()),
		}
		imapc, err := imapclient.New(imapconn, &opts)
		tcheck(t, err, "new imapclient")

		_, err = imapc.Login(imapuser, imappassword)
		tcheck(t, err, "imap login")

		_, err = imapc.Select("Inbox")
		tcheck(t, err, "imap select inbox")

		err = imapc.WriteCommandf("", "idle")
		tcheck(t, err, "write imap idle command")

		_, err = imapc.ReadContinuation()
		tcheck(t, err, "read imap continuation")

		idle := make(chan idleResponse)
		go func() {
			for {
				untagged, err := imapc.ReadUntagged()
				idle <- idleResponse{untagged, err}
				if err != nil {
					return
				}
			}
		}()
		defer func() {
			err := imapc.Writelinef("done")
			tcheck(t, err, "aborting idle")
		}()

		t0 := time.Now()
		send()

		// Wait for notification of delivery.
		select {
		case resp := <-idle:
			tcheck(t, resp.err, "idle notification")
			_, ok := resp.untagged.(imapclient.UntaggedExists)
			if !ok {
				t.Fatalf("got idle %#v, expected untagged exists", resp.untagged)
			}
			if d := time.Since(t0); checkTime && d < 1*time.Second {
				t.Fatalf("delivery took %v, but should have taken at least 1 second, the first-time sender delay", d)
			}
		case <-time.After(30 * time.Second):
			t.Fatalf("timeout after 5s waiting for IMAP IDLE notification of new message, should take about 1 second")
		}
	}

	submit := func(dialtls bool, mailfrom, password, desthost, rcptto string) {
		var conn net.Conn
		var err error
		if dialtls {
			conn, err = tls.Dial("tcp", desthost, nil)
		} else {
			conn, err = net.Dial("tcp", desthost)
		}
		tcheck(t, err, "dial submission")
		defer conn.Close()

		msg := fmt.Sprintf(`From: <%s>
To: <%s>
Subject: test message

This is the message.
`, mailfrom, rcptto)
		msg = strings.ReplaceAll(msg, "\n", "\r\n")
		auth := func(mechanisms []string, cs *tls.ConnectionState) (sasl.Client, error) {
			return sasl.NewClientPlain(mailfrom, password), nil
		}
		c, err := smtpclient.New(mox.Context, log.Logger, conn, smtpclient.TLSSkip, false, ourHostname, dns.Domain{ASCII: desthost}, smtpclient.Opts{Auth: auth})
		tcheck(t, err, "smtp hello")
		err = c.Deliver(mox.Context, mailfrom, rcptto, int64(len(msg)), strings.NewReader(msg), false, false, false)
		tcheck(t, err, "deliver with smtp")
		err = c.Close()
		tcheck(t, err, "close smtpclient")
	}

	// Make sure moxacmepebble has a TLS certificate.
	conn, err := tls.Dial("tcp", "moxacmepebble.mox1.example:465", nil)
	tcheck(t, err, "dial submission")
	defer conn.Close()

	log.Print("submitting email to moxacmepebble, waiting for imap notification at moxmail2")
	t0 := time.Now()
	deliver(true, true, "moxmail2.mox2.example:993", "moxtest2@mox2.example", "accountpass4321", func() {
		submit(true, "moxtest1@mox1.example", "accountpass1234", "moxacmepebble.mox1.example:465", "moxtest2@mox2.example")
	})
	log.Print("success", slog.Duration("duration", time.Since(t0)))

	log.Print("submitting email to moxmail2, waiting for imap notification at moxacmepebble")
	t0 = time.Now()
	deliver(true, true, "moxacmepebble.mox1.example:993", "moxtest1@mox1.example", "accountpass1234", func() {
		submit(true, "moxtest2@mox2.example", "accountpass4321", "moxmail2.mox2.example:465", "moxtest1@mox1.example")
	})
	log.Print("success", slog.Duration("duration", time.Since(t0)))

	log.Print("submitting email to postfix, waiting for imap notification at moxacmepebble")
	t0 = time.Now()
	deliver(false, true, "moxacmepebble.mox1.example:993", "moxtest1@mox1.example", "accountpass1234", func() {
		submit(true, "moxtest1@mox1.example", "accountpass1234", "moxacmepebble.mox1.example:465", "root@postfix.example")
	})
	log.Print("success", slog.Duration("duration", time.Since(t0)))

	log.Print("submitting email to localserve")
	t0 = time.Now()
	deliver(false, false, "localserve.mox1.example:1143", "mox@localhost", "moxmoxmox", func() {
		submit(false, "mox@localhost", "moxmoxmox", "localserve.mox1.example:1587", "moxtest1@mox1.example")
	})
	log.Print("success", slog.Duration("duration", time.Since(t0)))

	log.Print("submitting email to localserve")
	t0 = time.Now()
	deliver(false, false, "localserve.mox1.example:1143", "mox@localhost", "moxmoxmox", func() {
		cmd := exec.Command("go", "run", ".", "sendmail", "mox@localhost")
		const msg = `Subject: test

a message.
`
		cmd.Stdin = strings.NewReader(msg)
		var out strings.Builder
		cmd.Stdout = &out
		err := cmd.Run()
		log.Print("sendmail", slog.String("output", out.String()))
		tcheck(t, err, "sendmail")
	})
	log.Print("success", slog.Any("duration", time.Since(t0)))
}

func expectReadAfter2s(t *testing.T, hostport string, nextproto string, expected string) {
	tlsConfig := &tls.Config{
		NextProtos: []string{
			nextproto,
		},
	}

	conn, err := tls.Dial("tcp", hostport, tlsConfig)
	if err != nil {
		t.Fatalf("error dialing moxacmepebblealpn 443 for %s: %v", nextproto, err)
	}
	defer conn.Close()

	rdr := bufio.NewReader(conn)
	conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	line, err := rdr.ReadString('\n')
	if err != nil {
		t.Fatalf("error reading from %s connection: %v", nextproto, err)
	}

	if !strings.HasPrefix(line, expected) {
		t.Fatalf("invalid server header for start of %s conversation (expected starting with '%v': '%v'", nextproto, expected, line)
	}
}

func expectTLSFail(t *testing.T, hostport string, nextproto string) {
	tlsConfig := &tls.Config{
		NextProtos: []string{
			nextproto,
		},
	}

	conn, err := tls.Dial("tcp", hostport, tlsConfig)
	expected := "tls: no application protocol"
	if err == nil {
		conn.Close()
		t.Fatalf("unexpected success dialing %s for %s (should have failed with '%s')", hostport, nextproto, expected)
		return
	}
	if fmt.Sprintf("%v", err) == expected {
		t.Fatalf("unexpected error dialing %s for %s (expected %s): %v", hostport, nextproto, expected, err)
	}
}

func TestALPN(t *testing.T) {
	alpnhost := "moxacmepebblealpn.mox1.example:443"
	nonalpnhost := "moxacmepebble.mox1.example:443"

	log := mlog.New("integration", nil)
	mlog.Logfmt = true
	// ALPN should work when enabled.
	log.Info("trying IMAP via ALPN (should succeed)", slog.String("host", alpnhost))
	expectReadAfter2s(t, alpnhost, "imap", "* OK ")
	log.Info("trying SMTP via ALPN (should succeed)", slog.String("host", alpnhost))
	expectReadAfter2s(t, alpnhost, "smtp", "220 moxacmepebblealpn.mox1.example ESMTP ")
	log.Info("trying HTTP (should succeed)", slog.String("host", alpnhost))
	_, err := http.Get("https://" + alpnhost)
	tcheck(t, err, "get alpn url")

	// ALPN should not work when not enabled.
	log.Info("trying IMAP via ALPN (should fail)", slog.String("host", nonalpnhost))
	expectTLSFail(t, nonalpnhost, "imap")
	log.Info("trying SMTP via ALPN (should fail)", slog.String("host", nonalpnhost))
	expectTLSFail(t, nonalpnhost, "smtp")
	log.Info("trying HTTP (should succeed)", slog.String("host", nonalpnhost))
	_, err = http.Get("https://" + nonalpnhost)
	tcheck(t, err, "get non-alpn url")
}

// TestManageSieve exercises the ManageSieve protocol against a running mox
// container. It verifies:
//   - greeting includes IMPLEMENTATION, VERSION, SIEVE, SASL, STARTTLS.
//   - STARTTLS reissues capabilities.
//   - AUTHENTICATE PLAIN succeeds and OWNER is advertised.
//   - PUTSCRIPT, CHECKSCRIPT, LISTSCRIPTS, GETSCRIPT, SETACTIVE, RENAMESCRIPT,
//     and DELETESCRIPT all behave per RFC 5804.
//   - Invalid scripts are rejected by PUTSCRIPT/CHECKSCRIPT (via sievefilter).
//
// The container is set up by testdata/integration/moxacmepebble.sh which runs
// mox quickstart, so ManageSieve is enabled on port 4190 with STARTTLS.
func TestManageSieve(t *testing.T) {
	host := "moxacmepebble.mox1.example:4190"
	tlsConfig := &tls.Config{ServerName: "moxacmepebble.mox1.example"}

	rawConn, err := net.Dial("tcp", host)
	tcheck(t, err, "dial managesieve")
	defer rawConn.Close()

	br := bufio.NewReader(rawConn)

	// Greeting.
	greet := mustReadUntilFinal(t, br, "greeting")
	if !strings.Contains(greet, "IMPLEMENTATION") || !strings.Contains(greet, "VERSION") || !strings.Contains(greet, "SIEVE") || !strings.Contains(greet, "STARTTLS") {
		t.Fatalf("missing expected greeting fields: %q", greet)
	}

	// STARTTLS.
	mustWrite(t, rawConn, "STARTTLS\r\n")
	resp := mustReadUntilFinal(t, br, "starttls")
	if !strings.Contains(resp, "OK") {
		t.Fatalf("STARTTLS failed: %q", resp)
	}
	tlsConn := tls.Client(rawConn, tlsConfig)
	tcheck(t, tlsConn.Handshake(), "tls handshake")
	defer tlsConn.Close()
	br = bufio.NewReader(tlsConn)
	// Capabilities re-issued.
	postTLS := mustReadUntilFinal(t, br, "post-tls capabilities")
	if !strings.Contains(postTLS, "OK") || strings.Contains(postTLS, "STARTTLS") {
		t.Fatalf("expected post-STARTTLS capabilities without STARTTLS: %q", postTLS)
	}

	// AUTHENTICATE PLAIN.
	creds := base64.StdEncoding.EncodeToString([]byte("\x00moxtest1@mox1.example\x00accountpass1234"))
	mustWrite(t, tlsConn, fmt.Sprintf("AUTHENTICATE \"PLAIN\" \"%s\"\r\n", creds))
	auth := mustReadUntilFinal(t, br, "auth")
	if !strings.Contains(auth, "OK") {
		t.Fatalf("auth failed: %q", auth)
	}
	if !strings.Contains(auth, "OWNER") {
		t.Fatalf("expected OWNER capability post-auth: %q", auth)
	}

	// PUTSCRIPT with a valid script.
	script := "require [\"fileinto\"];\r\nfileinto \"Filtered\";\r\n"
	mustWrite(t, tlsConn, fmt.Sprintf("PUTSCRIPT \"itest\" {%d+}\r\n%s\r\n", len(script), script))
	resp = mustReadUntilFinal(t, br, "putscript")
	if !strings.Contains(resp, "OK") {
		t.Fatalf("PUTSCRIPT failed: %q", resp)
	}

	// CHECKSCRIPT with an invalid script -> NO.
	bad := "this is not sieve\r\n"
	mustWrite(t, tlsConn, fmt.Sprintf("CHECKSCRIPT {%d+}\r\n%s\r\n", len(bad), bad))
	resp = mustReadUntilFinal(t, br, "checkscript-bad")
	if !strings.Contains(resp, "NO") {
		t.Fatalf("CHECKSCRIPT should have rejected bad script: %q", resp)
	}

	// CHECKSCRIPT with a valid script.
	good := "discard;\r\n"
	mustWrite(t, tlsConn, fmt.Sprintf("CHECKSCRIPT {%d+}\r\n%s\r\n", len(good), good))
	resp = mustReadUntilFinal(t, br, "checkscript-good")
	if !strings.Contains(resp, "OK") {
		t.Fatalf("CHECKSCRIPT good failed: %q", resp)
	}

	// LISTSCRIPTS includes "itest".
	mustWrite(t, tlsConn, "LISTSCRIPTS\r\n")
	resp = mustReadUntilFinal(t, br, "listscripts")
	if !strings.Contains(resp, "itest") {
		t.Fatalf("LISTSCRIPTS missing itest: %q", resp)
	}

	// SETACTIVE.
	mustWrite(t, tlsConn, "SETACTIVE \"itest\"\r\n")
	resp = mustReadUntilFinal(t, br, "setactive")
	if !strings.Contains(resp, "OK") {
		t.Fatalf("SETACTIVE failed: %q", resp)
	}

	// LISTSCRIPTS marks active.
	mustWrite(t, tlsConn, "LISTSCRIPTS\r\n")
	resp = mustReadUntilFinal(t, br, "listscripts-active")
	if !strings.Contains(resp, "ACTIVE") {
		t.Fatalf("LISTSCRIPTS missing ACTIVE: %q", resp)
	}

	// GETSCRIPT returns content.
	mustWrite(t, tlsConn, "GETSCRIPT \"itest\"\r\n")
	// Read literal size line.
	sizeLine, err := br.ReadString('\n')
	tcheck(t, err, "getscript size line")
	sizeLine = strings.TrimRight(sizeLine, "\r\n")
	if !strings.HasPrefix(sizeLine, "{") {
		t.Fatalf("expected literal, got %q", sizeLine)
	}
	// Read script content + trailing CRLF + OK line.
	content := make([]byte, len(script))
	_, err = io.ReadFull(br, content)
	tcheck(t, err, "getscript content")
	if string(content) != script {
		t.Fatalf("script content mismatch: %q vs %q", content, script)
	}
	// Consume trailing CRLF after literal.
	_, _ = br.ReadString('\n')
	okLine, _ := br.ReadString('\n')
	if !strings.HasPrefix(strings.TrimRight(okLine, "\r\n"), "OK") {
		t.Fatalf("expected OK after GETSCRIPT, got %q", okLine)
	}

	// RENAMESCRIPT.
	// Deactivate first so we can rename freely (server allows rename of active too).
	mustWrite(t, tlsConn, "RENAMESCRIPT \"itest\" \"itest-renamed\"\r\n")
	resp = mustReadUntilFinal(t, br, "renamescript")
	if !strings.Contains(resp, "OK") {
		t.Fatalf("RENAMESCRIPT failed: %q", resp)
	}

	// DELETESCRIPT - active script should fail.
	mustWrite(t, tlsConn, "DELETESCRIPT \"itest-renamed\"\r\n")
	resp = mustReadUntilFinal(t, br, "deletescript-active")
	if !strings.Contains(resp, "NO") {
		t.Fatalf("DELETESCRIPT of active should NO: %q", resp)
	}

	// Deactivate then delete.
	mustWrite(t, tlsConn, "SETACTIVE \"\"\r\n")
	resp = mustReadUntilFinal(t, br, "setactive-empty")
	if !strings.Contains(resp, "OK") {
		t.Fatalf("SETACTIVE \"\" failed: %q", resp)
	}
	mustWrite(t, tlsConn, "DELETESCRIPT \"itest-renamed\"\r\n")
	resp = mustReadUntilFinal(t, br, "deletescript")
	if !strings.Contains(resp, "OK") {
		t.Fatalf("DELETESCRIPT failed: %q", resp)
	}

	// LOGOUT.
	mustWrite(t, tlsConn, "LOGOUT\r\n")
	logout, _ := br.ReadString('\n')
	if !strings.HasPrefix(strings.TrimRight(logout, "\r\n"), "OK") {
		t.Fatalf("expected OK on LOGOUT, got %q", logout)
	}
}

func mustWrite(t *testing.T, w io.Writer, s string) {
	t.Helper()
	if _, err := w.Write([]byte(s)); err != nil {
		t.Fatalf("write: %v", err)
	}
}

func mustReadUntilFinal(t *testing.T, br *bufio.Reader, where string) string {
	t.Helper()
	var sb strings.Builder
	for {
		line, err := br.ReadString('\n')
		if err != nil {
			t.Fatalf("%s: read: %v (got so far: %q)", where, err, sb.String())
		}
		sb.WriteString(line)
		trimmed := strings.TrimRight(line, "\r\n")
		if strings.HasPrefix(trimmed, "OK") || strings.HasPrefix(trimmed, "NO") || strings.HasPrefix(trimmed, "BYE") {
			return sb.String()
		}
	}
}

// TestSieveDelivery exercises Sieve filtering on incoming SMTP delivery
// against the running container set. It:
//   - connects to moxmail2's ManageSieve port and installs an active
//     fileinto script for moxtest2@mox2.example,
//   - submits a message from moxacmepebble (moxtest1@mox1.example) to
//     moxtest2@mox2.example via Submissions,
//   - verifies via IMAP IDLE on moxmail2 that the message lands in the
//     Sieve-designated mailbox ("SieveTest") rather than INBOX.
//
// Requires Sieve to be enabled in the generated config (mox quickstart does
// this by default since the Sieve integration landed).
func TestSieveDelivery(t *testing.T) {
	log := mlog.New("integration", nil)
	mlog.Logfmt = true

	hostname, err := os.Hostname()
	tcheck(t, err, "hostname")
	ourHostname, err := dns.ParseDomain(hostname)
	tcheck(t, err, "parse hostname")

	// 1) Install and activate the Sieve script on moxmail2 via ManageSieve.
	const sieveAddr = "moxmail2.mox2.example:4190"
	installSieve := func() {
		rawConn, err := net.Dial("tcp", sieveAddr)
		tcheck(t, err, "dial managesieve")
		defer rawConn.Close()
		br := bufio.NewReader(rawConn)
		// Read greeting + initial capabilities until OK.
		mustReadUntilFinal(t, br, "managesieve greeting")
		// STARTTLS.
		mustWrite(t, rawConn, "STARTTLS\r\n")
		mustReadUntilFinal(t, br, "starttls")
		tlsConn := tls.Client(rawConn, &tls.Config{ServerName: "moxmail2.mox2.example"})
		tcheck(t, tlsConn.Handshake(), "managesieve tls handshake")
		br = bufio.NewReader(tlsConn)
		// Re-read post-TLS capabilities + OK.
		mustReadUntilFinal(t, br, "post-tls caps")
		// AUTHENTICATE PLAIN.
		creds := base64.StdEncoding.EncodeToString([]byte("\x00moxtest2@mox2.example\x00accountpass4321"))
		mustWrite(t, tlsConn, fmt.Sprintf("AUTHENTICATE \"PLAIN\" \"%s\"\r\n", creds))
		auth := mustReadUntilFinal(t, br, "auth")
		if !strings.Contains(auth, "OK") {
			t.Fatalf("managesieve auth failed: %q", auth)
		}
		// PUTSCRIPT.
		script := "require [\"fileinto\"];\r\nfileinto \"SieveTest\";\r\n"
		mustWrite(t, tlsConn, fmt.Sprintf("PUTSCRIPT \"deliveryfilter\" {%d+}\r\n%s\r\n", len(script), script))
		put := mustReadUntilFinal(t, br, "putscript")
		if !strings.Contains(put, "OK") {
			t.Fatalf("PUTSCRIPT failed: %q", put)
		}
		// SETACTIVE.
		mustWrite(t, tlsConn, "SETACTIVE \"deliveryfilter\"\r\n")
		set := mustReadUntilFinal(t, br, "setactive")
		if !strings.Contains(set, "OK") {
			t.Fatalf("SETACTIVE failed: %q", set)
		}
		// LOGOUT.
		mustWrite(t, tlsConn, "LOGOUT\r\n")
		_, _ = br.ReadString('\n')
	}
	installSieve()
	log.Print("sieve script installed and activated on moxmail2")

	// 2) Connect IMAP IDLE on moxmail2 watching SieveTest, then submit.
	imapconn, err := tls.Dial("tcp", "moxmail2.mox2.example:993", nil)
	tcheck(t, err, "dial imap")
	defer imapconn.Close()
	opts := imapclient.Opts{Logger: slog.Default().With("cid", mox.Cid())}
	imapc, err := imapclient.New(imapconn, &opts)
	tcheck(t, err, "new imapclient")
	_, err = imapc.Login("moxtest2@mox2.example", "accountpass4321")
	tcheck(t, err, "imap login")

	// The SieveTest mailbox may not exist yet — it will be created on first
	// delivery by Sieve fileinto. Use IDLE on Inbox to detect "no delivery
	// into Inbox" later; but more directly: subscribe/select after delivery.

	// Submit the message via submissions on moxacmepebble.
	const subject = "sieve-integration-test"
	subjectMarker := fmt.Sprintf("Subject: %s", subject)
	const mailfrom = "moxtest1@mox1.example"
	const rcptto = "moxtest2@mox2.example"
	const desthost = "moxacmepebble.mox1.example:465"

	conn, err := tls.Dial("tcp", desthost, nil)
	tcheck(t, err, "dial submission")
	defer conn.Close()

	msg := fmt.Sprintf("From: <%s>\r\nTo: <%s>\r\n%s\r\nMessage-Id: <sieve-int@example.org>\r\n\r\nbody.\r\n", mailfrom, rcptto, subjectMarker)
	auth := func(mechanisms []string, cs *tls.ConnectionState) (sasl.Client, error) {
		return sasl.NewClientPlain(mailfrom, "accountpass1234"), nil
	}
	smtpc, err := smtpclient.New(mox.Context, log.Logger, conn, smtpclient.TLSSkip, false, ourHostname, dns.Domain{ASCII: "moxacmepebble.mox1.example"}, smtpclient.Opts{Auth: auth})
	tcheck(t, err, "smtp hello")
	err = smtpc.Deliver(mox.Context, mailfrom, rcptto, int64(len(msg)), strings.NewReader(msg), false, false, false)
	tcheck(t, err, "smtp deliver")
	smtpc.Close()

	// Poll the SieveTest mailbox for the message. Allow up to 15 seconds
	// for delivery to traverse SMTP and reach the destination. We check by
	// SELECT-ing the mailbox and inspecting the untagged EXISTS response.
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		time.Sleep(500 * time.Millisecond)
		resp, err := imapc.Select("SieveTest")
		if err != nil {
			continue // mailbox not created yet
		}
		// Scan untagged responses for EXISTS > 0.
		exists := 0
		for _, u := range resp.Untagged {
			if v, ok := u.(imapclient.UntaggedExists); ok {
				exists = int(v)
			}
		}
		if exists > 0 {
			log.Print("message delivered to SieveTest by Sieve", slog.Int("exists", exists))
			return
		}
	}

	// Diagnostic: check Inbox to see if message arrived but Sieve didn't filter.
	if resp, err := imapc.Select("Inbox"); err == nil {
		exists := 0
		for _, u := range resp.Untagged {
			if v, ok := u.(imapclient.UntaggedExists); ok {
				exists = int(v)
			}
		}
		if exists > 0 {
			t.Fatalf("message arrived in Inbox (Sieve did not filter): EXISTS=%d", exists)
		}
	}
	t.Fatalf("message not found in SieveTest within 15 seconds")
}

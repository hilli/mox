package managesieveserver

import (
	"bufio"
	"bytes"
	"context"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/mjl-/mox/mlog"
	mox "github.com/mjl-/mox/mox-"
	"github.com/mjl-/mox/store"
)

var ctxbg = context.Background()

func setupServer(t *testing.T) (*store.Account, func()) {
	t.Helper()
	log := mlog.New("managesieveserver", nil)
	os.RemoveAll("../testdata/managesieveserver/data")
	mox.ConfigStaticPath = filepath.FromSlash("../testdata/managesieveserver/mox.conf")
	mox.MustLoadConfig(true, false)
	if err := store.Init(ctxbg); err != nil {
		t.Fatalf("store init: %v", err)
	}
	acc, err := store.OpenAccount(log, "mjl", false)
	if err != nil {
		store.Close()
		t.Fatalf("open account: %v", err)
	}
	if err := acc.SetPassword(log, "testtest1234"); err != nil {
		acc.Close()
		store.Close()
		t.Fatalf("set password: %v", err)
	}
	cleanup := func() {
		acc.Close()
		acc.WaitClosed()
		store.Close()
	}
	return acc, cleanup
}

// connect spins up the managesieve serve goroutine on a net.Pipe and returns a
// buffered reader/writer for the client side.
func connect(t *testing.T, acc *store.Account) (*bufio.Reader, io.WriteCloser, func()) {
	t.Helper()
	serverConn, clientConn := net.Pipe()
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		serveConn("test", mox.Cid(), nil, serverConn, false, true /* NoRequireSTARTTLS */)
	}()
	cleanup := func() {
		clientConn.Close()
		wg.Wait()
	}
	return bufio.NewReader(clientConn), clientConn, cleanup
}

func readLineT(t *testing.T, br *bufio.Reader) string {
	t.Helper()
	line, err := br.ReadString('\n')
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	return strings.TrimRight(line, "\r\n")
}

func readUntilFinal(t *testing.T, br *bufio.Reader) []string {
	t.Helper()
	var lines []string
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		l := readLineT(t, br)
		lines = append(lines, l)
		if strings.HasPrefix(l, "OK") || strings.HasPrefix(l, "NO") || strings.HasPrefix(l, "BYE") {
			return lines
		}
	}
	t.Fatalf("no final response, got: %v", lines)
	return nil
}

func write(t *testing.T, w io.Writer, s string) {
	t.Helper()
	if _, err := w.Write([]byte(s)); err != nil {
		t.Fatalf("write: %v", err)
	}
}

func TestGreetingAndCapabilityAndLogout(t *testing.T) {
	acc, cleanup := setupServer(t)
	defer cleanup()
	_ = acc

	br, w, done := connect(t, acc)
	defer done()

	greeting := readUntilFinal(t, br)
	// Greeting should include IMPLEMENTATION, VERSION, SIEVE, SASL and end with OK.
	joined := strings.Join(greeting, "\n")
	if !strings.Contains(joined, "IMPLEMENTATION") {
		t.Fatalf("missing IMPLEMENTATION: %v", greeting)
	}
	if !strings.Contains(joined, "VERSION") {
		t.Fatalf("missing VERSION: %v", greeting)
	}
	if !strings.Contains(joined, "SIEVE") {
		t.Fatalf("missing SIEVE: %v", greeting)
	}
	if !strings.Contains(joined, "SASL") {
		t.Fatalf("missing SASL: %v", greeting)
	}
	if !strings.HasPrefix(greeting[len(greeting)-1], "OK") {
		t.Fatalf("greeting did not end with OK: %v", greeting)
	}

	// CAPABILITY again.
	write(t, w, "CAPABILITY\r\n")
	cap := readUntilFinal(t, br)
	if !strings.HasPrefix(cap[len(cap)-1], "OK") {
		t.Fatalf("CAPABILITY did not end with OK: %v", cap)
	}

	// LOGOUT.
	write(t, w, "LOGOUT\r\n")
	logout := readLineT(t, br)
	if !strings.HasPrefix(logout, "OK") {
		t.Fatalf("expected OK on logout, got %q", logout)
	}
}

func TestUnauthenticated(t *testing.T) {
	acc, cleanup := setupServer(t)
	defer cleanup()
	_ = acc

	br, w, done := connect(t, acc)
	defer done()
	readUntilFinal(t, br)

	// LISTSCRIPTS without auth -> NO.
	write(t, w, "LISTSCRIPTS\r\n")
	l := readLineT(t, br)
	if !strings.HasPrefix(l, "NO") {
		t.Fatalf("expected NO, got %q", l)
	}
}

func TestAuthPlainAndPutscriptAndListAndGet(t *testing.T) {
	acc, cleanup := setupServer(t)
	defer cleanup()
	_ = acc

	br, w, done := connect(t, acc)
	defer done()
	readUntilFinal(t, br)

	// AUTHENTICATE PLAIN with initial response.
	creds := []byte("\x00mjl@mox.example\x00testtest1234")
	// SASL PLAIN: authzid NUL authcid NUL password
	enc := base64Encode(creds)
	write(t, w, `AUTHENTICATE "PLAIN" "`+enc+`"`+"\r\n")
	resp := readUntilFinal(t, br)
	if !strings.HasPrefix(resp[len(resp)-1], "OK") {
		t.Fatalf("auth failed: %v", resp)
	}

	// PUTSCRIPT with literal content.
	script := "keep;\r\n"
	write(t, w, `PUTSCRIPT "myscript" {`+itoa(len(script))+"+}\r\n"+script+"\r\n")
	resp = readUntilFinal(t, br)
	if !strings.HasPrefix(resp[len(resp)-1], "OK") {
		t.Fatalf("PUTSCRIPT failed: %v", resp)
	}

	// LISTSCRIPTS.
	write(t, w, "LISTSCRIPTS\r\n")
	resp = readUntilFinal(t, br)
	joined := strings.Join(resp, "\n")
	if !strings.Contains(joined, "myscript") {
		t.Fatalf("expected myscript in list: %v", resp)
	}

	// SETACTIVE.
	write(t, w, `SETACTIVE "myscript"`+"\r\n")
	resp = readUntilFinal(t, br)
	if !strings.HasPrefix(resp[len(resp)-1], "OK") {
		t.Fatalf("SETACTIVE failed: %v", resp)
	}

	// LISTSCRIPTS should now mark active.
	write(t, w, "LISTSCRIPTS\r\n")
	resp = readUntilFinal(t, br)
	joined = strings.Join(resp, "\n")
	if !strings.Contains(joined, "ACTIVE") {
		t.Fatalf("expected ACTIVE marker: %v", resp)
	}

	// GETSCRIPT.
	write(t, w, `GETSCRIPT "myscript"`+"\r\n")
	// Response: literal size line, content, OK.
	sizeLine := readLineT(t, br)
	if !strings.HasPrefix(sizeLine, "{") {
		t.Fatalf("expected literal size, got %q", sizeLine)
	}
	// Read script content. Just consume an arbitrary amount; the server writes
	// exactly len(script) bytes followed by \r\n then OK.
	buf := make([]byte, len(script))
	if _, err := io.ReadFull(br, buf); err != nil {
		t.Fatalf("read script content: %v", err)
	}
	if !bytes.Equal(buf, []byte(script)) {
		t.Fatalf("script content mismatch: %q vs %q", buf, script)
	}
	// Consume trailing CRLF after literal content.
	readLineT(t, br)
	// Then OK line.
	ok := readLineT(t, br)
	if !strings.HasPrefix(ok, "OK") {
		t.Fatalf("expected OK after GETSCRIPT, got %q", ok)
	}

	// DELETESCRIPT - active script.
	write(t, w, `DELETESCRIPT "myscript"`+"\r\n")
	resp = readUntilFinal(t, br)
	if !strings.HasPrefix(resp[len(resp)-1], "NO") {
		t.Fatalf("expected NO on delete of active script: %v", resp)
	}

	// Deactivate then delete.
	write(t, w, `SETACTIVE ""`+"\r\n")
	resp = readUntilFinal(t, br)
	if !strings.HasPrefix(resp[len(resp)-1], "OK") {
		t.Fatalf("SETACTIVE empty failed: %v", resp)
	}
	write(t, w, `DELETESCRIPT "myscript"`+"\r\n")
	resp = readUntilFinal(t, br)
	if !strings.HasPrefix(resp[len(resp)-1], "OK") {
		t.Fatalf("DELETESCRIPT failed: %v", resp)
	}
}

func TestCheckscript(t *testing.T) {
	acc, cleanup := setupServer(t)
	defer cleanup()
	_ = acc

	br, w, done := connect(t, acc)
	defer done()
	readUntilFinal(t, br)

	creds := []byte("\x00mjl@mox.example\x00testtest1234")
	write(t, w, `AUTHENTICATE "PLAIN" "`+base64Encode(creds)+`"`+"\r\n")
	readUntilFinal(t, br)

	content := "keep;\r\n"
	write(t, w, `CHECKSCRIPT {`+itoa(len(content))+"+}\r\n"+content+"\r\n")
	resp := readUntilFinal(t, br)
	if !strings.HasPrefix(resp[len(resp)-1], "OK") {
		t.Fatalf("CHECKSCRIPT failed: %v", resp)
	}
}

func TestPutscriptValidation(t *testing.T) {
	acc, cleanup := setupServer(t)
	defer cleanup()
	_ = acc

	br, w, done := connect(t, acc)
	defer done()
	readUntilFinal(t, br)

	creds := []byte("\x00mjl@mox.example\x00testtest1234")
	write(t, w, `AUTHENTICATE "PLAIN" "`+base64Encode(creds)+`"`+"\r\n")
	readUntilFinal(t, br)

	// Bad script - should be rejected.
	bad := "this is not sieve\r\n"
	write(t, w, `PUTSCRIPT "badscript" {`+itoa(len(bad))+"+}\r\n"+bad+"\r\n")
	resp := readUntilFinal(t, br)
	if !strings.HasPrefix(resp[len(resp)-1], "NO") {
		t.Fatalf("expected NO for invalid script, got %v", resp)
	}

	// Verify it wasn't stored.
	write(t, w, "LISTSCRIPTS\r\n")
	resp = readUntilFinal(t, br)
	joined := strings.Join(resp, "\n")
	if strings.Contains(joined, "badscript") {
		t.Fatalf("bad script should not be stored: %v", resp)
	}
}

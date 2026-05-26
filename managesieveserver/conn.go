package managesieveserver

import (
	"bufio"
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"fmt"
	"hash"
	"io"
	"log/slog"
	"net"
	"runtime/debug"
	"strings"
	"time"

	"github.com/mjl-/bstore"

	"github.com/mjl-/mox/dns"
	"github.com/mjl-/mox/metrics"
	"github.com/mjl-/mox/mlog"
	mox "github.com/mjl-/mox/mox-"
	"github.com/mjl-/mox/moxio"
	"github.com/mjl-/mox/moxvar"
	"github.com/mjl-/mox/scram"
	"github.com/mjl-/mox/sievefilter"
	"github.com/mjl-/mox/store"
)

// state of a ManageSieve connection per RFC 5804 §2.
type state int

const (
	stateNotAuth state = iota
	stateAuth
)

type conn struct {
	cid               int64
	conn              net.Conn
	listenerName      string
	br                *bufio.Reader
	bw                *bufio.Writer
	tr                *moxio.TraceReader
	tw                *moxio.TraceWriter
	log               mlog.Log
	baseTLSConfig     *tls.Config
	tls               bool
	noTLSClientAuth   bool
	noRequireSTARTTLS bool

	state    state
	account  *store.Account
	username string

	// For LoginAttempt tracking similar to imapserver.
	authFailed int
}

// serveConn is the entry point per accepted connection.
func serveConn(listenerName string, cid int64, baseTLSConfig *tls.Config, nc net.Conn, noTLSClientAuth, noRequireSTARTTLS bool) {
	log := mlog.New("managesieveserver", nil).WithCid(cid)
	c := &conn{
		cid:               cid,
		conn:              nc,
		listenerName:      listenerName,
		log:               log,
		baseTLSConfig:     baseTLSConfig,
		noTLSClientAuth:   noTLSClientAuth,
		noRequireSTARTTLS: noRequireSTARTTLS,
	}
	c.tr = moxio.NewTraceReader(log, "C: ", nc)
	c.tw = moxio.NewTraceWriter(log, "S: ", nc)
	c.br = bufio.NewReader(c.tr)
	c.bw = bufio.NewWriter(c.tw)

	mox.Connections.Register(nc, "managesieve", listenerName)
	defer mox.Connections.Unregister(nc)

	defer func() {
		if r := recover(); r != nil {
			c.log.Error("panic in managesieve connection", slog.Any("err", r), slog.String("stack", string(debug.Stack())))
			metrics.PanicInc(metrics.Managesieveserver)
		}
		if c.account != nil {
			err := c.account.Close()
			c.log.Check(err, "closing account")
			c.account = nil
		}
		err := nc.Close()
		c.log.Check(err, "closing connection")
	}()

	select {
	case <-mox.Shutdown.Done():
		c.writeLine("BYE \"server is shutting down\"")
		c.bw.Flush()
		return
	default:
	}

	c.writeGreeting()
	if err := c.bw.Flush(); err != nil {
		c.log.Infox("write greeting", err)
		return
	}

	c.runLoop()
}

// writeLine writes a single line followed by CRLF.
func (c *conn) writeLine(s string) {
	c.bw.WriteString(s)
	c.bw.WriteString("\r\n")
}

// writeOKContinuation is the synchronizing-literal continuation. ManageSieve
// uses a simple "OK" response per RFC 5804. We write a minimal OK that doesn't
// look like a final command response - actually per the RFC there is no
// dedicated continuation token. We follow Pigeonhole's convention of writing
// nothing and letting the client send data after seeing readiness.
// Simpler: we don't support sync literals on the data path; we use non-sync
// {N+} from the client. For protocol compliance we write "OK \"go ahead\"\r\n"
// which most clients ignore. But correctness-wise, this is fine because the
// client only proceeds once we've flushed.
func (c *conn) writeOKContinuation() error {
	c.writeLine("OK")
	return c.bw.Flush()
}

func (c *conn) writeGreeting() {
	c.writeCapabilities()
	c.writeLine(`OK "ManageSieve ready."`)
}

// writeCapabilities writes the current capability list per RFC 5804 §1.7.
// Each capability is `"NAME"` or `"NAME" "value"`, one per line.
func (c *conn) writeCapabilities() {
	c.writeLine(fmt.Sprintf(`"IMPLEMENTATION" "mox %s"`, moxvar.Version))
	c.writeLine(`"VERSION" "1.0"`)
	c.writeLine(fmt.Sprintf(`"SIEVE" "%s"`, SieveExtensions))
	if !c.tls && c.baseTLSConfig != nil {
		c.writeLine(`"STARTTLS"`)
	}
	saslMechs := c.saslMechanisms()
	c.writeLine(fmt.Sprintf(`"SASL" "%s"`, saslMechs))
	if c.state == stateAuth && c.username != "" {
		c.writeLine(fmt.Sprintf(`"OWNER" "%s"`, escapeQuoted(c.username)))
	}
	c.writeLine(`"MAXREDIRECTS" "4"`)
}

func (c *conn) saslMechanisms() string {
	var l []string
	// We always advertise SCRAM PLUS variants (per imapserver convention),
	// even on plain connections, to detect downgrade.
	l = append(l, "SCRAM-SHA-256-PLUS", "SCRAM-SHA-256", "SCRAM-SHA-1-PLUS", "SCRAM-SHA-1", "CRAM-MD5")
	if c.tls || c.noRequireSTARTTLS {
		l = append(l, "PLAIN")
	}
	if c.tls && !c.noTLSClientAuth {
		l = append(l, "EXTERNAL")
	}
	return strings.Join(l, " ")
}

func escapeQuoted(s string) string {
	s = strings.ReplaceAll(s, `\`, `\\`)
	s = strings.ReplaceAll(s, `"`, `\"`)
	return s
}

// runLoop reads commands until logout, EOF, or fatal error.
func (c *conn) runLoop() {
	for {
		select {
		case <-mox.Shutdown.Done():
			c.writeLine(`BYE "server is shutting down"`)
			c.bw.Flush()
			return
		default:
		}
		// Per RFC 5804 §1.2: after auth, idle timeout >= 30 min. Before auth
		// can be shorter.
		var idleTimeout time.Duration
		if c.state == stateAuth {
			idleTimeout = 30 * time.Minute
		} else {
			idleTimeout = 30 * time.Second
		}
		if err := c.conn.SetReadDeadline(time.Now().Add(idleTimeout)); err != nil {
			c.log.Infox("set read deadline", err)
			return
		}
		line, err := readLine(c.br)
		if err != nil {
			if !errors.Is(err, io.EOF) && !errors.Is(err, net.ErrClosed) {
				c.log.Debugx("read command", err)
			}
			return
		}
		if line == "" {
			continue
		}
		start := time.Now()
		t := newTokenReader(c.br, line, c.writeOKContinuation)
		cmd, err := t.atom()
		if err != nil {
			c.writeLine(fmt.Sprintf(`NO "%s"`, escapeQuoted(err.Error())))
			if err := c.bw.Flush(); err != nil {
				return
			}
			metricCommands.WithLabelValues("unknown", "bad").Observe(time.Since(start).Seconds())
			continue
		}
		result := "ok"
		switch cmd {
		case "AUTHENTICATE":
			c.cmdAuthenticate(t)
		case "STARTTLS":
			c.cmdStarttls(t)
		case "LOGOUT":
			c.cmdLogout(t)
			return
		case "CAPABILITY":
			c.cmdCapability(t)
		case "NOOP":
			c.cmdNoop(t)
		case "HAVESPACE":
			c.cmdHavespace(t)
		case "PUTSCRIPT":
			c.cmdPutscript(t)
		case "LISTSCRIPTS":
			c.cmdListscripts(t)
		case "SETACTIVE":
			c.cmdSetactive(t)
		case "GETSCRIPT":
			c.cmdGetscript(t)
		case "DELETESCRIPT":
			c.cmdDeletescript(t)
		case "RENAMESCRIPT":
			c.cmdRenamescript(t)
		case "CHECKSCRIPT":
			c.cmdCheckscript(t)
		default:
			c.writeLine(fmt.Sprintf(`NO "unknown command %q"`, cmd))
			result = "bad"
		}
		if err := c.bw.Flush(); err != nil {
			c.log.Debugx("flush", err)
			return
		}
		metricCommands.WithLabelValues(strings.ToLower(cmd), result).Observe(time.Since(start).Seconds())
	}
}

// requireAuth writes a NO and returns false when not authenticated.
func (c *conn) requireAuth() bool {
	if c.state != stateAuth {
		c.writeLine(`NO "Not authenticated"`)
		return false
	}
	return true
}

// requireNoAuth returns false when already authenticated.
func (c *conn) requireNoAuth() bool {
	if c.state == stateAuth {
		c.writeLine(`NO "Already authenticated"`)
		return false
	}
	return true
}

// cmdCapability re-issues the capability list followed by OK.
func (c *conn) cmdCapability(t *tokenReader) {
	c.writeCapabilities()
	c.writeLine(`OK`)
}

// cmdNoop replies OK, optionally echoing a TAG response code.
func (c *conn) cmdNoop(t *tokenReader) {
	var tag string
	if !t.eol() {
		s, err := t.str()
		if err != nil {
			c.writeLine(fmt.Sprintf(`NO "%s"`, escapeQuoted(err.Error())))
			return
		}
		tag = s
	}
	if tag != "" {
		c.writeLine(fmt.Sprintf(`OK (TAG "%s") "NOOP"`, escapeQuoted(tag)))
	} else {
		c.writeLine(`OK "NOOP"`)
	}
}

// cmdLogout replies OK and the caller closes the connection.
func (c *conn) cmdLogout(t *tokenReader) {
	c.writeLine(`OK "Bye."`)
	c.bw.Flush()
}

// cmdStarttls upgrades to TLS, then reissues capabilities.
func (c *conn) cmdStarttls(t *tokenReader) {
	if c.tls {
		c.writeLine(`NO "TLS already active"`)
		return
	}
	if c.baseTLSConfig == nil {
		c.writeLine(`NO "TLS not configured"`)
		return
	}
	if c.state == stateAuth {
		c.writeLine(`NO "STARTTLS not allowed after authentication"`)
		return
	}
	c.writeLine(`OK "Begin TLS negotiation"`)
	if err := c.bw.Flush(); err != nil {
		c.log.Debugx("flush before tls", err)
		return
	}
	tlsConn := tls.Server(c.conn, c.baseTLSConfig)
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	if err := tlsConn.HandshakeContext(ctx); err != nil {
		c.log.Debugx("tls handshake", err)
		return
	}
	c.conn = tlsConn
	c.tls = true
	c.tr = moxio.NewTraceReader(c.log, "C: ", tlsConn)
	c.tw = moxio.NewTraceWriter(c.log, "S: ", tlsConn)
	c.br = bufio.NewReader(c.tr)
	c.bw = bufio.NewWriter(c.tw)
	// Reissue capabilities (RFC 5804 §2.2).
	c.writeCapabilities()
	c.writeLine(`OK "TLS negotiated"`)
}

// cmdAuthenticate handles SASL authentication.
func (c *conn) cmdAuthenticate(t *tokenReader) {
	if !c.requireNoAuth() {
		return
	}
	mech, err := t.str()
	if err != nil {
		c.writeLine(fmt.Sprintf(`NO "%s"`, escapeQuoted(err.Error())))
		return
	}
	mech = strings.ToUpper(mech)
	// Optional initial response.
	var initialResponse string
	hadIR := false
	if !t.eol() {
		s, err := t.str()
		if err != nil {
			c.writeLine(fmt.Sprintf(`NO "%s"`, escapeQuoted(err.Error())))
			return
		}
		initialResponse = s
		hadIR = true
	}
	defer func() {
		if c.authFailed >= 3 {
			// Slow down further attempts.
			time.Sleep(time.Duration(c.authFailed-2) * 250 * time.Millisecond)
		}
	}()

	switch mech {
	case "PLAIN":
		c.authPlain(initialResponse, hadIR)
	case "CRAM-MD5":
		c.authCRAMMD5()
	case "SCRAM-SHA-1", "SCRAM-SHA-1-PLUS", "SCRAM-SHA-256", "SCRAM-SHA-256-PLUS":
		c.authSCRAM(mech, initialResponse, hadIR)
	case "EXTERNAL":
		c.authExternal(initialResponse, hadIR)
	default:
		c.writeLine(fmt.Sprintf(`NO "Unsupported SASL mechanism %q"`, mech))
	}
}

// readSASLLine reads one SASL data line from client: a quoted string, literal,
// or "*" (abort).
func (c *conn) readSASLLine() (string, bool, error) {
	line, err := readLine(c.br)
	if err != nil {
		return "", false, err
	}
	if line == "*" || line == `"*"` {
		return "", true, nil
	}
	t := newTokenReader(c.br, line, c.writeOKContinuation)
	s, err := t.str()
	if err != nil {
		return "", false, err
	}
	return s, false, nil
}

func (c *conn) writeSASLChallenge(data []byte) {
	enc := base64.StdEncoding.EncodeToString(data)
	c.writeLine(fmt.Sprintf(`{%d+}`, len(enc)))
	c.bw.WriteString(enc)
	c.writeLine("")
}

func (c *conn) authPlain(initial string, hadIR bool) {
	if !c.tls && !c.noRequireSTARTTLS {
		c.writeLine(`NO (ENCRYPT-NEEDED) "TLS required for plaintext authentication"`)
		c.authFailed++
		return
	}
	var resp []byte
	if hadIR {
		b, err := base64.StdEncoding.DecodeString(initial)
		if err != nil {
			c.writeLine(`NO "bad base64 in initial response"`)
			c.authFailed++
			return
		}
		resp = b
	} else {
		// Server challenges with empty challenge.
		c.writeSASLChallenge(nil)
		if err := c.bw.Flush(); err != nil {
			return
		}
		s, abort, err := c.readSASLLine()
		if err != nil || abort {
			if abort {
				c.writeLine(`NO "Authentication aborted"`)
			} else {
				c.writeLine(`NO "bad response"`)
			}
			c.authFailed++
			return
		}
		b, err := base64.StdEncoding.DecodeString(s)
		if err != nil {
			c.writeLine(`NO "bad base64"`)
			c.authFailed++
			return
		}
		resp = b
	}
	parts := bytes.Split(resp, []byte{0})
	if len(parts) != 3 {
		c.writeLine(`NO "bad PLAIN response"`)
		c.authFailed++
		return
	}
	authzid := string(parts[0])
	authcid := string(parts[1])
	password := string(parts[2])
	if authzid != "" && authzid != authcid {
		c.writeLine(`NO "cannot assume role"`)
		c.authFailed++
		return
	}
	acc, accName, err := store.OpenEmailAuth(c.log, authcid, password, true)
	if err != nil {
		if errors.Is(err, store.ErrUnknownCredentials) {
			c.writeLine(`NO "Authentication failed"`)
		} else if errors.Is(err, store.ErrLoginDisabled) {
			c.writeLine(fmt.Sprintf(`NO "%s"`, escapeQuoted(err.Error())))
		} else {
			c.log.Infox("plain auth", err)
			c.writeLine(`NO "Authentication failed"`)
		}
		c.authFailed++
		return
	}
	c.account = acc
	c.username = accName
	c.state = stateAuth
	c.writeCapabilities()
	c.writeLine(fmt.Sprintf(`OK "Authenticated as %s"`, escapeQuoted(accName)))
}

func (c *conn) authCRAMMD5() {
	chal := fmt.Sprintf("<%d.%d@%s>", uint64(mox.CryptoRandInt()), time.Now().UnixNano(), mox.Conf.Static.HostnameDomain.ASCII)
	c.writeSASLChallenge([]byte(chal))
	if err := c.bw.Flush(); err != nil {
		return
	}
	s, abort, err := c.readSASLLine()
	if err != nil || abort {
		c.writeLine(`NO "Authentication aborted"`)
		c.authFailed++
		return
	}
	respBytes, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		c.writeLine(`NO "bad base64"`)
		c.authFailed++
		return
	}
	parts := strings.SplitN(string(respBytes), " ", 2)
	if len(parts) != 2 || len(parts[1]) != 2*md5.Size {
		c.writeLine(`NO "bad CRAM-MD5 response"`)
		c.authFailed++
		return
	}
	username := parts[0]
	clientDigest := parts[1]
	acc, accName, _, err := store.OpenEmail(c.log, username, true)
	if err != nil {
		c.writeLine(`NO "Authentication failed"`)
		c.authFailed++
		return
	}
	var ipad, opad hash.Hash
	acc.WithRLock(func() {
		err := acc.DB.Read(context.TODO(), func(tx *bstore.Tx) error {
			p, err := bstore.QueryTx[store.Password](tx).Get()
			if err != nil {
				return err
			}
			ipad = p.CRAMMD5.Ipad
			opad = p.CRAMMD5.Opad
			return nil
		})
		if err != nil {
			c.log.Errorx("cram-md5 lookup", err)
		}
	})
	if ipad == nil || opad == nil {
		c.writeLine(`NO "Authentication failed"`)
		acc.Close()
		c.authFailed++
		return
	}
	ipad.Write([]byte(chal))
	opad.Write(ipad.Sum(nil))
	expected := fmt.Sprintf("%x", opad.Sum(nil))
	if !hmacEq(clientDigest, expected) {
		c.writeLine(`NO "Authentication failed"`)
		acc.Close()
		c.authFailed++
		return
	}
	c.account = acc
	c.username = accName
	c.state = stateAuth
	c.writeCapabilities()
	c.writeLine(fmt.Sprintf(`OK "Authenticated as %s"`, escapeQuoted(accName)))
}

func hmacEq(a, b string) bool {
	return hmac.Equal([]byte(a), []byte(b))
}

func (c *conn) authSCRAM(mech, initial string, hadIR bool) {
	var newHash func() hash.Hash
	switch mech {
	case "SCRAM-SHA-1", "SCRAM-SHA-1-PLUS":
		newHash = sha1.New
	case "SCRAM-SHA-256", "SCRAM-SHA-256-PLUS":
		newHash = sha256.New
	default:
		c.writeLine(`NO "unsupported SCRAM variant"`)
		return
	}
	requireChannelBinding := strings.HasSuffix(mech, "-PLUS")
	if requireChannelBinding && !c.tls {
		c.writeLine(`NO "channel binding requires TLS"`)
		c.authFailed++
		return
	}
	var cs *tls.ConnectionState
	if c.tls {
		st := c.conn.(*tls.Conn).ConnectionState()
		cs = &st
	}
	var c0 []byte
	if hadIR {
		b, err := base64.StdEncoding.DecodeString(initial)
		if err != nil {
			c.writeLine(`NO "bad initial response"`)
			c.authFailed++
			return
		}
		c0 = b
	} else {
		c.writeSASLChallenge(nil)
		if err := c.bw.Flush(); err != nil {
			return
		}
		s, abort, err := c.readSASLLine()
		if err != nil || abort {
			c.writeLine(`NO "Authentication aborted"`)
			c.authFailed++
			return
		}
		b, err := base64.StdEncoding.DecodeString(s)
		if err != nil {
			c.writeLine(`NO "bad base64"`)
			c.authFailed++
			return
		}
		c0 = b
	}
	ss, err := scram.NewServer(newHash, c0, cs, requireChannelBinding)
	if err != nil {
		c.writeLine(fmt.Sprintf(`NO "%s"`, escapeQuoted(err.Error())))
		c.authFailed++
		return
	}
	username := ss.Authentication
	acc, accName, _, err := store.OpenEmail(c.log, username, true)
	if err != nil {
		c.writeLine(`NO "Authentication failed"`)
		c.authFailed++
		return
	}
	defer func() {
		if c.account == nil {
			acc.Close()
		}
	}()
	var xscram store.SCRAM
	acc.WithRLock(func() {
		err := acc.DB.Read(context.TODO(), func(tx *bstore.Tx) error {
			p, err := bstore.QueryTx[store.Password](tx).Get()
			if err != nil {
				return err
			}
			switch mech {
			case "SCRAM-SHA-1", "SCRAM-SHA-1-PLUS":
				xscram = p.SCRAMSHA1
			default:
				xscram = p.SCRAMSHA256
			}
			return nil
		})
		if err != nil {
			c.log.Errorx("scram lookup", err)
		}
	})
	if len(xscram.Salt) == 0 || xscram.Iterations == 0 || len(xscram.SaltedPassword) == 0 {
		c.writeLine(`NO "Authentication failed"`)
		c.authFailed++
		return
	}
	s1, err := ss.ServerFirst(xscram.Iterations, xscram.Salt)
	if err != nil {
		c.writeLine(`NO "scram failure"`)
		c.authFailed++
		return
	}
	c.writeSASLChallenge([]byte(s1))
	if err := c.bw.Flush(); err != nil {
		return
	}
	clientFinal, abort, err := c.readSASLLine()
	if err != nil || abort {
		c.writeLine(`NO "Authentication aborted"`)
		c.authFailed++
		return
	}
	c2, err := base64.StdEncoding.DecodeString(clientFinal)
	if err != nil {
		c.writeLine(`NO "bad base64"`)
		c.authFailed++
		return
	}
	s3, err := ss.Finish(c2, xscram.SaltedPassword)
	if err != nil {
		c.writeLine(`NO "Authentication failed"`)
		c.authFailed++
		return
	}
	c.account = acc
	c.username = accName
	c.state = stateAuth
	// Include the server final via SASL response code.
	c.writeCapabilities()
	if len(s3) > 0 {
		c.writeLine(fmt.Sprintf(`OK (SASL "%s") "Authenticated as %s"`, base64.StdEncoding.EncodeToString([]byte(s3)), escapeQuoted(accName)))
	} else {
		c.writeLine(fmt.Sprintf(`OK "Authenticated as %s"`, escapeQuoted(accName)))
	}
}

func (c *conn) authExternal(initial string, hadIR bool) {
	if !c.tls {
		c.writeLine(`NO "EXTERNAL requires TLS"`)
		c.authFailed++
		return
	}
	state := c.conn.(*tls.Conn).ConnectionState()
	if len(state.PeerCertificates) == 0 {
		c.writeLine(`NO "no client certificate"`)
		c.authFailed++
		return
	}
	// We don't currently support EXTERNAL identity resolution from client cert
	// without further integration. Reject for now.
	c.writeLine(`NO "EXTERNAL not implemented"`)
	c.authFailed++
}

// cmdHavespace: HAVESPACE <name> <number>
func (c *conn) cmdHavespace(t *tokenReader) {
	if !c.requireAuth() {
		return
	}
	name, err := t.str()
	if err != nil {
		c.writeLine(fmt.Sprintf(`NO "%s"`, escapeQuoted(err.Error())))
		return
	}
	if err := store.CheckSieveScriptName(name); err != nil {
		c.writeLine(fmt.Sprintf(`NO "%s"`, escapeQuoted(err.Error())))
		return
	}
	size, err := t.number()
	if err != nil {
		c.writeLine(fmt.Sprintf(`NO "%s"`, escapeQuoted(err.Error())))
		return
	}
	p := c.policy()
	if err := c.account.SieveCheckQuota(name, size, p.MaxScripts, p.MaxScriptSize, p.MaxTotalScriptSize); err != nil {
		c.writeQuotaError(err)
		return
	}
	c.writeLine(`OK`)
}

// cmdPutscript: PUTSCRIPT <name> <content>
func (c *conn) cmdPutscript(t *tokenReader) {
	if !c.requireAuth() {
		return
	}
	name, err := t.str()
	if err != nil {
		c.writeLine(fmt.Sprintf(`NO "%s"`, escapeQuoted(err.Error())))
		return
	}
	if err := store.CheckSieveScriptName(name); err != nil {
		c.writeLine(fmt.Sprintf(`NO "%s"`, escapeQuoted(err.Error())))
		return
	}
	// Reject oversize scripts before reading them into memory. The literal
	// parser's maxLiteralOverride caps the read so a misbehaving client
	// can't allocate megabytes for a sub-KB policy. The override is reset
	// after the read so any subsequent str() (none in this command, but
	// future-proof) starts from the default cap.
	p := c.policy()
	if p.MaxScriptSize > 0 {
		t.maxLiteralOverride = p.MaxScriptSize
		defer func() { t.maxLiteralOverride = 0 }()
	}
	content, err := t.str()
	if err != nil {
		c.writeLine(fmt.Sprintf(`NO (QUOTA/MAXSIZE) "%s"`, escapeQuoted(err.Error())))
		return
	}
	if len(content) == 0 {
		c.writeLine(`NO "empty script"`)
		return
	}
	if err := c.account.SieveCheckQuota(name, int64(len(content)), p.MaxScripts, p.MaxScriptSize, p.MaxTotalScriptSize); err != nil {
		c.writeQuotaError(err)
		return
	}
	var warnings string
	if v := getValidator(); v != nil {
		w, err := v([]byte(content))
		if err != nil {
			c.writeLine(fmt.Sprintf(`NO "%s"`, escapeQuoted(err.Error())))
			return
		}
		warnings = w
	}
	if err := c.account.SievePutScript(name, []byte(content)); err != nil {
		c.writeLine(fmt.Sprintf(`NO "%s"`, escapeQuoted(err.Error())))
		return
	}
	if warnings != "" {
		c.writeLine(fmt.Sprintf(`OK (WARNINGS) %s`, quoteOrLiteral(warnings)))
	} else {
		c.writeLine(`OK`)
	}
}

// cmdCheckscript: CHECKSCRIPT <content>
func (c *conn) cmdCheckscript(t *tokenReader) {
	if !c.requireAuth() {
		return
	}
	p := c.policy()
	if p.MaxScriptSize > 0 {
		t.maxLiteralOverride = p.MaxScriptSize
		defer func() { t.maxLiteralOverride = 0 }()
	}
	content, err := t.str()
	if err != nil {
		c.writeLine(fmt.Sprintf(`NO (QUOTA/MAXSIZE) "%s"`, escapeQuoted(err.Error())))
		return
	}
	var warnings string
	if v := getValidator(); v != nil {
		w, err := v([]byte(content))
		if err != nil {
			c.writeLine(fmt.Sprintf(`NO "%s"`, escapeQuoted(err.Error())))
			return
		}
		warnings = w
	}
	if warnings != "" {
		c.writeLine(fmt.Sprintf(`OK (WARNINGS) %s`, quoteOrLiteral(warnings)))
	} else {
		c.writeLine(`OK`)
	}
}

// cmdListscripts: LISTSCRIPTS
func (c *conn) cmdListscripts(t *tokenReader) {
	if !c.requireAuth() {
		return
	}
	scripts, active, err := c.account.SieveListScripts()
	if err != nil {
		c.writeLine(fmt.Sprintf(`NO "%s"`, escapeQuoted(err.Error())))
		return
	}
	for _, s := range scripts {
		if s.Name == active {
			c.writeLine(fmt.Sprintf(`%s ACTIVE`, quoteOrLiteral(s.Name)))
		} else {
			c.writeLine(quoteOrLiteral(s.Name))
		}
	}
	c.writeLine(`OK`)
}

// cmdGetscript: GETSCRIPT <name>
func (c *conn) cmdGetscript(t *tokenReader) {
	if !c.requireAuth() {
		return
	}
	name, err := t.str()
	if err != nil {
		c.writeLine(fmt.Sprintf(`NO "%s"`, escapeQuoted(err.Error())))
		return
	}
	content, err := c.account.SieveGetScript(name)
	if err != nil {
		if errors.Is(err, store.ErrSieveScriptNotFound) {
			c.writeLine(`NO (NONEXISTENT) "No such script"`)
		} else {
			c.writeLine(fmt.Sprintf(`NO "%s"`, escapeQuoted(err.Error())))
		}
		return
	}
	c.writeLine(fmt.Sprintf(`{%d}`, len(content)))
	c.bw.Write(content)
	c.writeLine("")
	c.writeLine(`OK`)
}

// cmdDeletescript: DELETESCRIPT <name>
func (c *conn) cmdDeletescript(t *tokenReader) {
	if !c.requireAuth() {
		return
	}
	name, err := t.str()
	if err != nil {
		c.writeLine(fmt.Sprintf(`NO "%s"`, escapeQuoted(err.Error())))
		return
	}
	if err := c.account.SieveDeleteScript(name); err != nil {
		switch {
		case errors.Is(err, store.ErrSieveScriptNotFound):
			c.writeLine(`NO (NONEXISTENT) "No such script"`)
		case errors.Is(err, store.ErrSieveScriptActive):
			c.writeLine(`NO (ACTIVE) "Cannot delete active script"`)
		default:
			c.writeLine(fmt.Sprintf(`NO "%s"`, escapeQuoted(err.Error())))
		}
		return
	}
	c.writeLine(`OK`)
}

// cmdRenamescript: RENAMESCRIPT <oldname> <newname>
func (c *conn) cmdRenamescript(t *tokenReader) {
	if !c.requireAuth() {
		return
	}
	oldName, err := t.str()
	if err != nil {
		c.writeLine(fmt.Sprintf(`NO "%s"`, escapeQuoted(err.Error())))
		return
	}
	newName, err := t.str()
	if err != nil {
		c.writeLine(fmt.Sprintf(`NO "%s"`, escapeQuoted(err.Error())))
		return
	}
	if err := c.account.SieveRenameScript(oldName, newName); err != nil {
		switch {
		case errors.Is(err, store.ErrSieveScriptNotFound):
			c.writeLine(`NO (NONEXISTENT) "No such script"`)
		case errors.Is(err, store.ErrSieveScriptExists):
			c.writeLine(`NO (ALREADYEXISTS) "Destination script already exists"`)
		default:
			c.writeLine(fmt.Sprintf(`NO "%s"`, escapeQuoted(err.Error())))
		}
		return
	}
	c.writeLine(`OK`)
}

// cmdSetactive: SETACTIVE <name>
func (c *conn) cmdSetactive(t *tokenReader) {
	if !c.requireAuth() {
		return
	}
	name, err := t.str()
	if err != nil {
		c.writeLine(fmt.Sprintf(`NO "%s"`, escapeQuoted(err.Error())))
		return
	}
	if err := c.account.SieveSetActive(name); err != nil {
		if errors.Is(err, store.ErrSieveScriptNotFound) {
			c.writeLine(`NO (NONEXISTENT) "No such script"`)
		} else {
			c.writeLine(fmt.Sprintf(`NO "%s"`, escapeQuoted(err.Error())))
		}
		return
	}
	c.writeLine(`OK`)
}

// writeQuotaError maps store sieve errors to ManageSieve QUOTA response codes.
func (c *conn) writeQuotaError(err error) {
	switch {
	case errors.Is(err, store.ErrSieveScriptTooLarge):
		c.writeLine(fmt.Sprintf(`NO (QUOTA/MAXSIZE) "%s"`, escapeQuoted(err.Error())))
	case errors.Is(err, store.ErrSieveTooManyScripts):
		c.writeLine(fmt.Sprintf(`NO (QUOTA/MAXSCRIPTS) "%s"`, escapeQuoted(err.Error())))
	case errors.Is(err, store.ErrSieveTotalTooLarge):
		c.writeLine(fmt.Sprintf(`NO (QUOTA) "%s"`, escapeQuoted(err.Error())))
	default:
		c.writeLine(fmt.Sprintf(`NO "%s"`, escapeQuoted(err.Error())))
	}
}

// policy returns the effective Sieve policy for the authenticated account.
func (c *conn) policy() sievefilter.Policy {
	var domain dns.Domain
	if accConf, ok := mox.Conf.Account(c.account.Name); ok {
		domain = accConf.DNSDomain
	}
	server, dom, acc := mox.Conf.SievePolicy(c.account.Name, domain)
	return sievefilter.Resolve(server, dom, acc)
}

// quoteOrLiteral returns a ManageSieve string representation for s. Uses a
// quoted string when safe, otherwise a literal.
func quoteOrLiteral(s string) string {
	if strings.ContainsAny(s, "\r\n\"\\") || strings.Contains(s, "\x00") {
		return fmt.Sprintf("{%d}\r\n%s", len(s), s)
	}
	return `"` + s + `"`
}

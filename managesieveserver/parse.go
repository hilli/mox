package managesieveserver

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
)

// errProtocol indicates a malformed ManageSieve command.
var errProtocol = errors.New("protocol error")

// maxLiteralSize is the maximum literal size accepted from a client. This is
// the absolute cap; per-script size limits are enforced in addition by
// PUTSCRIPT/CHECKSCRIPT.
const maxLiteralSize = 2 * 1024 * 1024

// tokenReader parses ManageSieve tokens (atoms, numbers, strings: quoted or
// literal) across multiple lines when literals span them.
type tokenReader struct {
	br   *bufio.Reader
	line string
	pos  int
	// writeOK is called when the parser encounters a synchronizing literal
	// {N}. It must send the OK continuation response so the client can send
	// the literal content. May be nil; if nil, synchronizing literals return
	// an error.
	writeOK func() error
	// maxLiteralOverride, when > 0, replaces the package-default
	// maxLiteralSize for the next call to str()/literal(). The caller is
	// responsible for resetting between calls if needed.
	maxLiteralOverride int64
}

func newTokenReader(br *bufio.Reader, initial string, writeOK func() error) *tokenReader {
	return &tokenReader{br: br, line: initial, pos: 0, writeOK: writeOK}
}

func (t *tokenReader) skipSP() {
	for t.pos < len(t.line) && (t.line[t.pos] == ' ' || t.line[t.pos] == '\t') {
		t.pos++
	}
}

func (t *tokenReader) eol() bool {
	t.skipSP()
	if t.pos >= len(t.line) {
		return true
	}
	// Allow trailing CR before LF stripping.
	if t.pos == len(t.line)-1 && t.line[t.pos] == '\r' {
		return true
	}
	return false
}

// nextLine reads a new line and replaces the buffered line, resetting pos.
func (t *tokenReader) nextLine() error {
	line, err := readLine(t.br)
	if err != nil {
		return err
	}
	t.line = line
	t.pos = 0
	return nil
}

// remainder returns the rest of the current line, stripped of trailing CR.
func (t *tokenReader) remainder() string {
	t.skipSP()
	s := t.line[t.pos:]
	s = strings.TrimRight(s, "\r")
	t.pos = len(t.line)
	return s
}

// atom returns the next whitespace-terminated atom, uppercased.
func (t *tokenReader) atom() (string, error) {
	t.skipSP()
	start := t.pos
	for t.pos < len(t.line) {
		c := t.line[t.pos]
		if c == ' ' || c == '\t' || c == '\r' || c == '\n' {
			break
		}
		t.pos++
	}
	if start == t.pos {
		return "", fmt.Errorf("%w: expected atom", errProtocol)
	}
	return strings.ToUpper(t.line[start:t.pos]), nil
}

// number returns the next number token.
func (t *tokenReader) number() (int64, error) {
	t.skipSP()
	start := t.pos
	for t.pos < len(t.line) && t.line[t.pos] >= '0' && t.line[t.pos] <= '9' {
		t.pos++
	}
	if start == t.pos {
		return 0, fmt.Errorf("%w: expected number", errProtocol)
	}
	return strconv.ParseInt(t.line[start:t.pos], 10, 64)
}

// str returns the next string token: quoted or literal. Literal content can
// span lines; on return t.line/t.pos point to the rest of the original command
// (the part following the literal).
func (t *tokenReader) str() (string, error) {
	t.skipSP()
	if t.pos >= len(t.line) {
		return "", fmt.Errorf("%w: expected string", errProtocol)
	}
	switch t.line[t.pos] {
	case '"':
		return t.quoted()
	case '{':
		return t.literal()
	}
	return "", fmt.Errorf("%w: expected string at %q", errProtocol, t.line[t.pos:])
}

func (t *tokenReader) quoted() (string, error) {
	if t.line[t.pos] != '"' {
		return "", fmt.Errorf("%w: expected quote", errProtocol)
	}
	t.pos++
	var sb strings.Builder
	for {
		if t.pos >= len(t.line) {
			return "", fmt.Errorf("%w: unterminated quoted string", errProtocol)
		}
		c := t.line[t.pos]
		t.pos++
		switch c {
		case '"':
			return sb.String(), nil
		case '\\':
			if t.pos >= len(t.line) {
				return "", fmt.Errorf("%w: bad escape", errProtocol)
			}
			esc := t.line[t.pos]
			t.pos++
			switch esc {
			case '\\', '"':
				sb.WriteByte(esc)
			default:
				return "", fmt.Errorf("%w: bad escape %q", errProtocol, esc)
			}
		case '\r', '\n':
			return "", fmt.Errorf("%w: CR/LF in quoted string", errProtocol)
		default:
			sb.WriteByte(c)
		}
	}
}

func (t *tokenReader) literal() (string, error) {
	if t.line[t.pos] != '{' {
		return "", fmt.Errorf("%w: expected '{'", errProtocol)
	}
	t.pos++
	end := strings.IndexByte(t.line[t.pos:], '}')
	if end < 0 {
		return "", fmt.Errorf("%w: literal missing '}'", errProtocol)
	}
	spec := t.line[t.pos : t.pos+end]
	t.pos += end + 1
	nonsync := false
	if strings.HasSuffix(spec, "+") {
		nonsync = true
		spec = spec[:len(spec)-1]
	}
	n, err := strconv.ParseInt(spec, 10, 64)
	if err != nil || n < 0 {
		return "", fmt.Errorf("%w: bad literal size %q", errProtocol, spec)
	}
	limit := int64(maxLiteralSize)
	if t.maxLiteralOverride > 0 && t.maxLiteralOverride < limit {
		limit = t.maxLiteralOverride
	}
	if n > limit {
		return "", fmt.Errorf("%w: literal too large (%d bytes, max %d)", errProtocol, n, limit)
	}
	// Synchronizing literal: server must signal readiness before client sends.
	if !nonsync {
		if t.writeOK == nil {
			return "", fmt.Errorf("%w: synchronizing literals not supported here", errProtocol)
		}
		if err := t.writeOK(); err != nil {
			return "", err
		}
	}
	// After the literal token there should be CRLF at end of line. The literal
	// content follows on subsequent bytes.
	data := make([]byte, n)
	if _, err := io.ReadFull(t.br, data); err != nil {
		return "", fmt.Errorf("read literal: %w", err)
	}
	// Read the rest of the line (may be empty or contain more args).
	if err := t.nextLine(); err != nil {
		return "", err
	}
	return string(data), nil
}

// readLine reads one CRLF-terminated line from r, returning it without the
// trailing CRLF. Returns io.EOF if connection closed before any data was read.
func readLine(r *bufio.Reader) (string, error) {
	line, err := r.ReadString('\n')
	if err != nil {
		return "", err
	}
	line = strings.TrimRight(line, "\r\n")
	return line, nil
}

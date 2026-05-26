// Package message defines the abstract view of an email message that
// Sieve tests and actions consult. Keeping it an interface lets the
// library stay independent of any particular mail-parsing library.
//
// A net/mail-backed adapter is provided in this package for convenience.
package message

import (
	"io"
	"net/mail"
	"strings"
)

// Header is a single name/value pair preserving original case for the name.
type Header struct {
	Name  string
	Value string
}

// Message is the abstract view of a mail message used by Sieve tests.
// All header lookups are case-insensitive on the name.
type Message interface {
	// Header returns all values for a header, in order, in their original
	// form (i.e. with whitespace trimmed but otherwise unchanged).
	Header(name string) []string
	// AllHeaders returns every header in the order it appears in the
	// message.
	AllHeaders() []Header
	// Body returns a reader over the message body (everything after the
	// header/body separator). Each call returns a fresh reader positioned
	// at the start of the body.
	Body() io.Reader
	// Size is the total size of the message in bytes (headers + body).
	Size() int
	// Envelope returns the SMTP envelope values for the named field
	// ("from", "to"). It returns nil if no envelope is associated with
	// the message.
	Envelope(field string) []string
}

// FromNetMail wraps a *net/mail.Message. The body is fully read into
// memory so that Body() and Size() are cheap and repeatable.
func FromNetMail(m *mail.Message) Message {
	body, _ := io.ReadAll(m.Body)
	headers := make([]Header, 0)
	// net/mail.Header is a map; key order is not preserved. For most
	// Sieve uses (tests by header name) this is fine.
	for k, vs := range m.Header {
		for _, v := range vs {
			headers = append(headers, Header{Name: k, Value: strings.TrimSpace(v)})
		}
	}
	return &mailMessage{headers: headers, body: body}
}

type mailMessage struct {
	headers  []Header
	body     []byte
	envelope map[string][]string
	parts    []MIMEPart
}

func (m *mailMessage) Header(name string) []string {
	var out []string
	for _, h := range m.headers {
		if strings.EqualFold(h.Name, name) {
			out = append(out, h.Value)
		}
	}
	return out
}

func (m *mailMessage) AllHeaders() []Header { return m.headers }

func (m *mailMessage) Body() io.Reader { return strings.NewReader(string(m.body)) }

func (m *mailMessage) Size() int {
	// Approximate: sum of headers + blank line + body.
	n := 0
	for _, h := range m.headers {
		n += len(h.Name) + 2 + len(h.Value) + 2
	}
	n += 2 + len(m.body)
	return n
}

func (m *mailMessage) Envelope(field string) []string {
	if m.envelope == nil {
		return nil
	}
	return m.envelope[strings.ToLower(field)]
}

// MIMEParts implements MIMEProvider; returns nil for messages built
// through Builder unless parts have been attached.
func (m *mailMessage) MIMEParts() []MIMEPart { return m.parts }

// Builder is a convenience for constructing Messages in tests and small
// host apps without going through net/mail.
type Builder struct {
	headers  []Header
	body     []byte
	envelope map[string][]string
	parts    []MIMEPart
}

func NewBuilder() *Builder { return &Builder{envelope: map[string][]string{}} }

func (b *Builder) AddHeader(name, value string) *Builder {
	b.headers = append(b.headers, Header{Name: name, Value: value})
	return b
}

func (b *Builder) SetBody(body []byte) *Builder { b.body = body; return b }

func (b *Builder) SetEnvelope(field string, values ...string) *Builder {
	b.envelope[strings.ToLower(field)] = values
	return b
}

// AddMIMEPart attaches a pre-built MIME part. Useful for tests that want
// to exercise the "mime" extension without parsing a multipart blob.
func (b *Builder) AddMIMEPart(p MIMEPart) *Builder {
	b.parts = append(b.parts, p)
	return b
}

func (b *Builder) Build() Message {
	return &mailMessage{headers: b.headers, body: b.body, envelope: b.envelope, parts: b.parts}
}

// NewMIMEPart builds a synthetic MIMEPart for tests and host code that
// already has the headers/body parsed.
func NewMIMEPart(headers []Header, body []byte) MIMEPart {
	ct := ""
	for _, h := range headers {
		if strings.EqualFold(h.Name, "Content-Type") {
			ct = h.Value
			break
		}
	}
	return &mimePart{headers: headers, body: body, contentType: ct}
}

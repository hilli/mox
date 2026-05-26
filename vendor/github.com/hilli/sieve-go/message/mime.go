package message

import (
	"bytes"
	"io"
	"mime"
	"mime/multipart"
	"net/mail"
	"strings"
)

// MIMEPart is the view of a single MIME body part used by the
// "mime" Sieve extension (RFC 5703). It exposes part-scope headers and
// the part body, plus a couple of convenience accessors that mirror what
// Sieve scripts most commonly want to ask about a part.
type MIMEPart interface {
	Header(name string) []string
	AllHeaders() []Header
	Body() io.Reader
	ContentType() string
	IsAttachment() bool
}

// MIMEProvider is implemented by Messages that can enumerate their MIME
// structure. Returned parts are the *child* parts of the message in
// depth-first order; the root (the message itself) is NOT included — use
// the Message's own headers for that.
type MIMEProvider interface {
	MIMEParts() []MIMEPart
}

// ParseMIME parses a complete RFC 5322 message (headers + body) and
// returns a Message that implements MIMEProvider. Non-multipart messages
// yield zero child parts. Parts are walked depth-first; nested
// multiparts contribute each of their leaf parts in turn.
func ParseMIME(raw []byte) (Message, error) {
	m, err := mail.ReadMessage(bytes.NewReader(raw))
	if err != nil {
		return nil, err
	}
	bodyBytes, _ := io.ReadAll(m.Body)
	headers := make([]Header, 0, len(m.Header))
	for k, vs := range m.Header {
		for _, v := range vs {
			headers = append(headers, Header{Name: k, Value: strings.TrimSpace(v)})
		}
	}
	parts := walkParts(m.Header.Get("Content-Type"), bodyBytes)
	return &mailMessage{
		headers: headers,
		body:    bodyBytes,
		parts:   parts,
	}, nil
}

func walkParts(rootCT string, body []byte) []MIMEPart {
	mt, params, err := mime.ParseMediaType(rootCT)
	if err != nil || !strings.HasPrefix(mt, "multipart/") {
		return nil
	}
	boundary := params["boundary"]
	if boundary == "" {
		return nil
	}
	mr := multipart.NewReader(bytes.NewReader(body), boundary)
	var out []MIMEPart
	for {
		p, err := mr.NextPart()
		if err == io.EOF {
			break
		}
		if err != nil {
			break
		}
		partBody, _ := io.ReadAll(p)
		hdrs := make([]Header, 0, len(p.Header))
		for k, vs := range p.Header {
			for _, v := range vs {
				hdrs = append(hdrs, Header{Name: k, Value: strings.TrimSpace(v)})
			}
		}
		ct := p.Header.Get("Content-Type")
		mp := &mimePart{headers: hdrs, body: partBody, contentType: ct}
		// If the part is itself multipart, recurse and emit its children
		// instead of the wrapper.
		if children := walkParts(ct, partBody); len(children) > 0 {
			out = append(out, children...)
			continue
		}
		out = append(out, mp)
	}
	return out
}

type mimePart struct {
	headers     []Header
	body        []byte
	contentType string
}

func (p *mimePart) Header(name string) []string {
	var out []string
	for _, h := range p.headers {
		if strings.EqualFold(h.Name, name) {
			out = append(out, h.Value)
		}
	}
	return out
}

func (p *mimePart) AllHeaders() []Header { return p.headers }
func (p *mimePart) Body() io.Reader      { return bytes.NewReader(p.body) }

func (p *mimePart) ContentType() string {
	mt, _, err := mime.ParseMediaType(p.contentType)
	if err != nil {
		return strings.ToLower(strings.TrimSpace(p.contentType))
	}
	return mt
}

func (p *mimePart) IsAttachment() bool {
	for _, v := range p.Header("Content-Disposition") {
		mt, _, err := mime.ParseMediaType(v)
		if err == nil && strings.EqualFold(mt, "attachment") {
			return true
		}
		if strings.HasPrefix(strings.ToLower(strings.TrimSpace(v)), "attachment") {
			return true
		}
	}
	return false
}

// Mox message adapter for github.com/hilli/sieve-go.
//
// The adapter parses headers from a combined MsgPrefix + on-disk message file
// using net/mail, and exposes SMTP envelope values from the parsed
// store.Message. Body is provided lazily.

package sievefilter

import (
	"bytes"
	"io"
	"net/mail"
	"os"
	"strings"

	sievemsg "github.com/hilli/sieve-go/message"

	"github.com/mjl-/mox/store"
)

// MoxMessage adapts a store.Message + on-disk file to the sieve-go
// message.Message interface. It also exposes a deferred MIME parse for the
// body/mime extensions through message.MIMEProvider, but only parses MIME on
// first use to avoid the cost when not needed.
//
// MoxMessage is not safe for concurrent use across goroutines.
type MoxMessage struct {
	m    *store.Message
	file *os.File
	size int64

	// envelope fields populated from SMTP transaction.
	envelopeFrom string
	envelopeTo   []string

	// Cached parsed view; built lazily.
	parsed       bool
	rawBytes     []byte // cached combined MsgPrefix + on-disk body; populated on first ensureParsed/MIMEParts call.
	headers      []sievemsg.Header
	bodyBytes    []byte
	mimeParts    []sievemsg.MIMEPart
	parseErr     error
	headerLookup map[string][]string
}

// NewMoxMessage wraps a store.Message with the MsgPrefix combined with an
// on-disk file. envelopeFrom and envelopeTo populate the SMTP envelope values
// used by the "envelope" Sieve extension.
func NewMoxMessage(m *store.Message, file *os.File, envelopeFrom string, envelopeTo []string) *MoxMessage {
	return &MoxMessage{
		m:            m,
		file:         file,
		size:         m.Size,
		envelopeFrom: envelopeFrom,
		envelopeTo:   envelopeTo,
	}
}

func (mm *MoxMessage) raw() ([]byte, error) {
	// Build the full message: MsgPrefix + on-disk file. Memoized so multiple
	// callers (header parse, MIME parse, body read) don't re-read the file.
	if mm.rawBytes != nil {
		return mm.rawBytes, nil
	}
	if _, err := mm.file.Seek(0, io.SeekStart); err != nil {
		return nil, err
	}
	body, err := io.ReadAll(mm.file)
	if err != nil {
		return nil, err
	}
	out := make([]byte, 0, len(mm.m.MsgPrefix)+len(body))
	out = append(out, mm.m.MsgPrefix...)
	out = append(out, body...)
	mm.rawBytes = out
	return out, nil
}

func (mm *MoxMessage) ensureParsed() {
	if mm.parsed {
		return
	}
	mm.parsed = true
	raw, err := mm.raw()
	if err != nil {
		mm.parseErr = err
		return
	}
	msg, err := mail.ReadMessage(bytes.NewReader(raw))
	if err != nil {
		mm.parseErr = err
		return
	}
	body, err := io.ReadAll(msg.Body)
	if err != nil {
		mm.parseErr = err
		return
	}
	mm.bodyBytes = body
	mm.headerLookup = map[string][]string{}
	mm.headers = nil
	for k, vs := range msg.Header {
		lk := strings.ToLower(k)
		for _, v := range vs {
			mm.headers = append(mm.headers, sievemsg.Header{Name: k, Value: strings.TrimSpace(v)})
			mm.headerLookup[lk] = append(mm.headerLookup[lk], strings.TrimSpace(v))
		}
	}
	// MIME parts are parsed only if the body extension's :content tag or the
	// mime extension is used. Use sieve-go's ParseMIME on the raw bytes only
	// if first accessed via MIMEParts; deferred to avoid the cost otherwise.
}

func (mm *MoxMessage) Header(name string) []string {
	mm.ensureParsed()
	if mm.parseErr != nil {
		return nil
	}
	return mm.headerLookup[strings.ToLower(name)]
}

func (mm *MoxMessage) AllHeaders() []sievemsg.Header {
	mm.ensureParsed()
	return mm.headers
}

func (mm *MoxMessage) Body() io.Reader {
	mm.ensureParsed()
	return bytes.NewReader(mm.bodyBytes)
}

func (mm *MoxMessage) Size() int {
	return int(mm.size)
}

func (mm *MoxMessage) Envelope(field string) []string {
	switch strings.ToLower(field) {
	case "from":
		if mm.envelopeFrom == "" {
			return nil
		}
		return []string{mm.envelopeFrom}
	case "to":
		return mm.envelopeTo
	}
	return nil
}

// MIMEParts implements sievemsg.MIMEProvider. The parts are parsed lazily on
// first access using the sieve-go ParseMIME helper.
func (mm *MoxMessage) MIMEParts() []sievemsg.MIMEPart {
	mm.ensureParsed()
	if mm.parseErr != nil {
		return nil
	}
	if mm.mimeParts != nil {
		return mm.mimeParts
	}
	raw, err := mm.raw()
	if err != nil {
		return nil
	}
	parsed, err := sievemsg.ParseMIME(raw)
	if err != nil {
		return nil
	}
	if mp, ok := parsed.(sievemsg.MIMEProvider); ok {
		mm.mimeParts = mp.MIMEParts()
	}
	return mm.mimeParts
}

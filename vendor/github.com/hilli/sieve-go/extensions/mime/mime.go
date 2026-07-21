// Package mime implements the subset of the Sieve "mime" extension
// (RFC 5703) that scripts most commonly need: the ":mime" and
// ":anychild" tags on the existing "header", "address", and "exists"
// tests. With these tags a script can introspect the MIME structure of
// a message — most usefully, detect attachments:
//
//	require ["mime"];
//	if header :mime :anychild :contains "Content-Disposition" "attachment" {
//	    fileinto "Attachments";
//	}
//
// Semantics:
//
//   - :mime — look at MIME headers instead of the top-level RFC 5322
//     headers. Without :anychild this is the top-level part (i.e. the
//     message itself), so effectively a no-op for non-multipart mail.
//   - :mime :anychild — iterate every child MIME part (depth-first, leaf
//     parts only) and test its headers.
//   - :anychild without :mime is a script error per RFC 5703.
//
// Hosts must supply a message that implements message.MIMEProvider for
// :anychild to find any parts. The message.ParseMIME helper does this
// out of the box.
//
// Not yet implemented: foreverypart / break loops, the replace/enclose/
// extracttext actions. Scripts using those will fail validation as
// "unknown" until they land.
package mime

import (
	"fmt"
	"net/mail"
	"strings"

	"github.com/hilli/sieve-go"
	"github.com/hilli/sieve-go/ast"
	"github.com/hilli/sieve-go/interpreter"
	"github.com/hilli/sieve-go/message"
	"github.com/hilli/sieve-go/registry"
)

const Capability = "mime"

func Register(i *sieve.Interpreter) {
	r := i.Registry()
	// The base header/address/exists tests do not themselves require the
	// "mime" capability (RFC 5703 §5): only the :mime and :anychild tagged
	// arguments do. Register them capability-free but route through the
	// MIME-aware implementations, and require "mime" for the tags.
	r.RegisterTest("header", testHeader, "")
	r.RegisterTest("address", testAddress, "")
	r.RegisterTest("exists", testExists, "")
	r.RegisterTag(":mime", Capability)
	r.RegisterTag(":anychild", Capability)
	r.RegisterCommand("foreverypart", commandForeverypart, Capability)
	r.RegisterAction("break", actionBreak, Capability)
	r.RegisterAction("extracttext", actionExtractText, Capability)
	r.RegisterAction("replace", actionReplace, Capability)
	r.RegisterAction("enclose", actionEnclose, Capability)
}

func init() { Register(sieve.Default()) }

// mimeMode classifies what scope the test should run over.
type mimeMode int

const (
	modeNormal   mimeMode = iota // no :mime, no :anychild — RFC 5322 headers
	modeTopLevel                 // :mime without :anychild — top-level MIME headers (== message headers)
	modeAnyChild                 // :mime :anychild — iterate child parts
)

func modeFromArgs(args *ast.Arguments) (mimeMode, error) {
	var hasMIME, hasChild bool
	for _, tg := range args.Tags {
		switch strings.ToLower(tg.Name) {
		case ":mime":
			hasMIME = true
		case ":anychild":
			hasChild = true
		}
	}
	switch {
	case hasChild && !hasMIME:
		return modeNormal, fmt.Errorf("mime: :anychild requires :mime")
	case hasChild:
		return modeAnyChild, nil
	case hasMIME:
		return modeTopLevel, nil
	}
	return modeNormal, nil
}

func testHeader(ctx registry.Context, args *ast.Arguments, children []*ast.Test) (bool, error) {
	mode, err := modeFromArgs(args)
	if err != nil {
		return false, err
	}
	if mode == modeNormal {
		return interpreter.TestHeader(ctx, args, children)
	}
	if mode == modeTopLevel {
		// Inside foreverypart, :mime targets the current iteration part
		// (RFC 5703 §3); otherwise it's the top-level part (== message).
		if cp := interpreter.CurrentPart(ctx); cp != nil {
			return headerMatchParts(ctx, args, []message.MIMEPart{cp})
		}
		return interpreter.TestHeader(ctx, args, children)
	}
	return headerMatchParts(ctx, args, mimeParts(ctx))
}

func headerMatchParts(ctx registry.Context, args *ast.Arguments, parts []message.MIMEPart) (bool, error) {
	names, keys, err := twoStringLists(args, "header")
	if err != nil {
		return false, err
	}
	matcher := interpreter.LookupMatcher(ctx, args)
	for _, p := range parts {
		for _, hn := range names {
			for _, v := range p.Header(hn) {
				for _, k := range keys {
					if matcher(v, k) {
						return true, nil
					}
				}
			}
		}
	}
	return false, nil
}

func testAddress(ctx registry.Context, args *ast.Arguments, children []*ast.Test) (bool, error) {
	mode, err := modeFromArgs(args)
	if err != nil {
		return false, err
	}
	if mode == modeNormal || mode == modeTopLevel {
		return interpreter.TestAddress(ctx, args, children)
	}
	names, keys, err := twoStringLists(args, "address")
	if err != nil {
		return false, err
	}
	matcher := interpreter.LookupMatcher(ctx, args)
	ap := addressPartOf(args)
	for _, p := range mimeParts(ctx) {
		for _, hn := range names {
			for _, raw := range p.Header(hn) {
				addrs, err := mail.ParseAddressList(raw)
				if err != nil {
					continue
				}
				for _, a := range addrs {
					part := addrPart(a.Address, ap)
					for _, k := range keys {
						if matcher(part, k) {
							return true, nil
						}
					}
				}
			}
		}
	}
	return false, nil
}

func testExists(ctx registry.Context, args *ast.Arguments, children []*ast.Test) (bool, error) {
	mode, err := modeFromArgs(args)
	if err != nil {
		return false, err
	}
	if mode == modeNormal || mode == modeTopLevel {
		return interpreter.TestExists(ctx, args, children)
	}
	if len(args.Positional) != 1 {
		return false, fmt.Errorf("exists: expected 1 argument")
	}
	names, ok := stringsOf(args.Positional[0])
	if !ok {
		return false, fmt.Errorf("exists: expected string or string list")
	}
	parts := mimeParts(ctx)
	for _, n := range names {
		found := false
		for _, p := range parts {
			if len(p.Header(n)) > 0 {
				found = true
				break
			}
		}
		if !found {
			return false, nil
		}
	}
	return true, nil
}

func mimeParts(ctx registry.Context) []message.MIMEPart {
	if mp, ok := ctx.Message().(message.MIMEProvider); ok {
		return mp.MIMEParts()
	}
	return nil
}

// --- small helpers (kept local to avoid coupling to interpreter internals) ---

func twoStringLists(args *ast.Arguments, name string) ([]string, []string, error) {
	if len(args.Positional) != 2 {
		return nil, nil, fmt.Errorf("%s: expected 2 positional arguments, got %d", name, len(args.Positional))
	}
	a, ok := stringsOf(args.Positional[0])
	if !ok {
		return nil, nil, fmt.Errorf("%s: first argument must be string or string list", name)
	}
	b, ok := stringsOf(args.Positional[1])
	if !ok {
		return nil, nil, fmt.Errorf("%s: second argument must be string or string list", name)
	}
	return a, b, nil
}

func stringsOf(v ast.Value) ([]string, bool) {
	switch x := v.(type) {
	case ast.StringValue:
		return []string{x.Value}, true
	case ast.StringListValue:
		return x.Values, true
	}
	return nil, false
}

type addressPart int

const (
	apAll addressPart = iota
	apLocal
	apDomain
)

func addressPartOf(args *ast.Arguments) addressPart {
	for _, tg := range args.Tags {
		switch strings.ToLower(tg.Name) {
		case ":localpart":
			return apLocal
		case ":domain":
			return apDomain
		case ":all":
			return apAll
		}
	}
	return apAll
}

func addrPart(addr string, p addressPart) string {
	at := strings.LastIndexByte(addr, '@')
	switch p {
	case apLocal:
		if at < 0 {
			return addr
		}
		return addr[:at]
	case apDomain:
		if at < 0 {
			return ""
		}
		return addr[at+1:]
	}
	return addr
}

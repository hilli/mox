// Package fileinto implements the Sieve "fileinto" extension (RFC 5232).
//
// The host application must implement the Handler interface (which
// extends sieve.Handler with a FileInto method). Importing this package
// for its side effects registers the action on the default interpreter.
// To install the extension into a custom interpreter, call Register.
//
// The :flags tag (RFC 5232 §3.3, requires imap4flags) is honoured when
// the host implements FlagsHandler.
package fileinto

import (
	"fmt"
	"strings"

	"github.com/hilli/sieve-go"
	"github.com/hilli/sieve-go/ast"
	"github.com/hilli/sieve-go/registry"
)

// Capability is the string scripts must `require` to use fileinto.
const Capability = "fileinto"

// Handler is the action interface the host must implement. It extends
// the core sieve.Handler with the FileInto method.
type Handler interface {
	sieve.Handler
	FileInto(mailbox string) error
}

// FlagsHandler is an optional richer interface that the host may
// implement to receive deliveries together with the IMAP flags supplied
// by the script's :flags tag (RFC 5232 §3.3). When fileinto sees a
// :flags tag but the host does not implement FlagsHandler, the action
// returns an error to avoid silently dropping the flag information.
type FlagsHandler interface {
	Handler
	FileIntoWithFlags(mailbox string, flags []string) error
}

// Register installs the fileinto action on the given interpreter.
func Register(i *sieve.Interpreter) {
	i.Registry().RegisterAction("fileinto", action, Capability)
}

func action(ctx registry.Context, args *ast.Arguments) error {
	if len(args.Positional) < 1 {
		return fmt.Errorf("fileinto: expected 1 string argument")
	}
	// :flags owns the positional that follows it; the mailbox is the
	// remaining positional.
	flags, flagsIdx, err := extractFlags(args, "fileinto")
	if err != nil {
		return err
	}
	mailboxIdx := -1
	for i := range args.Positional {
		if i == flagsIdx {
			continue
		}
		mailboxIdx = i
		break
	}
	if mailboxIdx < 0 {
		return fmt.Errorf("fileinto: missing mailbox argument")
	}
	// Reject any extra positional that isn't owned by :flags.
	for i := range args.Positional {
		if i == flagsIdx || i == mailboxIdx {
			continue
		}
		return fmt.Errorf("fileinto: unexpected extra argument")
	}
	s, ok := args.Positional[mailboxIdx].(ast.StringValue)
	if !ok {
		return fmt.Errorf("fileinto: argument must be a string")
	}
	h, ok := ctx.Handler().(Handler)
	if !ok {
		return fmt.Errorf("fileinto: handler does not implement fileinto.Handler")
	}
	ctx.MarkExplicitAction()
	if flags != nil {
		fh, ok := h.(FlagsHandler)
		if !ok {
			return fmt.Errorf("fileinto :flags requires a handler implementing FlagsHandler")
		}
		return fh.FileIntoWithFlags(s.Value, flags)
	}
	return h.FileInto(s.Value)
}

// extractFlags returns the flag list from :flags <string-list>, and the
// index of the positional owned by the tag (-1 if none). Returns (nil,
// -1, nil) if :flags is absent.
func extractFlags(args *ast.Arguments, name string) ([]string, int, error) {
	for i, ref := range args.Order {
		if ref.Kind != ast.KindTag {
			continue
		}
		if !strings.EqualFold(args.Tags[ref.Idx].Name, ":flags") {
			continue
		}
		if i+1 >= len(args.Order) || args.Order[i+1].Kind != ast.KindPositional {
			return nil, -1, fmt.Errorf("%s :flags requires a string or string list argument", name)
		}
		pIdx := args.Order[i+1].Idx
		raw, ok := stringsOf(args.Positional[pIdx])
		if !ok {
			return nil, -1, fmt.Errorf("%s :flags argument must be a string or string list", name)
		}
		// Per RFC 5232, flags may be supplied as a single space-separated
		// string or as a list.
		var flags []string
		for _, v := range raw {
			flags = append(flags, strings.Fields(v)...)
		}
		if flags == nil {
			flags = []string{}
		}
		return flags, pIdx, nil
	}
	return nil, -1, nil
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

func init() {
	// Self-register on the default interpreter so that simply importing
	// this package enables fileinto for the package-level sieve.Compile.
	// Hosts that build a custom interpreter should call Register(i) on
	// it directly.
	Register(defaultI)
}

// defaultI is a reference to the same interpreter used by sieve.Compile.
// We obtain it through a small unexported accessor in the sieve package.
var defaultI = sieve.Default()

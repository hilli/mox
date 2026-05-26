// Package editheader implements the Sieve "editheader" extension
// (RFC 5293). It adds two actions:
//
//	addheader [:last] "Field" "Value"
//	deleteheader [:index <n>] [:last] [MATCH-TYPE] [COMPARATOR]
//	             "Field" [<value-patterns: string-list>]
//
// The host must implement Handler so the mutations can be applied to
// the message that will ultimately be delivered. The library itself
// does not rewrite the in-memory message; that is the host's job (since
// downstream tests in the same script aren't guaranteed to observe the
// changes per RFC 5293 §5).
package editheader

import (
	"fmt"
	"strconv"

	"github.com/hilli/sieve-go"
	"github.com/hilli/sieve-go/ast"
	"github.com/hilli/sieve-go/interpreter"
	"github.com/hilli/sieve-go/registry"
)

const Capability = "editheader"

// Handler is the host interface for editheader.
type Handler interface {
	sieve.Handler
	// AddHeader inserts a header. If atTop is true, prepend; else append.
	AddHeader(field, value string, atTop bool) error
	// DeleteHeader removes matching headers. If patterns is empty, all
	// instances are removed. matcher is non-nil and tests each header's
	// value against each pattern. index, if non-zero, is a 1-based selector
	// (positive from top, negative from bottom per RFC 5293 §6); fromLast
	// indicates :last was present.
	DeleteHeader(field string, patterns []string, matcher func(value, key string) bool, index int, fromLast bool) error
}

// Register installs the addheader/deleteheader actions.
func Register(i *sieve.Interpreter) {
	r := i.Registry()
	r.RegisterAction("addheader", actionAdd, Capability)
	r.RegisterAction("deleteheader", actionDelete, Capability)
}

func init() { Register(sieve.Default()) }

func actionAdd(ctx registry.Context, args *ast.Arguments) error {
	if len(args.Positional) != 2 {
		return fmt.Errorf("addheader: expected field name and value")
	}
	field, ok := args.Positional[0].(ast.StringValue)
	if !ok {
		return fmt.Errorf("addheader: field name must be a string")
	}
	val, ok := args.Positional[1].(ast.StringValue)
	if !ok {
		return fmt.Errorf("addheader: value must be a string")
	}
	atTop := !args.HasTag(":last")
	h, ok := ctx.Handler().(Handler)
	if !ok {
		return fmt.Errorf("addheader: handler does not implement editheader.Handler")
	}
	return h.AddHeader(field.Value, val.Value, atTop)
}

func actionDelete(ctx registry.Context, args *ast.Arguments) error {
	if len(args.Positional) < 1 {
		return fmt.Errorf("deleteheader: expected at least a field name")
	}

	// :index <n> consumes the next positional.
	index := 0
	if v := args.ValueAfterTag(":index"); v != nil {
		switch x := v.(type) {
		case ast.NumberValue:
			if x.Value < 1 {
				return fmt.Errorf("deleteheader: :index must be >= 1")
			}
			index = int(x.Value)
		case ast.StringValue:
			n, err := strconv.Atoi(x.Value)
			if err != nil || n < 1 {
				return fmt.Errorf("deleteheader: :index must be a positive integer")
			}
			index = n
		default:
			return fmt.Errorf("deleteheader: :index must be a number")
		}
	}
	fromLast := args.HasTag(":last")

	// Find the first positional that is NOT a value of :index.
	indexValueIdx := -1
	for i, ref := range args.Order {
		if ref.Kind != ast.KindTag {
			continue
		}
		if eqFold(args.Tags[ref.Idx].Name, ":index") &&
			i+1 < len(args.Order) && args.Order[i+1].Kind == ast.KindPositional {
			indexValueIdx = args.Order[i+1].Idx
			break
		}
	}
	var remaining []ast.Value
	for i, v := range args.Positional {
		if i == indexValueIdx {
			continue
		}
		remaining = append(remaining, v)
	}
	if len(remaining) < 1 {
		return fmt.Errorf("deleteheader: missing field name")
	}
	field, ok := remaining[0].(ast.StringValue)
	if !ok {
		return fmt.Errorf("deleteheader: field name must be a string")
	}
	var patterns []string
	if len(remaining) >= 2 {
		switch v := remaining[1].(type) {
		case ast.StringValue:
			patterns = []string{v.Value}
		case ast.StringListValue:
			patterns = v.Values
		default:
			return fmt.Errorf("deleteheader: patterns must be string or string list")
		}
	}
	matcher := interpreter.LookupMatcher(ctx, args)
	h, ok := ctx.Handler().(Handler)
	if !ok {
		return fmt.Errorf("deleteheader: handler does not implement editheader.Handler")
	}
	return h.DeleteHeader(field.Value, patterns, matcher, index, fromLast)
}

func eqFold(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := 0; i < len(a); i++ {
		ca, cb := a[i], b[i]
		if ca >= 'A' && ca <= 'Z' {
			ca += 'a' - 'A'
		}
		if cb >= 'A' && cb <= 'Z' {
			cb += 'a' - 'A'
		}
		if ca != cb {
			return false
		}
	}
	return true
}

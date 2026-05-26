// Package vacation implements the Sieve "vacation" action (RFC 5230).
// A script declares an auto-reply with optional :days suppression
// window, :subject, :from, :addresses (alternative recipient
// addresses), :mime (the body is a complete MIME message), and
// :handle (server-side de-duplication handle).
//
// The library does not actually generate or send any reply. It parses
// the action and delegates to Handler.Vacation, which the host must
// implement. The host is responsible for de-duplication, recipient
// filtering, and SMTP submission.
package vacation

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/hilli/sieve-go"
	"github.com/hilli/sieve-go/ast"
	"github.com/hilli/sieve-go/registry"
)

const Capability = "vacation"

// Params is the fully parsed vacation action passed to the host. Reason
// is the body of the reply (either plain text or, with Mime=true, a
// complete MIME message).
type Params struct {
	Reason    string
	Days      int      // 0 = unset (use server default per RFC 5230 §4)
	Subject   string   // "" = unset
	From      string   // "" = unset
	Handle    string   // "" = unset
	Addresses []string // alternative recipient addresses, may be empty
	Mime      bool
}

// Handler is the host interface for the vacation action.
type Handler interface {
	sieve.Handler
	Vacation(p Params) error
}

// Register installs the vacation action.
func Register(i *sieve.Interpreter) {
	i.Registry().RegisterAction("vacation", action, Capability)
}

func init() { Register(sieve.Default()) }

func action(ctx registry.Context, args *ast.Arguments) error {
	if len(args.Positional) < 1 {
		return fmt.Errorf("vacation: expected reason argument")
	}

	p := Params{Mime: args.HasTag(":mime")}

	// Value-bearing tags consume the positional that follows them.
	consumed := map[int]bool{}
	markConsumed := func(tagName string, setter func(ast.Value) error) error {
		for i, ref := range args.Order {
			if ref.Kind != ast.KindTag {
				continue
			}
			if !strings.EqualFold(args.Tags[ref.Idx].Name, tagName) {
				continue
			}
			if i+1 < len(args.Order) && args.Order[i+1].Kind == ast.KindPositional {
				vi := args.Order[i+1].Idx
				consumed[vi] = true
				return setter(args.Positional[vi])
			}
			return fmt.Errorf("vacation: %s requires a value", tagName)
		}
		return nil
	}

	if err := markConsumed(":days", func(v ast.Value) error {
		n, err := asNonNegInt(v, "vacation: :days")
		if err != nil {
			return err
		}
		p.Days = n
		return nil
	}); err != nil {
		return err
	}
	if err := markConsumed(":subject", strSetter("vacation: :subject", &p.Subject)); err != nil {
		return err
	}
	if err := markConsumed(":from", strSetter("vacation: :from", &p.From)); err != nil {
		return err
	}
	if err := markConsumed(":handle", strSetter("vacation: :handle", &p.Handle)); err != nil {
		return err
	}
	if err := markConsumed(":addresses", func(v ast.Value) error {
		switch x := v.(type) {
		case ast.StringValue:
			p.Addresses = []string{x.Value}
		case ast.StringListValue:
			p.Addresses = x.Values
		default:
			return fmt.Errorf("vacation: :addresses must be string or string list")
		}
		return nil
	}); err != nil {
		return err
	}

	// The reason is the remaining positional.
	reasonIdx := -1
	for i := range args.Positional {
		if consumed[i] {
			continue
		}
		reasonIdx = i
		break
	}
	if reasonIdx < 0 {
		return fmt.Errorf("vacation: missing reason argument")
	}
	for i := range args.Positional {
		if i == reasonIdx || consumed[i] {
			continue
		}
		return fmt.Errorf("vacation: unexpected extra argument")
	}
	reason, ok := args.Positional[reasonIdx].(ast.StringValue)
	if !ok {
		return fmt.Errorf("vacation: reason must be a string")
	}
	p.Reason = reason.Value

	h, ok := ctx.Handler().(Handler)
	if !ok {
		return fmt.Errorf("vacation: handler does not implement vacation.Handler")
	}
	return h.Vacation(p)
}

func strSetter(errPrefix string, dst *string) func(ast.Value) error {
	return func(v ast.Value) error {
		s, ok := v.(ast.StringValue)
		if !ok {
			return fmt.Errorf("%s must be a string", errPrefix)
		}
		*dst = s.Value
		return nil
	}
}

func asNonNegInt(v ast.Value, errPrefix string) (int, error) {
	switch x := v.(type) {
	case ast.NumberValue:
		return int(x.Value), nil
	case ast.StringValue:
		n, err := strconv.Atoi(x.Value)
		if err != nil || n < 0 {
			return 0, fmt.Errorf("%s must be a non-negative integer", errPrefix)
		}
		return n, nil
	}
	return 0, fmt.Errorf("%s must be a number", errPrefix)
}

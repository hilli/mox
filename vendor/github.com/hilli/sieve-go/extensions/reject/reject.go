// Package reject implements the Sieve "reject" and "ereject" actions
// (RFC 5429). Both refuse delivery and return the supplied reason text
// to the sender — `ereject` is the protocol-aware variant that performs
// an SMTP-level rejection while `reject` generates a delivery-status
// notification, but at the script level they are syntactically and
// semantically identical, differing only in capability name.
//
// The host application implements Handler.Reject(reason). When the
// extension distinguishes the two, the host may type-assert to
// EjectHandler for ereject.
package reject

import (
	"fmt"

	"github.com/hilli/sieve-go"
	"github.com/hilli/sieve-go/ast"
	"github.com/hilli/sieve-go/registry"
)

const (
	Capability  = "reject"
	ECapability = "ereject"
)

// Handler is the host interface for the reject action.
type Handler interface {
	sieve.Handler
	Reject(reason string) error
}

// EjectHandler is the optional host interface for ereject. If absent
// the action falls back to Handler.Reject.
type EjectHandler interface {
	Handler
	Ereject(reason string) error
}

// Register installs both reject and ereject on the given interpreter.
func Register(i *sieve.Interpreter) {
	i.Registry().RegisterAction("reject", actionReject, Capability)
	i.Registry().RegisterAction("ereject", actionEreject, ECapability)
}

func init() { Register(sieve.Default()) }

func actionReject(ctx registry.Context, args *ast.Arguments) error {
	reason, err := singleString(args, "reject")
	if err != nil {
		return err
	}
	h, ok := ctx.Handler().(Handler)
	if !ok {
		return fmt.Errorf("reject: handler does not implement reject.Handler")
	}
	ctx.MarkExplicitAction()
	return h.Reject(reason)
}

func actionEreject(ctx registry.Context, args *ast.Arguments) error {
	reason, err := singleString(args, "ereject")
	if err != nil {
		return err
	}
	h, ok := ctx.Handler().(Handler)
	if !ok {
		return fmt.Errorf("ereject: handler does not implement reject.Handler")
	}
	ctx.MarkExplicitAction()
	if eh, ok := h.(EjectHandler); ok {
		return eh.Ereject(reason)
	}
	return h.Reject(reason)
}

func singleString(args *ast.Arguments, name string) (string, error) {
	if len(args.Positional) != 1 {
		return "", fmt.Errorf("%s: expected 1 string argument, got %d", name, len(args.Positional))
	}
	s, ok := args.Positional[0].(ast.StringValue)
	if !ok {
		return "", fmt.Errorf("%s: argument must be a string", name)
	}
	return s.Value, nil
}

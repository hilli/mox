package interpreter

import (
	"github.com/hilli/sieve-go/message"
	"github.com/hilli/sieve-go/registry"
)

// CurrentPart returns the MIME part being iterated by an enclosing
// foreverypart loop (RFC 5703), or nil when no such loop is active or
// ctx is not an interpreter state.
func CurrentPart(ctx registry.Context) message.MIMEPart {
	if s, ok := ctx.(*state); ok {
		return s.part
	}
	return nil
}

// SetCurrentPart updates the per-iteration MIME part on ctx and returns
// a restore function. Use it like:
//
//	restore := interpreter.SetCurrentPart(ctx, part)
//	defer restore()
func SetCurrentPart(ctx registry.Context, p message.MIMEPart) func() {
	s, ok := ctx.(*state)
	if !ok {
		return func() {}
	}
	prev := s.part
	s.part = p
	return func() { s.part = prev }
}

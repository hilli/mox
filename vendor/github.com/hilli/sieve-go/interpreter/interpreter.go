// Package interpreter wires the AST, registry, message, and host Handler
// together. It exposes a Compile/Validate/Run API consumed by the
// top-level sieve package façade.
package interpreter

import (
	"fmt"
	"strings"

	"github.com/hilli/sieve-go/ast"
	"github.com/hilli/sieve-go/message"
	"github.com/hilli/sieve-go/registry"
)
// Interpreter holds a registry and can compile/run scripts against it.
// One Interpreter is safe for concurrent use by multiple goroutines as
// long as no further registration happens after first use.
type Interpreter struct {
	reg *registry.Registry
}

// New constructs an Interpreter and registers the RFC 5228 builtins.
// Additional extensions can be registered on the returned Registry.
func New() *Interpreter {
	i := &Interpreter{reg: registry.New()}
	RegisterCore(i.reg)
	return i
}

// Registry exposes the underlying registry so callers (and extension
// packages) can register additional actions/tests.
func (i *Interpreter) Registry() *registry.Registry { return i.reg }

// Script is a compiled (parsed + validated) Sieve script.
type Script struct {
	ast    *ast.Script
	caps   map[string]bool
	interp *Interpreter
}

// Compile parses and validates the script.
func (i *Interpreter) Compile(s *ast.Script) (*Script, error) {
	caps, err := i.validate(s)
	if err != nil {
		return nil, err
	}
	return &Script{ast: s, caps: caps, interp: i}, nil
}

// Validate runs Compile but discards the resulting Script.
func (i *Interpreter) Validate(s *ast.Script) error {
	_, err := i.Compile(s)
	return err
}

// validate walks the script, collects required capabilities from any
// `require` commands, and verifies every command/test exists in the
// registry and has its required capability.
func (i *Interpreter) validate(s *ast.Script) (map[string]bool, error) {
	caps := map[string]bool{}

	// Pass 1: collect requires (must appear before any other command per
	// RFC 5228 §3.2; we enforce that loosely: any `require` may appear at
	// the top level, but we warn if it follows a non-require command).
	seenNonRequire := false
	for _, c := range s.Commands {
		if c.Name == "require" {
			if seenNonRequire {
				return nil, fmt.Errorf("`require` at %d:%d must precede other commands", c.Pos.Line, c.Pos.Col)
			}
			for _, v := range c.Args.Positional {
				switch x := v.(type) {
				case ast.StringValue:
					caps[x.Value] = true
				case ast.StringListValue:
					for _, s := range x.Values {
						caps[s] = true
					}
				default:
					return nil, fmt.Errorf("require: expected string or string list at %d:%d", c.Pos.Line, c.Pos.Col)
				}
			}
		} else {
			seenNonRequire = true
		}
	}

	// Verify each required capability is known.
	for cap := range caps {
		if !i.reg.HasCapability(cap) {
			return nil, fmt.Errorf("unknown capability %q (did you forget to import an extension?)", cap)
		}
	}

	// Pass 2: walk and validate commands/tests.
	return caps, i.validateCommands(s.Commands, caps)
}

func (i *Interpreter) validateCommands(cmds []*ast.Command, caps map[string]bool) error {
	for _, c := range cmds {
		switch c.Name {
		case "require":
			continue
		case "if", "elsif":
			if c.Test == nil {
				return fmt.Errorf("%s at %d:%d requires a test", c.Name, c.Pos.Line, c.Pos.Col)
			}
			if err := i.validateTest(c.Test, caps); err != nil {
				return err
			}
			if !c.HasBlock {
				return fmt.Errorf("%s at %d:%d requires a block", c.Name, c.Pos.Line, c.Pos.Col)
			}
			if err := i.validateCommands(c.Block, caps); err != nil {
				return err
			}
		case "else":
			if !c.HasBlock {
				return fmt.Errorf("else at %d:%d requires a block", c.Pos.Line, c.Pos.Col)
			}
			if err := i.validateCommands(c.Block, caps); err != nil {
				return err
			}
		case "stop":
			// no args, no block
		default:
			// Control-flow command first.
			if cfn, req, ok := i.reg.LookupCommand(c.Name); ok {
				_ = cfn
				if req != "" && !caps[req] {
					return fmt.Errorf("command %q at %d:%d requires capability %q (add to `require`)", c.Name, c.Pos.Line, c.Pos.Col, req)
				}
				if c.HasBlock {
					if err := i.validateCommands(c.Block, caps); err != nil {
						return err
					}
				}
				continue
			}
			_, req, ok := i.reg.LookupAction(c.Name)
			if !ok {
				return fmt.Errorf("unknown action %q at %d:%d", c.Name, c.Pos.Line, c.Pos.Col)
			}
			if req != "" && !caps[req] {
				return fmt.Errorf("action %q at %d:%d requires capability %q (add to `require`)", c.Name, c.Pos.Line, c.Pos.Col, req)
			}
		}
	}
	return nil
}

func (i *Interpreter) validateTest(t *ast.Test, caps map[string]bool) error {
	switch t.Name {
	case "not":
		if len(t.Children) != 1 {
			return fmt.Errorf("not at %d:%d requires exactly one test", t.Pos.Line, t.Pos.Col)
		}
		return i.validateTest(t.Children[0], caps)
	case "allof", "anyof":
		if len(t.Children) == 0 {
			return fmt.Errorf("%s at %d:%d requires at least one test", t.Name, t.Pos.Line, t.Pos.Col)
		}
		for _, c := range t.Children {
			if err := i.validateTest(c, caps); err != nil {
				return err
			}
		}
		return nil
	case "true", "false":
		return nil
	default:
		_, req, ok := i.reg.LookupTest(t.Name)
		if !ok {
			return fmt.Errorf("unknown test %q at %d:%d", t.Name, t.Pos.Line, t.Pos.Col)
		}
		if req != "" && !caps[req] {
			return fmt.Errorf("test %q at %d:%d requires capability %q (add to `require`)", t.Name, t.Pos.Line, t.Pos.Col, req)
		}
		// Validate any match-type tags' capabilities. Other tags (address
		// parts, comparator, body transforms, ...) are still resolved
		// lazily at run time.
		for _, tg := range t.Args.Tags {
			if _, mreq, ok := i.reg.LookupMatchType(strings.ToLower(tg.Name)); ok {
				if mreq != "" && !caps[mreq] {
					return fmt.Errorf("match type %q at %d:%d requires capability %q (add to `require`)", tg.Name, tg.Pos.Line, tg.Pos.Col, mreq)
				}
			}
		}
		return nil
	}
}

// Run executes the compiled script against msg, dispatching actions to
// handler. Implicit keep (RFC 5228 §2.10.6) is applied if no explicit
// keep/redirect/fileinto/discard action ran.
func (s *Script) Run(msg message.Message, handler registry.Handler) error {
	st := &state{msg: msg, handler: handler, reg: s.interp.reg}
	if err := s.interp.execBlock(s.ast.Commands, st); err != nil && err != errStop {
		return err
	}
	if !st.explicit {
		if err := handler.Keep(); err != nil {
			return fmt.Errorf("implicit keep: %w", err)
		}
	}
	return nil
}

var errStop = fmt.Errorf("stop")

func (i *Interpreter) execBlock(cmds []*ast.Command, st *state) error {
	skipChain := false // set after a successful if/elsif so the elsif/else chain short-circuits
	for _, c := range cmds {
		switch c.Name {
		case "require":
			// no-op at run time
		case "if":
			ok, err := st.EvalTest(c.Test)
			if err != nil {
				return err
			}
			if ok {
				if err := i.execBlock(c.Block, st); err != nil {
					return err
				}
				skipChain = true
			} else {
				skipChain = false
			}
		case "elsif":
			if skipChain {
				continue
			}
			ok, err := st.EvalTest(c.Test)
			if err != nil {
				return err
			}
			if ok {
				if err := i.execBlock(c.Block, st); err != nil {
					return err
				}
				skipChain = true
			}
		case "else":
			if skipChain {
				skipChain = false
				continue
			}
			if err := i.execBlock(c.Block, st); err != nil {
				return err
			}
			skipChain = false
		case "stop":
			return errStop
		default:
			skipChain = false
			// Look up control-flow commands first (e.g. foreverypart).
			if cfn, _, ok := i.reg.LookupCommand(c.Name); ok {
				if err := cfn(st, &c.Args, c.Block, func(b []*ast.Command) error {
					return i.execBlock(b, st)
				}); err != nil {
					if _, isBreak := err.(*registry.BreakError); isBreak {
						return err // propagate up to the nearest loop
					}
					if err == errStop {
						return err
					}
					return fmt.Errorf("%s: %w", c.Name, err)
				}
			} else {
				fn, _, ok := i.reg.LookupAction(c.Name)
				if !ok {
					return fmt.Errorf("unknown action %q at %d:%d", c.Name, c.Pos.Line, c.Pos.Col)
				}
				a := expandArgs(&c.Args, st.vars)
				if err := fn(st, a); err != nil {
					if _, isBreak := err.(*registry.BreakError); isBreak {
						return err // propagate raw so the loop sees it
					}
					return fmt.Errorf("%s: %w", c.Name, err)
				}
			}
		}
		if st.stopped {
			return errStop
		}
	}
	return nil
}

// state implements registry.Context.
type state struct {
	msg      message.Message
	handler  registry.Handler
	reg      *registry.Registry
	explicit bool
	stopped  bool
	vars     *registry.Variables
	// part, if non-nil, is the current MIME part inside a foreverypart
	// loop. Tests like header/exists in mime-aware mode use this.
	part message.MIMEPart
}

func (s *state) Message() message.Message  { return s.msg }
func (s *state) Handler() registry.Handler { return s.handler }
func (s *state) MarkExplicitAction()       { s.explicit = true }
func (s *state) Stop()                     { s.stopped = true }
func (s *state) Variables() *registry.Variables {
	if s.vars == nil {
		s.vars = registry.NewVariables()
	}
	return s.vars
}

// CurrentPart returns the MIME part being iterated by an enclosing
// foreverypart loop, or nil when no such loop is active.
func (s *state) CurrentPart() message.MIMEPart { return s.part }

// SetCurrentPart updates the current MIME part; intended for use by the
// mime extension's foreverypart implementation.
func (s *state) SetCurrentPart(p message.MIMEPart) { s.part = p }

func (s *state) EvalTest(t *ast.Test) (bool, error) {
	switch t.Name {
	case "true":
		return true, nil
	case "false":
		return false, nil
	case "not":
		v, err := s.EvalTest(t.Children[0])
		return !v, err
	case "allof":
		for _, c := range t.Children {
			v, err := s.EvalTest(c)
			if err != nil {
				return false, err
			}
			if !v {
				return false, nil
			}
		}
		return true, nil
	case "anyof":
		for _, c := range t.Children {
			v, err := s.EvalTest(c)
			if err != nil {
				return false, err
			}
			if v {
				return true, nil
			}
		}
		return false, nil
	}
	fn, _, ok := s.reg.LookupTest(t.Name)
	if !ok {
		return false, fmt.Errorf("unknown test %q at %d:%d", t.Name, t.Pos.Line, t.Pos.Col)
	}
	a := expandArgs(&t.Args, s.vars)
	return fn(s, a, t.Children)
}

// Helpers used by core test implementations.

// stringsOf flattens a positional argument that may be a single string or
// a string list into a slice of strings.
func stringsOf(v ast.Value) ([]string, bool) {
	switch x := v.(type) {
	case ast.StringValue:
		return []string{x.Value}, true
	case ast.StringListValue:
		return x.Values, true
	}
	return nil, false
}

// AddressPart returns the function for whichever address-part tag is
// present in args (e.g. :localpart, :domain, :user, :detail) — falling
// back to the identity (`:all`) when none is set. Extensions register
// their own parts via registry.RegisterAddressPart.
func AddressPart(ctx registry.Context, args *ast.Arguments) registry.AddressPartFunc {
	reg := ctx.(*state).reg
	for _, tg := range args.Tags {
		if fn, _, ok := reg.LookupAddressPart(strings.ToLower(tg.Name)); ok {
			return fn
		}
	}
	if fn, _, ok := reg.LookupAddressPart(":all"); ok {
		return fn
	}
	return func(a string) string { return a }
}

// addressPartOf / addressPartString remain for backwards compatibility
// within the interpreter package; new code should use AddressPart above.
type addressPart int

const (
	addrAll addressPart = iota
	addrLocal
	addrDomain
)

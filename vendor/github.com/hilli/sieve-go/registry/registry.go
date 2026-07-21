// Package registry holds the set of Sieve commands, tests, and tagged
// arguments that an interpreter knows about. Core (RFC 5228) builtins
// are registered automatically by package interpreter on construction;
// extension packages register additional functionality through their
// init() and can opt in to a capability that scripts must `require`.
//
// The registry is the single source of truth for what a script may
// contain: validation walks the AST and checks every command/test name
// against the registry, and the interpreter dispatches through it.
package registry

import (
	"fmt"
	"strings"
	"sync"

	"github.com/hilli/sieve-go/ast"
	"github.com/hilli/sieve-go/message"
)

// ActionFunc executes a registered action against the host.
//
// Implementations may inspect args (positional and tagged) and call into
// the supplied Handler. They must not retain refs to args after returning.
type ActionFunc func(ctx Context, args *ast.Arguments) error

// TestFunc evaluates a registered test against the current message.
type TestFunc func(ctx Context, args *ast.Arguments, children []*ast.Test) (bool, error)

// Context is what action/test implementations are given at run time.
// It is intentionally minimal; richer extensions can grow it through
// well-known keys on State if needed.
type Context interface {
	Message() message.Message
	Handler() Handler
	// EvalTest dispatches a child test through the registry. allof/anyof/not
	// use this to evaluate their children.
	EvalTest(t *ast.Test) (bool, error)
	// MarkExplicitAction is called by actions that satisfy the implicit-keep
	// rule (RFC 5228 §2.10.6) so the interpreter knows not to keep at the
	// end of the script.
	MarkExplicitAction()
	// Stop signals "stop;" — the interpreter halts after the current
	// command returns.
	Stop()
	// Variables exposes the script-level variable store (RFC 5229).
	// Returns nil if the variables extension has not been registered.
	Variables() *Variables
}

// Variables holds the named/numbered values used by Sieve string
// interpolation (RFC 5229). Names are case-insensitive. Numbered
// variables (set by :matches captures) are exposed under "0".."9".
type Variables struct {
	named    map[string]string
	captured []string // last :matches captures; [0] is the whole match
}

func NewVariables() *Variables {
	return &Variables{named: map[string]string{}}
}

// Get returns the value for name (case-insensitive). Numeric names map
// to :matches captures. Returns "" if not set.
func (v *Variables) Get(name string) string {
	if v == nil {
		return ""
	}
	if len(name) > 0 && name[0] >= '0' && name[0] <= '9' {
		// numeric
		idx := 0
		for _, c := range name {
			if c < '0' || c > '9' {
				return ""
			}
			idx = idx*10 + int(c-'0')
		}
		if idx < len(v.captured) {
			return v.captured[idx]
		}
		return ""
	}
	return v.named[lower(name)]
}

// Set assigns a named variable.
func (v *Variables) Set(name, value string) {
	if v == nil {
		return
	}
	v.named[lower(name)] = value
}

// SetCaptures replaces the numeric capture set (called after a :matches
// comparison; captures[0] is the whole match).
func (v *Variables) SetCaptures(caps []string) {
	if v == nil {
		return
	}
	v.captured = caps
}

func lower(s string) string {
	b := []byte(s)
	for i, c := range b {
		if c >= 'A' && c <= 'Z' {
			b[i] = c + ('a' - 'A')
		}
	}
	return string(b)
}

// Handler is what the host application implements to receive Sieve
// actions. Extensions that add new actions can either type-assert this
// interface to a richer one defined in their own package, or accept a
// generic ExtHandler from State (see Context).
type Handler interface {
	Keep() error
	Discard() error
	Redirect(addr string) error
}

// Registry holds registered actions, tests, and capabilities.
type Registry struct {
	mu           sync.RWMutex
	actions      map[string]actionEntry
	tests        map[string]testEntry
	matchTypes   map[string]matchTypeEntry
	comparators  map[string]comparatorEntry
	addressParts map[string]addressPartEntry
	commands     map[string]commandEntry
	// tags maps an extension-defined tagged argument (e.g. ":mime") to the
	// capability a script must `require` to use it. Used for tags that
	// extend existing tests/commands without being match-types, address
	// parts or comparators (RFC 5703 ":mime"/":anychild", for example).
	tags map[string]string
	// caps is the set of capabilities considered "available" by this
	// registry. Core capabilities (none for RFC 5228 base) plus anything
	// registered with a non-empty Requires.
	caps map[string]bool
}

type actionEntry struct {
	fn       ActionFunc
	requires string // capability name, or "" for always-available
}

type testEntry struct {
	fn       TestFunc
	requires string
}

// MatchTypeFunc compares an actual value against a key per the semantics
// of a particular match-type tag (e.g. :is, :contains, :matches, :regex).
// Inputs are pre-decoded strings; comparators (case folding etc.) are the
// matcher's responsibility for now.
type MatchTypeFunc func(value, key string) bool

type matchTypeEntry struct {
	fn       MatchTypeFunc
	requires string
}

// Comparator implements the RFC 5228 §2.7.3 collation hooks consumed by
// the :is / :contains / :matches built-in match types.
type Comparator interface {
	Equal(a, b string) bool
	Contains(s, key string) bool
	Matches(s, pattern string) bool
}

type comparatorEntry struct {
	cmp      Comparator
	requires string
}

func New() *Registry {
	return &Registry{
		actions:      map[string]actionEntry{},
		tests:        map[string]testEntry{},
		matchTypes:   map[string]matchTypeEntry{},
		comparators:  map[string]comparatorEntry{},
		addressParts: map[string]addressPartEntry{},
		commands:     map[string]commandEntry{},
		tags:         map[string]string{},
		caps:         map[string]bool{},
	}
}

// CommandFunc implements a Sieve control-flow command (e.g. foreverypart
// from RFC 5703). It receives the parsed args, the script block lexically
// nested under the command, and an exec callback to (recursively) run a
// block in the same execution state.
//
// Use ctx.Stop() to abort the whole script. To break out of a containing
// loop, return ErrBreak (with an optional label via BreakError).
type CommandFunc func(ctx Context, args *ast.Arguments, block []*ast.Command, exec func([]*ast.Command) error) error

type commandEntry struct {
	fn       CommandFunc
	requires string
}

// RegisterCommand adds a control-flow command. requires, if non-empty,
// names the capability scripts must `require` to use it.
func (r *Registry) RegisterCommand(name string, fn CommandFunc, requires string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.commands[name] = commandEntry{fn: fn, requires: requires}
	if requires != "" {
		r.caps[requires] = true
	}
}

// LookupCommand returns the command and its required capability.
func (r *Registry) LookupCommand(name string) (CommandFunc, string, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	e, ok := r.commands[name]
	if !ok {
		return nil, "", false
	}
	return e.fn, e.requires, true
}

// BreakError is the sentinel returned by an action to unwind the
// innermost enclosing foreverypart loop. Containing commands check for
// this error type and stop iterating without propagating the error.
type BreakError struct{ Label string }

func (e *BreakError) Error() string {
	if e.Label == "" {
		return "break"
	}
	return "break :name " + e.Label
}

// RegisterAction adds an action. If requires is non-empty, scripts must
// `require "<cap>";` to use this action.
func (r *Registry) RegisterAction(name string, fn ActionFunc, requires string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.actions[name] = actionEntry{fn: fn, requires: requires}
	if requires != "" {
		r.caps[requires] = true
	}
}

// RegisterTest adds a test under the given name.
func (r *Registry) RegisterTest(name string, fn TestFunc, requires string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.tests[name] = testEntry{fn: fn, requires: requires}
	if requires != "" {
		r.caps[requires] = true
	}
}

// LookupAction returns the action and its required capability.
func (r *Registry) LookupAction(name string) (ActionFunc, string, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	e, ok := r.actions[name]
	if !ok {
		return nil, "", false
	}
	return e.fn, e.requires, true
}

// LookupTest returns the test and its required capability.
func (r *Registry) LookupTest(name string) (TestFunc, string, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	e, ok := r.tests[name]
	if !ok {
		return nil, "", false
	}
	return e.fn, e.requires, true
}

// HasCapability reports whether a capability string is known.
func (r *Registry) HasCapability(name string) bool {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.caps[name]
}

// RegisterMatchType adds a match-type tag (e.g. ":is", ":regex"). The
// name MUST include the leading colon. If requires is non-empty, scripts
// must `require "<cap>";` to use the tag.
func (r *Registry) RegisterMatchType(name string, fn MatchTypeFunc, requires string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.matchTypes[name] = matchTypeEntry{fn: fn, requires: requires}
	if requires != "" {
		r.caps[requires] = true
	}
}

// LookupMatchType returns the matcher and its required capability.
func (r *Registry) LookupMatchType(name string) (MatchTypeFunc, string, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	e, ok := r.matchTypes[name]
	if !ok {
		return nil, "", false
	}
	return e.fn, e.requires, true
}

// RegisterTag records that an extension-defined tagged argument (e.g.
// ":mime") requires a capability. This lets an extension add tags to an
// existing test or command without making the base test/command itself
// require the capability. The tag name is matched case-insensitively and
// should include the leading colon (e.g. ":mime").
func (r *Registry) RegisterTag(name, requires string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.tags[strings.ToLower(name)] = requires
	if requires != "" {
		r.caps[requires] = true
	}
}

// LookupTag returns the capability an extension-defined tag requires. ok is
// false for unknown tags (e.g. core match-types or address parts, which are
// resolved through their own registries).
func (r *Registry) LookupTag(name string) (requires string, ok bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	req, ok := r.tags[strings.ToLower(name)]
	return req, ok
}

// RegisterComparator adds a comparator (RFC 5228 §2.7.3) under its IANA
// name (e.g. "i;ascii-casemap"). If requires is non-empty, scripts must
// `require "comparator-<name>";` to use it (the Sieve convention).
func (r *Registry) RegisterComparator(name string, c Comparator, requires string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.comparators[name] = comparatorEntry{cmp: c, requires: requires}
	if requires != "" {
		r.caps[requires] = true
	}
}

// LookupComparator returns the comparator and its required capability.
func (r *Registry) LookupComparator(name string) (Comparator, string, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	e, ok := r.comparators[name]
	if !ok {
		return nil, "", false
	}
	return e.cmp, e.requires, true
}

// AddressPartFunc returns the requested part of an RFC 5321 address.
// Implementations receive the full addr-spec (e.g. "alice+filter@x.y")
// and return the desired part.
type AddressPartFunc func(addr string) string

type addressPartEntry struct {
	fn       AddressPartFunc
	requires string
}

// RegisterAddressPart adds an address-part tag (e.g. ":localpart",
// ":user"). name MUST include the leading colon.
func (r *Registry) RegisterAddressPart(name string, fn AddressPartFunc, requires string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.addressParts == nil {
		r.addressParts = map[string]addressPartEntry{}
	}
	r.addressParts[name] = addressPartEntry{fn: fn, requires: requires}
	if requires != "" {
		r.caps[requires] = true
	}
}

// LookupAddressPart returns the function for an address-part tag.
func (r *Registry) LookupAddressPart(name string) (AddressPartFunc, string, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	e, ok := r.addressParts[name]
	if !ok {
		return nil, "", false
	}
	return e.fn, e.requires, true
}

// ErrUnknown is returned by validation when a command or test is not in
// the registry.
type ErrUnknown struct {
	Kind string // "action" or "test"
	Name string
}

func (e *ErrUnknown) Error() string { return fmt.Sprintf("unknown %s %q", e.Kind, e.Name) }

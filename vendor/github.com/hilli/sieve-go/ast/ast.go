// Package ast defines the Sieve abstract syntax tree.
//
// A Script is a sequence of Commands. A Command has a name, positional
// and tagged arguments, an optional test (for control-flow commands), and
// an optional block of nested commands. Tests have the same shape as
// commands but produce a boolean and never have a block.
//
// The AST is intentionally minimal and uniform: command and test names are
// stored as strings rather than typed constants so that the parser does
// not need to know which extensions are loaded. Semantic validation
// happens later, against the registry.
package ast

import "github.com/hilli/sieve-go/token"

// Position is a 1-based line/column in the source.
type Position struct {
	Line int
	Col  int
}

func PosFrom(t token.Token) Position { return Position{Line: t.Line, Col: t.Col} }

// Script is a parsed Sieve script.
type Script struct {
	Commands []*Command
}

// Command is one statement: an identifier followed by arguments and either
// a ";" or a block. For control-flow commands (if/elsif/else) the Test
// field is populated.
type Command struct {
	Name     string
	Pos      Position
	Args     Arguments
	Test     *Test      // for if/elsif; nil otherwise
	Block    []*Command // for if/elsif/else and any future block command; nil otherwise
	HasBlock bool       // distinguishes empty block "{ }" from no block at all
}

// Test is a boolean expression used inside if/elsif and combinators
// (allof/anyof/not).
type Test struct {
	Name     string
	Pos      Position
	Args     Arguments
	Children []*Test // for allof/anyof/not
}

// Arguments holds positional and tagged arguments in source order.
// Positional values may be StringValue, NumberValue, or StringListValue.
// Order preserves the interleaving of tags and positional arguments so
// that value-bearing tags (e.g. :comparator "i;octet", :content "text",
// :over 1K) can be paired with the positional that follows them.
type Arguments struct {
	Tags       []TaggedArg
	Positional []Value
	Order      []ArgRef
}

// ArgKind labels a slot in Arguments.Order.
type ArgKind int

const (
	KindTag ArgKind = iota
	KindPositional
)

// ArgRef is one entry in Arguments.Order pointing at either Tags[Idx] or
// Positional[Idx].
type ArgRef struct {
	Kind ArgKind
	Idx  int
}

// ValueAfterTag returns the positional value that immediately follows the
// first tag named name (case-insensitive), or nil if either the tag is
// absent or nothing follows it before the next tag / end of arguments.
func (a *Arguments) ValueAfterTag(name string) Value {
	for i, ref := range a.Order {
		if ref.Kind != KindTag {
			continue
		}
		if !eqFold(a.Tags[ref.Idx].Name, name) {
			continue
		}
		if i+1 < len(a.Order) && a.Order[i+1].Kind == KindPositional {
			return a.Positional[a.Order[i+1].Idx]
		}
		return nil
	}
	return nil
}

// HasTag reports whether a tag with the given name (case-insensitive) is
// present in Tags.
func (a *Arguments) HasTag(name string) bool {
	for _, t := range a.Tags {
		if eqFold(t.Name, name) {
			return true
		}
	}
	return false
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

// TaggedArg is a :tag argument. RFC 5228 tags can either be bare flags
// (e.g. :is) or carry a positional argument that follows (e.g.
// :comparator "i;ascii-casemap"). The follow-on argument is left in
// Positional in source order; the registry interprets the relationship.
type TaggedArg struct {
	Name string // includes leading ":"
	Pos  Position
}

// Value is any positional argument value.
type Value interface{ valueNode() }

type StringValue struct {
	Value string
	Pos   Position
}

type NumberValue struct {
	// Canonical byte count (K/M/G already applied by the lexer).
	Value uint64
	Pos   Position
}

type StringListValue struct {
	Values []string
	Pos    Position
}

func (StringValue) valueNode()     {}
func (NumberValue) valueNode()     {}
func (StringListValue) valueNode() {}

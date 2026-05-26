package interpreter

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/hilli/sieve-go/ast"
	"github.com/hilli/sieve-go/registry"
)

// valueBearingTags lists tags whose value is the positional that
// immediately follows them in source order. The list MUST stay in sync
// with the set of tags any bundled extension consumes a positional for.
// Callers that build positional argument lists from args.Positional use
// FreePositional below to skip these consumed slots.
var valueBearingTags = []string{
	":comparator", ":content", ":flags", ":index",
	":count", ":value", // relational (RFC 5231)
	":days", ":subject", ":from", ":handle", ":addresses", // vacation
}

// FreePositional returns the subset of args.Positional that is NOT the
// value of any value-bearing tag. Order is preserved.
func FreePositional(args *ast.Arguments) []ast.Value {
	consumed := consumedPositional(args)
	if len(consumed) == 0 {
		return args.Positional
	}
	out := make([]ast.Value, 0, len(args.Positional))
	for i, v := range args.Positional {
		if consumed[i] {
			continue
		}
		out = append(out, v)
	}
	return out
}

func consumedPositional(args *ast.Arguments) map[int]bool {
	var consumed map[int]bool
	for i, ref := range args.Order {
		if ref.Kind != ast.KindTag {
			continue
		}
		if !isValueBearing(args.Tags[ref.Idx].Name) {
			continue
		}
		if i+1 < len(args.Order) && args.Order[i+1].Kind == ast.KindPositional {
			if consumed == nil {
				consumed = map[int]bool{}
			}
			consumed[args.Order[i+1].Idx] = true
		}
	}
	return consumed
}

func isValueBearing(name string) bool {
	for _, t := range valueBearingTags {
		if strings.EqualFold(t, name) {
			return true
		}
	}
	return false
}

// SetMatchFunc decides whether the (sources, keys) tuple satisfies the
// match-type/comparator/relational selection in args. Tests collect
// source values and the key list and call the matcher exactly once.
type SetMatchFunc func(sources, keys []string) bool

// LookupSetMatcher is the list-level counterpart of LookupMatcher.
// It honours :comparator, :is/:contains/:matches/:regex (and any other
// registered match type), AND the relational :count/:value tags
// (RFC 5231). For non-relational matches the returned func iterates
// sources × keys with the pairwise matcher; for :count it compares the
// number of sources against the first key; for :value it compares
// each (source, key) pair with the relational operator.
func LookupSetMatcher(ctx registry.Context, args *ast.Arguments) SetMatchFunc {
	// Relational :count
	if v := args.ValueAfterTag(":count"); v != nil {
		op, ok := v.(ast.StringValue)
		if !ok {
			return func([]string, []string) bool { return false }
		}
		return func(srcs, keys []string) bool {
			for _, k := range keys {
				n, err := strconv.Atoi(k)
				if err != nil {
					continue
				}
				if relCompare(int64(len(srcs)), int64(n), op.Value) {
					return true
				}
			}
			return false
		}
	}
	// Relational :value
	if v := args.ValueAfterTag(":value"); v != nil {
		op, ok := v.(ast.StringValue)
		if !ok {
			return func([]string, []string) bool { return false }
		}
		return func(srcs, keys []string) bool {
			for _, s := range srcs {
				for _, k := range keys {
					if relValueCompare(s, k, op.Value) {
						return true
					}
				}
			}
			return false
		}
	}
	// Non-relational: wrap the pairwise matcher.
	m := LookupMatcher(ctx, args)
	return func(srcs, keys []string) bool {
		for _, s := range srcs {
			for _, k := range keys {
				if m(s, k) {
					return true
				}
			}
		}
		return false
	}
}

// Relational operator names per RFC 5231 §4.
const (
	relGT = "gt"
	relGE = "ge"
	relLT = "lt"
	relLE = "le"
	relEQ = "eq"
	relNE = "ne"
)

func relCompare[T int64 | float64](a, b T, op string) bool {
	switch strings.ToLower(op) {
	case relGT:
		return a > b
	case relGE:
		return a >= b
	case relLT:
		return a < b
	case relLE:
		return a <= b
	case relEQ:
		return a == b
	case relNE:
		return a != b
	}
	return false
}

// relValueCompare compares two strings using the relational :value
// operator. If both parse as integers we compare numerically; otherwise
// we fall back to byte-wise lexicographic comparison (RFC 5231 §3.2
// "i;ascii-numeric" specifics; for full compliance we'd dispatch the
// chosen comparator's collation, but this covers the common cases).
func relValueCompare(a, b, op string) bool {
	if an, errA := strconv.ParseInt(a, 10, 64); errA == nil {
		if bn, errB := strconv.ParseInt(b, 10, 64); errB == nil {
			return relCompare(an, bn, op)
		}
	}
	switch strings.ToLower(op) {
	case relGT:
		return a > b
	case relGE:
		return a >= b
	case relLT:
		return a < b
	case relLE:
		return a <= b
	case relEQ:
		return a == b
	case relNE:
		return a != b
	}
	return false
}

// ValidateRelationalOperator returns an error if op is not one of the
// six relational operators. Used by the relational extension at
// registration time.
func ValidateRelationalOperator(op string) error {
	switch strings.ToLower(op) {
	case relGT, relGE, relLT, relLE, relEQ, relNE:
		return nil
	}
	return fmt.Errorf("relational: unknown operator %q (want gt/ge/lt/le/eq/ne)", op)
}

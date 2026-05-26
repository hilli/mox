// Package variables implements the Sieve "variables" extension
// (RFC 5229). It adds:
//
//   - the `set` action with modifiers :lower, :upper, :lowerfirst,
//     :upperfirst, :length, :quotewildcard;
//   - the `string` test with the standard match-type and comparator tags.
//
// Variable expansion of `${name}` and `${0}..${9}` inside string
// arguments is performed by the interpreter at dispatch time, so any
// action or test sees already-substituted strings.
//
// Importing the package for its side effects registers the extension on
// the default interpreter. For a custom interpreter call Register.
package variables

import (
	"fmt"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/hilli/sieve-go"
	"github.com/hilli/sieve-go/ast"
	"github.com/hilli/sieve-go/interpreter"
	"github.com/hilli/sieve-go/registry"
)

// Capability is the string scripts must `require` to use variables.
const Capability = "variables"

// Register installs the extension on the given interpreter.
func Register(i *sieve.Interpreter) {
	i.Registry().RegisterAction("set", actionSet, Capability)
	i.Registry().RegisterTest("string", testString, Capability)
}

func init() { Register(sieve.Default()) }

// actionSet implements `set [MODIFIER]* "name" "value"`.
func actionSet(ctx registry.Context, args *ast.Arguments) error {
	if len(args.Positional) < 2 {
		return fmt.Errorf("set: expected variable name and value")
	}
	name, ok := args.Positional[len(args.Positional)-2].(ast.StringValue)
	if !ok {
		return fmt.Errorf("set: variable name must be a string")
	}
	val, ok := args.Positional[len(args.Positional)-1].(ast.StringValue)
	if !ok {
		return fmt.Errorf("set: value must be a string")
	}
	if !validName(name.Value) {
		return fmt.Errorf("set: invalid variable name %q", name.Value)
	}
	v := applyModifiers(val.Value, args)
	ctx.Variables().Set(name.Value, v)
	return nil
}

// Modifier precedence per RFC 5229 §4 table 1. We apply lowest
// precedence first so the highest precedence wins (matches the RFC's
// "modifier with highest precedence is applied last" rule).
var modifierOrder = []struct {
	tag   string
	apply func(string) string
}{
	{":length", func(s string) string { return strconv.Itoa(utf8.RuneCountInString(s)) }},
	{":quotewildcard", quoteWildcard},
	{":lowerfirst", lowerFirst},
	{":upperfirst", upperFirst},
	{":lower", strings.ToLower},
	{":upper", strings.ToUpper},
}

func applyModifiers(s string, args *ast.Arguments) string {
	for _, m := range modifierOrder {
		if args.HasTag(m.tag) {
			s = m.apply(s)
		}
	}
	return s
}

func lowerFirst(s string) string {
	if s == "" {
		return s
	}
	r, size := utf8.DecodeRuneInString(s)
	return string(unicode.ToLower(r)) + s[size:]
}

func upperFirst(s string) string {
	if s == "" {
		return s
	}
	r, size := utf8.DecodeRuneInString(s)
	return string(unicode.ToUpper(r)) + s[size:]
}

func quoteWildcard(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	for i := 0; i < len(s); i++ {
		if s[i] == '*' || s[i] == '?' || s[i] == '\\' {
			b.WriteByte('\\')
		}
		b.WriteByte(s[i])
	}
	return b.String()
}

func validName(s string) bool {
	if s == "" {
		return false
	}
	for i, r := range s {
		switch {
		case r == '_':
		case r >= 'a' && r <= 'z':
		case r >= 'A' && r <= 'Z':
		case i > 0 && r >= '0' && r <= '9':
		default:
			return false
		}
	}
	return true
}

// testString implements `string [MATCH-TYPE] [COMPARATOR]
// <source: string-list> <key-list: string-list>`.
func testString(ctx registry.Context, args *ast.Arguments, _ []*ast.Test) (bool, error) {
	if len(args.Positional) < 2 {
		return false, fmt.Errorf("string: expected source and key lists")
	}
	src, err := stringsOf(args.Positional[len(args.Positional)-2])
	if err != nil {
		return false, fmt.Errorf("string: source: %w", err)
	}
	keys, err := stringsOf(args.Positional[len(args.Positional)-1])
	if err != nil {
		return false, fmt.Errorf("string: keys: %w", err)
	}
	match := interpreter.LookupMatcher(ctx, args)
	for _, s := range src {
		for _, k := range keys {
			if match(s, k) {
				return true, nil
			}
		}
	}
	return false, nil
}

func stringsOf(v ast.Value) ([]string, error) {
	switch x := v.(type) {
	case ast.StringValue:
		return []string{x.Value}, nil
	case ast.StringListValue:
		return x.Values, nil
	}
	return nil, fmt.Errorf("expected string or string-list")
}

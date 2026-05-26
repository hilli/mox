package interpreter

import (
	"strings"

	"github.com/hilli/sieve-go/ast"
	"github.com/hilli/sieve-go/registry"
)

// ExpandString performs RFC 5229 §3 variable substitution on s using
// vars. Unknown names expand to "". Recognised forms:
//
//	${name}      — named variable
//	${0}..${9}   — numeric :matches capture
//	${  name }   — whitespace inside the braces is ignored
//
// A backslash before the leading "$" escapes the substitution.
func ExpandString(s string, vars *registry.Variables) string {
	if vars == nil || !strings.Contains(s, "${") {
		return s
	}
	var b strings.Builder
	b.Grow(len(s))
	i := 0
	for i < len(s) {
		if s[i] == '\\' && i+1 < len(s) && s[i+1] == '$' {
			b.WriteByte('$')
			i += 2
			continue
		}
		if s[i] == '$' && i+1 < len(s) && s[i+1] == '{' {
			end := strings.IndexByte(s[i+2:], '}')
			if end < 0 {
				b.WriteByte(s[i])
				i++
				continue
			}
			name := strings.TrimSpace(s[i+2 : i+2+end])
			b.WriteString(vars.Get(name))
			i += 2 + end + 1
			continue
		}
		b.WriteByte(s[i])
		i++
	}
	return b.String()
}

// expandArgs returns a copy of args with every string positional /
// string-list element expanded against vars. Tags themselves don't
// carry values directly (the values follow in Positional), so we just
// walk Positional.
func expandArgs(args *ast.Arguments, vars *registry.Variables) *ast.Arguments {
	if vars == nil {
		return args
	}
	cp := *args
	cp.Positional = make([]ast.Value, len(args.Positional))
	changed := false
	for i, v := range args.Positional {
		switch x := v.(type) {
		case ast.StringValue:
			ex := ExpandString(x.Value, vars)
			if ex != x.Value {
				changed = true
			}
			cp.Positional[i] = ast.StringValue{Value: ex, Pos: x.Pos}
		case ast.StringListValue:
			ns := make([]string, len(x.Values))
			for j, s := range x.Values {
				ex := ExpandString(s, vars)
				ns[j] = ex
				if ex != s {
					changed = true
				}
			}
			cp.Positional[i] = ast.StringListValue{Values: ns, Pos: x.Pos}
		default:
			cp.Positional[i] = v
		}
	}
	if !changed {
		return args
	}
	return &cp
}

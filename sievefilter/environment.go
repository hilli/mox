// Sieve "environment" extension (RFC 5183).
//
// Mox owns this extension because environment values are inherently provided
// by the host. The extension is registered with sieve-go's default interpreter
// at package init.
//
// The test syntax is:
//
//	environment [COMPARATOR] [MATCH-TYPE] <name: string> <key-list: string-list>
//
// The host supplies values for known names via an EnvironmentProvider on the
// sieve.Handler. Unknown items make the test fail (per RFC 5183 §4).

package sievefilter

import (
	"fmt"

	sieve "github.com/hilli/sieve-go"
	"github.com/hilli/sieve-go/ast"
	"github.com/hilli/sieve-go/interpreter"
	"github.com/hilli/sieve-go/registry"
)

// CapabilityEnvironment is the Sieve "environment" capability string.
const CapabilityEnvironment = "environment"

// EnvironmentProvider is implemented by host handlers that can supply Sieve
// "environment" item values. Unknown items must return ok=false to make the
// test fail per RFC 5183 §4.
type EnvironmentProvider interface {
	SieveEnvironment(name string) (value string, ok bool)
}

func init() {
	RegisterEnvironment(sieve.Default())
}

// RegisterEnvironment registers the "environment" test with the given
// interpreter. Hosts using a custom interpreter (e.g. per-tenant or per-account)
// should call this explicitly.
func RegisterEnvironment(i *sieve.Interpreter) {
	i.Registry().RegisterTest("environment", environmentTest, CapabilityEnvironment)
}

func environmentTest(ctx registry.Context, args *ast.Arguments, _ []*ast.Test) (bool, error) {
	if len(args.Positional) != 2 {
		return false, fmt.Errorf("environment: expected 2 positional arguments, got %d", len(args.Positional))
	}
	nameVal, ok := args.Positional[0].(ast.StringValue)
	if !ok {
		return false, fmt.Errorf("environment: first argument must be a string")
	}
	keys, ok := stringList(args.Positional[1])
	if !ok {
		return false, fmt.Errorf("environment: second argument must be a string or string list")
	}
	p, ok := ctx.Handler().(EnvironmentProvider)
	if !ok {
		// Per RFC 5183: unknown items make the test fail; no environment
		// provider is equivalent to "no items known".
		return false, nil
	}
	value, known := p.SieveEnvironment(nameVal.Value)
	if !known {
		return false, nil
	}
	matcher := interpreter.LookupMatcher(ctx, args)
	for _, k := range keys {
		if matcher(value, k) {
			return true, nil
		}
	}
	return false, nil
}

func stringList(v ast.Value) ([]string, bool) {
	switch x := v.(type) {
	case ast.StringValue:
		return []string{x.Value}, true
	case ast.StringListValue:
		return x.Values, true
	}
	return nil, false
}

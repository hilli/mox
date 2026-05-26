// Package relational implements the Sieve "relational" extension
// (RFC 5231). It adds the match-type tags `:count` and `:value`, each
// followed by a relational operator string ("gt", "ge", "lt", "le",
// "eq", "ne"). Combined with the standard comparators, these allow
// scripts to do numeric and arithmetic comparisons:
//
//	require ["relational"];
//	if header :value "gt" :comparator "i;ascii-numeric"
//	         "X-Priority" "5" { fileinto "Low"; }
//	if address :count "ge" "to" "5" { fileinto "ManyRecipients"; }
//
// The actual relational logic lives in the interpreter (see
// LookupSetMatcher) because it has to short-circuit the normal
// pairwise iteration. This package only registers the capability and
// the two tag names so scripts validate.
package relational

import (
	"fmt"

	"github.com/hilli/sieve-go"
	"github.com/hilli/sieve-go/interpreter"
	"github.com/hilli/sieve-go/registry"
)

const Capability = "relational"

// Register installs the relational match-type tags.
func Register(i *sieve.Interpreter) {
	r := i.Registry()
	// The actual semantics are implemented in LookupSetMatcher; here we
	// only register so :count / :value validate. The placeholder funcs
	// will fire only if a caller somehow bypasses LookupSetMatcher; they
	// fail safe by returning false.
	stub := func(string, string) bool { return false }
	r.RegisterMatchType(":count", registry.MatchTypeFunc(stub), Capability)
	r.RegisterMatchType(":value", registry.MatchTypeFunc(stub), Capability)
}

func init() { Register(sieve.Default()) }

// ValidateOperator returns an error if op is not one of the six
// relational operators recognised by RFC 5231. Provided as a convenience
// for hosts that want to pre-validate.
func ValidateOperator(op string) error {
	if err := interpreter.ValidateRelationalOperator(op); err != nil {
		return fmt.Errorf("%w", err)
	}
	return nil
}

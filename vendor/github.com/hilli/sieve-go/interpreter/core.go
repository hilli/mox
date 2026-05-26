package interpreter

import (
	"fmt"
	"net/mail"
	"strings"

	"github.com/hilli/sieve-go/ast"
	"github.com/hilli/sieve-go/registry"
)

// RegisterCore registers the RFC 5228 built-in actions, tests, and match
// types onto the given registry. None of these require a capability —
// they are always available.
func RegisterCore(r *registry.Registry) {
	// Actions.
	r.RegisterAction("keep", actionKeep, "")
	r.RegisterAction("discard", actionDiscard, "")
	r.RegisterAction("redirect", actionRedirect, "")

	// Tests.
	r.RegisterTest("address", testAddress, "")
	r.RegisterTest("header", testHeader, "")
	r.RegisterTest("exists", testExists, "")
	r.RegisterTest("size", testSize, "")

	// Match types. Default per RFC 5228 §2.7.1 is :is; the lookup helper
	// falls back to :is if no match-type tag is present.
	r.RegisterMatchType(":is", matchIs, "")
	r.RegisterMatchType(":contains", matchContains, "")
	r.RegisterMatchType(":matches", matchMatches, "")

	// Comparators (RFC 5228 §2.7.3). i;ascii-casemap is the default;
	// i;octet is the only other mandatory-to-implement comparator.
	r.RegisterComparator("i;ascii-casemap", asciiCasemap{}, "")
	r.RegisterComparator("i;octet", octet{}, "")

	// Address parts (RFC 5228 §2.7.4). Extensions like subaddress add more.
	r.RegisterAddressPart(":all", func(a string) string { return a }, "")
	r.RegisterAddressPart(":localpart", addressLocal, "")
	r.RegisterAddressPart(":domain", addressDomain, "")
}

func addressLocal(a string) string {
	if at := strings.LastIndexByte(a, '@'); at >= 0 {
		return a[:at]
	}
	return a
}

func addressDomain(a string) string {
	if at := strings.LastIndexByte(a, '@'); at >= 0 {
		return a[at+1:]
	}
	return ""
}

// ---------- actions ----------

// KeepWithFlagsHandler is the optional sub-interface for hosts that want
// to receive `keep :flags ["\\Seen", ...]` per RFC 5232 §3.3. When a
// script uses :flags on keep, the host MUST implement this interface or
// the action errors.
type KeepWithFlagsHandler interface {
	KeepWithFlags(flags []string) error
}

func actionKeep(ctx registry.Context, args *ast.Arguments) error {
	ctx.MarkExplicitAction()
	flags, _, err := extractKeepFlags(args, "keep")
	if err != nil {
		return err
	}
	if flags != nil {
		h, ok := ctx.Handler().(KeepWithFlagsHandler)
		if !ok {
			return fmt.Errorf("keep :flags requires a handler implementing KeepWithFlagsHandler")
		}
		return h.KeepWithFlags(flags)
	}
	return ctx.Handler().Keep()
}

func extractKeepFlags(args *ast.Arguments, name string) ([]string, int, error) {
	for i, ref := range args.Order {
		if ref.Kind != registryArgKindTag {
			continue
		}
		if !strings.EqualFold(args.Tags[ref.Idx].Name, ":flags") {
			continue
		}
		if i+1 >= len(args.Order) || args.Order[i+1].Kind != registryArgKindPositional {
			return nil, -1, fmt.Errorf("%s :flags requires a string or string list argument", name)
		}
		pIdx := args.Order[i+1].Idx
		raw, ok := stringsOf(args.Positional[pIdx])
		if !ok {
			return nil, -1, fmt.Errorf("%s :flags argument must be a string or string list", name)
		}
		var flags []string
		for _, v := range raw {
			flags = append(flags, strings.Fields(v)...)
		}
		if flags == nil {
			flags = []string{}
		}
		return flags, pIdx, nil
	}
	return nil, -1, nil
}

// Local aliases so we don't have to import ast in this dispatch helper
// from every file that mentions it.
const (
	registryArgKindTag        = ast.KindTag
	registryArgKindPositional = ast.KindPositional
)

func actionDiscard(ctx registry.Context, args *ast.Arguments) error {
	ctx.MarkExplicitAction()
	return ctx.Handler().Discard()
}

func actionRedirect(ctx registry.Context, args *ast.Arguments) error {
	if len(args.Positional) != 1 {
		return fmt.Errorf("redirect: expected 1 string argument")
	}
	addr, ok := args.Positional[0].(ast.StringValue)
	if !ok {
		return fmt.Errorf("redirect: expected string argument")
	}
	ctx.MarkExplicitAction()
	return ctx.Handler().Redirect(addr.Value)
}

// ---------- tests ----------

// testHeader implements `header [MATCH-TYPE] <header-names> <key-list>`.
func testHeader(ctx registry.Context, args *ast.Arguments, _ []*ast.Test) (bool, error) {
	names, keys, err := twoStringLists(args, "header")
	if err != nil {
		return false, err
	}
	matcher := LookupSetMatcher(ctx, args)
	msg := ctx.Message()
	var values []string
	for _, hn := range names {
		values = append(values, msg.Header(hn)...)
	}
	return matcher(values, keys), nil
}

// testAddress implements `address [ADDRESS-PART] [MATCH-TYPE] <header-list> <key-list>`.
func testAddress(ctx registry.Context, args *ast.Arguments, _ []*ast.Test) (bool, error) {
	names, keys, err := twoStringLists(args, "address")
	if err != nil {
		return false, err
	}
	matcher := LookupSetMatcher(ctx, args)
	ap := AddressPart(ctx, args)
	msg := ctx.Message()
	var parts []string
	for _, hn := range names {
		for _, raw := range msg.Header(hn) {
			addrs, err := mail.ParseAddressList(raw)
			if err != nil {
				continue
			}
			for _, a := range addrs {
				parts = append(parts, ap(a.Address))
			}
		}
	}
	return matcher(parts, keys), nil
}

// testEnvelope mirrors testAddress but reads from msg.Envelope.
func testEnvelope(ctx registry.Context, args *ast.Arguments, _ []*ast.Test) (bool, error) {
	names, keys, err := twoStringLists(args, "envelope")
	if err != nil {
		return false, err
	}
	matcher := LookupSetMatcher(ctx, args)
	ap := AddressPart(ctx, args)
	msg := ctx.Message()
	var parts []string
	for _, hn := range names {
		for _, raw := range msg.Envelope(hn) {
			parts = append(parts, ap(raw))
		}
	}
	return matcher(parts, keys), nil
}

// TestEnvelope is exposed so the envelope extension package can register
// it without duplicating logic.
var TestEnvelope = testEnvelope

// TestHeader, TestAddress, TestExists are exposed so the mime extension
// (RFC 5703) can delegate to the core implementation when a script does
// not use the :mime / :anychild tags.
var (
	TestHeader  = testHeader
	TestAddress = testAddress
	TestExists  = testExists
)

// testExists is true iff every named header is present at least once.
func testExists(ctx registry.Context, args *ast.Arguments, _ []*ast.Test) (bool, error) {
	if len(args.Positional) != 1 {
		return false, fmt.Errorf("exists: expected 1 argument")
	}
	names, ok := stringsOf(args.Positional[0])
	if !ok {
		return false, fmt.Errorf("exists: expected string or string list")
	}
	msg := ctx.Message()
	for _, n := range names {
		if len(msg.Header(n)) == 0 {
			return false, nil
		}
	}
	return true, nil
}

// testSize implements `size :over N` / `size :under N`.
func testSize(ctx registry.Context, args *ast.Arguments, _ []*ast.Test) (bool, error) {
	if len(args.Positional) != 1 {
		return false, fmt.Errorf("size: expected 1 number argument")
	}
	n, ok := args.Positional[0].(ast.NumberValue)
	if !ok {
		return false, fmt.Errorf("size: expected number")
	}
	sz := uint64(ctx.Message().Size())
	for _, tg := range args.Tags {
		switch strings.ToLower(tg.Name) {
		case ":over":
			return sz > n.Value, nil
		case ":under":
			return sz < n.Value, nil
		}
	}
	return false, fmt.Errorf("size: requires :over or :under")
}

// ---------- helpers ----------

// LookupMatcher returns the matcher function selected by the first
// match-type tag in args; defaults to :is when no match-type tag is
// present. It honours the :comparator tag for the built-in match types
// (:is/:contains/:matches) by binding the chosen Comparator, and pushes
// :matches captures into ctx.Variables() so RFC 5229 ${1}..${9} work.
// Extension match types (e.g. :regex) keep their registered semantics.
func LookupMatcher(ctx registry.Context, args *ast.Arguments) registry.MatchTypeFunc {
	reg := ctx.(*state).reg

	compName := "i;ascii-casemap"
	if v := args.ValueAfterTag(":comparator"); v != nil {
		if sv, ok := v.(ast.StringValue); ok {
			compName = sv.Value
		}
	}
	comp, _, ok := reg.LookupComparator(compName)
	if !ok {
		comp = asciiCasemap{}
	}
	fold := compName == "" || compName == "i;ascii-casemap"

	for _, tg := range args.Tags {
		name := strings.ToLower(tg.Name)
		switch name {
		case ":is":
			return func(s, k string) bool { return comp.Equal(s, k) }
		case ":contains":
			return func(s, k string) bool { return comp.Contains(s, k) }
		case ":matches":
			return func(s, k string) bool {
				caps, ok := matchAndCapture(s, k, fold)
				if ok {
					ctx.Variables().SetCaptures(caps)
				}
				return ok
			}
		}
		if fn, _, ok := reg.LookupMatchType(name); ok {
			return fn
		}
	}
	return func(s, k string) bool { return comp.Equal(s, k) }
}

func twoStringLists(args *ast.Arguments, name string) ([]string, []string, error) {
	pos := FreePositional(args)
	if len(pos) != 2 {
		return nil, nil, fmt.Errorf("%s: expected 2 positional arguments, got %d", name, len(pos))
	}
	a, ok := stringsOf(pos[0])
	if !ok {
		return nil, nil, fmt.Errorf("%s: first argument must be string or string list", name)
	}
	b, ok := stringsOf(pos[1])
	if !ok {
		return nil, nil, fmt.Errorf("%s: second argument must be string or string list", name)
	}
	return a, b, nil
}

func addressPartString(addr string, p addressPart) string {
	at := strings.LastIndexByte(addr, '@')
	switch p {
	case addrLocal:
		if at < 0 {
			return addr
		}
		return addr[:at]
	case addrDomain:
		if at < 0 {
			return ""
		}
		return addr[at+1:]
	default:
		return addr
	}
}

// matchIs/matchContains/matchMatches implement the RFC 5228 builtin
// match types using the default i;ascii-casemap comparator. These are
// retained for compatibility with extensions that registered them
// directly; LookupMatcher builds comparator-aware closures dynamically.
func matchIs(s, key string) bool       { return strings.EqualFold(s, key) }
func matchContains(s, key string) bool { return strings.Contains(strings.ToLower(s), strings.ToLower(key)) }
func matchMatches(s, key string) bool  { return wildcardMatch(s, key) }

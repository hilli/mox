// Package body implements the Sieve "body" extension (RFC 5173).
//
// `body [BODY-TRANSFORM] [MATCH-TYPE] <key-list>` tests whether the
// transformed message body matches any of the keys.
//
// Supported body transforms:
//
//   :raw   — match the body bytes as-is (default if no transform given).
//   :text  — same as :raw for plain text messages. A real MIME-aware
//            implementation would decode and concatenate text/* parts;
//            documented as a known limitation.
//   :content "type/subtype" — iterates the MIME parts exposed by
//            message.MIMEProvider and tests the body of each part whose
//            Content-Type starts with the prefix. An empty prefix
//            matches every part. Hosts that do not implement
//            MIMEProvider get zero parts and the test is false.
package body

import (
	"fmt"
	"io"
	"strings"

	"github.com/hilli/sieve-go"
	"github.com/hilli/sieve-go/ast"
	"github.com/hilli/sieve-go/interpreter"
	"github.com/hilli/sieve-go/message"
	"github.com/hilli/sieve-go/registry"
)

const Capability = "body"

func Register(i *sieve.Interpreter) {
	i.Registry().RegisterTest("body", test, Capability)
}

func init() { Register(sieve.Default()) }

func test(ctx registry.Context, args *ast.Arguments, _ []*ast.Test) (bool, error) {
	// :content takes a string value; positionals that follow it belong
	// to the tag, not the key list.
	var contentPrefix string
	hasContent := false
	if args.HasTag(":content") {
		hasContent = true
		v := args.ValueAfterTag(":content")
		sv, ok := v.(ast.StringValue)
		if !ok {
			return false, fmt.Errorf("body :content requires a string argument")
		}
		contentPrefix = sv.Value
	}
	keys, err := keyList(args, hasContent)
	if err != nil {
		return false, err
	}
	matcher := interpreter.LookupMatcher(ctx, args)

	if hasContent {
		mp, ok := ctx.Message().(message.MIMEProvider)
		if !ok {
			return false, nil
		}
		for _, p := range mp.MIMEParts() {
			if !contentTypeMatches(p.ContentType(), contentPrefix) {
				continue
			}
			b, _ := io.ReadAll(p.Body())
			s := string(b)
			for _, k := range keys {
				if matcher(s, k) {
					return true, nil
				}
			}
		}
		return false, nil
	}

	bodyBytes, err := io.ReadAll(ctx.Message().Body())
	if err != nil {
		return false, fmt.Errorf("body: read: %w", err)
	}
	value := string(bodyBytes)
	for _, k := range keys {
		if matcher(value, k) {
			return true, nil
		}
	}
	return false, nil
}

// keyList extracts the key argument. When :content is present it owns
// the positional that immediately follows it; the remaining positionals
// form the key list.
func keyList(args *ast.Arguments, hasContent bool) ([]string, error) {
	skip := -1
	if hasContent {
		for i, ref := range args.Order {
			if ref.Kind == ast.KindTag && strings.EqualFold(args.Tags[ref.Idx].Name, ":content") {
				if i+1 < len(args.Order) && args.Order[i+1].Kind == ast.KindPositional {
					skip = args.Order[i+1].Idx
				}
				break
			}
		}
	}
	remaining := make([]ast.Value, 0, len(args.Positional))
	for i, v := range args.Positional {
		if i == skip {
			continue
		}
		remaining = append(remaining, v)
	}
	if len(remaining) != 1 {
		return nil, fmt.Errorf("body: expected 1 string-list argument, got %d", len(remaining))
	}
	keys, ok := stringsOf(remaining[0])
	if !ok {
		return nil, fmt.Errorf("body: argument must be a string or string list")
	}
	return keys, nil
}

// contentTypeMatches reports whether ct matches the :content prefix.
// Per RFC 5173 §5.7: empty prefix matches everything; a bare type ("text")
// matches any subtype; a "type/sub" matches exactly.
func contentTypeMatches(ct, prefix string) bool {
	ct = strings.ToLower(strings.TrimSpace(ct))
	prefix = strings.ToLower(strings.TrimSpace(prefix))
	if prefix == "" {
		return true
	}
	if !strings.Contains(prefix, "/") {
		// type only
		slash := strings.IndexByte(ct, '/')
		if slash < 0 {
			return ct == prefix
		}
		return ct[:slash] == prefix
	}
	return ct == prefix
}

func stringsOf(v ast.Value) ([]string, bool) {
	switch x := v.(type) {
	case ast.StringValue:
		return []string{x.Value}, true
	case ast.StringListValue:
		return x.Values, true
	}
	return nil, false
}

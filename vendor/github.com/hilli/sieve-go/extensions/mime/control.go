package mime

import (
	"fmt"
	"io"
	"strings"

	"github.com/hilli/sieve-go"
	"github.com/hilli/sieve-go/ast"
	"github.com/hilli/sieve-go/interpreter"
	sievemsg "github.com/hilli/sieve-go/message"
	"github.com/hilli/sieve-go/registry"
)

// MutationHandler is the optional host interface for the body-mutating
// actions defined by RFC 5703 (replace, enclose, extracttext). Hosts
// that don't implement it will get a runtime error when scripts use
// those actions.
type MutationHandler interface {
	sieve.Handler
	// Replace replaces the current MIME part (or whole body if no part
	// loop is active) with body using the given content-type. From,
	// Subject and Type are optional supplements.
	Replace(part sievemsg.MIMEPart, body []byte, contentType, subject, from string) error
	// Enclose wraps the message in a new envelope with the supplied
	// body and headers.
	Enclose(body []byte, subject, headers string) error
	// ExtractText takes text extracted from the current MIME part and
	// stores it in the named Sieve variable.
	ExtractText(part sievemsg.MIMEPart, text string, varName string) error
}

// commandForeverypart implements the `foreverypart [:name "label"] {...}`
// loop. It walks every MIME child part (depth-first leaves) and runs the
// block once per part with the part installed as the "current" part.
func commandForeverypart(ctx registry.Context, args *ast.Arguments, block []*ast.Command, exec func([]*ast.Command) error) error {
	wantedLabel := ""
	if v := args.ValueAfterTag(":name"); v != nil {
		if sv, ok := v.(ast.StringValue); ok {
			wantedLabel = sv.Value
		}
	}
	parts := mimeParts(ctx)
	for _, p := range parts {
		restore := interpreter.SetCurrentPart(ctx, p)
		err := exec(block)
		restore()
		if err == nil {
			continue
		}
		if be, ok := err.(*registry.BreakError); ok {
			// A bare break (no label) unwinds the innermost loop; a labelled
			// break unwinds matching labels, propagating otherwise.
			if be.Label == "" || be.Label == wantedLabel {
				return nil
			}
			return be
		}
		return err
	}
	return nil
}

// actionBreak emits the sentinel BreakError. The interpreter unwinds
// out to the nearest enclosing foreverypart.
func actionBreak(_ registry.Context, args *ast.Arguments) error {
	label := ""
	if v := args.ValueAfterTag(":name"); v != nil {
		if sv, ok := v.(ast.StringValue); ok {
			label = sv.Value
		}
	}
	return &registry.BreakError{Label: label}
}

// actionExtractText copies the text body of the current MIME part into a
// Sieve variable. Syntax: `extracttext [:first <n>] [MODIFIER]* "name"`.
// Modifiers are honoured by the variables extension's interpolation
// pipeline at read time; here we just hand the raw text to the variable
// store (and to the host if it implements MutationHandler).
func actionExtractText(ctx registry.Context, args *ast.Arguments) error {
	if len(args.Positional) < 1 {
		return fmt.Errorf("extracttext: missing variable name")
	}
	// Variable name is the last positional (after any :first value).
	nameVal := args.Positional[len(args.Positional)-1]
	name, ok := nameVal.(ast.StringValue)
	if !ok {
		return fmt.Errorf("extracttext: variable name must be a string")
	}
	part := interpreter.CurrentPart(ctx)
	if part == nil {
		return fmt.Errorf("extracttext: only valid inside foreverypart")
	}
	if !isTextLike(part.ContentType()) {
		ctx.Variables().Set(name.Value, "")
		return nil
	}
	b, err := io.ReadAll(part.Body())
	if err != nil {
		return fmt.Errorf("extracttext: read part: %w", err)
	}
	text := string(b)
	if v := args.ValueAfterTag(":first"); v != nil {
		if sv, ok := v.(ast.StringValue); ok {
			n := 0
			for _, c := range sv.Value {
				if c < '0' || c > '9' {
					n = -1
					break
				}
				n = n*10 + int(c-'0')
			}
			if n > 0 && n < len(text) {
				text = text[:n]
			}
		}
	}
	ctx.Variables().Set(name.Value, text)
	if mh, ok := ctx.Handler().(MutationHandler); ok {
		return mh.ExtractText(part, text, name.Value)
	}
	return nil
}

func actionReplace(ctx registry.Context, args *ast.Arguments) error {
	body, err := lastStringPositional(args, "replace")
	if err != nil {
		return err
	}
	subject := ""
	if v := args.ValueAfterTag(":subject"); v != nil {
		if sv, ok := v.(ast.StringValue); ok {
			subject = sv.Value
		}
	}
	from := ""
	if v := args.ValueAfterTag(":from"); v != nil {
		if sv, ok := v.(ast.StringValue); ok {
			from = sv.Value
		}
	}
	contentType := ""
	if v := args.ValueAfterTag(":mime"); v != nil {
		if sv, ok := v.(ast.StringValue); ok {
			contentType = sv.Value
		}
	}
	mh, ok := ctx.Handler().(MutationHandler)
	if !ok {
		return fmt.Errorf("replace: handler does not implement mime.MutationHandler")
	}
	return mh.Replace(interpreter.CurrentPart(ctx), []byte(body), contentType, subject, from)
}

func actionEnclose(ctx registry.Context, args *ast.Arguments) error {
	body, err := lastStringPositional(args, "enclose")
	if err != nil {
		return err
	}
	subject := ""
	if v := args.ValueAfterTag(":subject"); v != nil {
		if sv, ok := v.(ast.StringValue); ok {
			subject = sv.Value
		}
	}
	headers := ""
	if v := args.ValueAfterTag(":headers"); v != nil {
		if sv, ok := v.(ast.StringValue); ok {
			headers = sv.Value
		}
	}
	mh, ok := ctx.Handler().(MutationHandler)
	if !ok {
		return fmt.Errorf("enclose: handler does not implement mime.MutationHandler")
	}
	return mh.Enclose([]byte(body), subject, headers)
}

func lastStringPositional(args *ast.Arguments, name string) (string, error) {
	if len(args.Positional) == 0 {
		return "", fmt.Errorf("%s: missing body argument", name)
	}
	s, ok := args.Positional[len(args.Positional)-1].(ast.StringValue)
	if !ok {
		return "", fmt.Errorf("%s: body must be a string", name)
	}
	return s.Value, nil
}

func isTextLike(ct string) bool {
	ct = strings.ToLower(ct)
	if ct == "" {
		return true
	}
	if slash := strings.IndexByte(ct, '/'); slash >= 0 {
		ct = ct[:slash]
	}
	return ct == "text"
}

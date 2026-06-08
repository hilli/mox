// Sieve evaluation in the IMAP-event (RFC 6785) context.
//
// IMAP events use a different action/test policy than delivery: the original
// IMAP operation always completes normally, and Sieve actions either add
// further copies (fileinto/redirect) or mark the original message \Deleted.
//
// Forbidden per RFC 6785:
//   - `reject` / `ereject` (§3.11)
//   - `vacation` (§3.11)
//   - `envelope` test (§4.6) — must error at runtime
//
// To enforce this we build a dedicated *sieve.Interpreter that registers
// only the safe extensions plus an envelope stub that errors when invoked.

package sievefilter

import (
	"context"
	"fmt"
	"strings"
	"sync"

	sieve "github.com/hilli/sieve-go"
	"github.com/hilli/sieve-go/ast"
	body "github.com/hilli/sieve-go/extensions/body"
	editheader "github.com/hilli/sieve-go/extensions/editheader"
	fileinto "github.com/hilli/sieve-go/extensions/fileinto"
	imap4flags "github.com/hilli/sieve-go/extensions/imap4flags"
	mimeext "github.com/hilli/sieve-go/extensions/mime"
	regexext "github.com/hilli/sieve-go/extensions/regex"
	relational "github.com/hilli/sieve-go/extensions/relational"
	subaddress "github.com/hilli/sieve-go/extensions/subaddress"
	variables "github.com/hilli/sieve-go/extensions/variables"
	"github.com/hilli/sieve-go/parser"
	"github.com/hilli/sieve-go/registry"

	"github.com/mjl-/mox/mlog"
)

// CapabilityIMAPSieve is the capability string advertised in ManageSieve
// SIEVE and required in IMAP-event scripts that depend on RFC 6785 features.
const CapabilityIMAPSieve = "imapsieve"

// IMAPEventCause values per RFC 6785 §4.3.
const (
	IMAPCauseAppend = "APPEND"
	IMAPCauseCopy   = "COPY"
	IMAPCauseFlag   = "FLAG"
)

var (
	imapInterpreter     *sieve.Interpreter
	imapInterpreterOnce sync.Once
)

// getIMAPInterpreter returns the lazily-initialised interpreter restricted to
// the extensions allowed by RFC 6785. Registration is done once; the
// interpreter is then immutable (per sieve-go conventions).
func getIMAPInterpreter() *sieve.Interpreter {
	imapInterpreterOnce.Do(func() {
		i := sieve.NewInterpreter()
		r := i.Registry()

		// Capabilities allowed in IMAP-event context.
		fileinto.Register(i)
		body.Register(i)
		imap4flags.Register(i)
		variables.Register(i)
		regexext.Register(i)
		mimeext.Register(i)
		subaddress.Register(i)
		relational.Register(i)
		editheader.Register(i)

		// Environment (host-supplied).
		RegisterEnvironment(i)

		// imapsieve capability is capability-only. We register a marker test
		// (unused in scripts) so HasCapability("imapsieve") is true and
		// `require ["imapsieve"];` validates.
		r.RegisterTest("imapsieve_marker", noopTest, CapabilityIMAPSieve)

		// envelope: register an erroring stub so any envelope test at runtime
		// fails the script per RFC 6785 §4.6. Scripts may still
		// `require ["envelope"]` (validation passes), but invocation errors.
		r.RegisterTest("envelope", envelopeForbidden, "envelope")

		imapInterpreter = i
	})
	return imapInterpreter
}

// noopTest is registered only so imapsieve becomes a known capability in the
// IMAP interpreter. It is not intended to be used in scripts.
func noopTest(_ registry.Context, _ *ast.Arguments, _ []*ast.Test) (bool, error) {
	return false, nil
}

// envelopeForbidden is an envelope test stub that always errors at runtime,
// per RFC 6785 §4.6.
func envelopeForbidden(_ registry.Context, _ *ast.Arguments, _ []*ast.Test) (bool, error) {
	return false, fmt.Errorf("envelope tests are not permitted in IMAP-event Sieve scripts (RFC 6785 §4.6)")
}

// IMAPEventInput is the input to ExecuteIMAPEvent.
type IMAPEventInput struct {
	Policy       Policy
	Script       []byte
	Message      *MoxMessage
	Cause        string   // APPEND, COPY, or FLAG.
	Mailbox      string   // mailbox name where event occurred.
	User         string   // imap.user
	Email        string   // imap.email
	ChangedFlags []string // for FLAG events.
	CurrentFlags []string
	Log          mlog.Log
}

// IMAPEventDecision is the outcome of an IMAP-event Sieve evaluation. The
// caller (IMAP server hook) is responsible for translating this into actual
// IMAP storage operations.
//
// Per RFC 6785:
//   - The original message in `Mailbox` remains. If `MarkDeleted` is true, the
//     caller should set \Deleted on it (optionally expunging UID-only).
//   - `FileInto` mailboxes get an *additional* copy of the message.
//   - `RedirectTo` causes the message to be (re-)sent via SMTP submission.
//   - `Flags` are applied to the original (e.g. for FLAG-cause scripts).
//   - `HeaderAdds`/`HeaderDeletes` apply only to redirect/fileinto copies
//     (transient per RFC 6785 §3.7).
type IMAPEventDecision struct {
	MarkDeleted   bool
	FileInto      []FileIntoTarget
	RedirectTo    []string
	Flags         []string
	HeaderAdds    []HeaderEdit
	HeaderDeletes []HeaderEdit
	Warning       string
}

// FileIntoTarget is a fileinto destination for IMAP-event Sieve.
type FileIntoTarget struct {
	Mailbox string
	Flags   []string
}

// ExecuteIMAPEvent compiles in.Script through the IMAP-restricted interpreter
// and runs it against in.Message. Errors during compile or run are surfaced
// to the caller; the caller decides whether to fall through with implicit
// keep semantics or surface to the client.
func ExecuteIMAPEvent(ctx context.Context, in IMAPEventInput) (IMAPEventDecision, error) {
	d := IMAPEventDecision{}
	if !in.Policy.Enabled || !in.Policy.RunOnIMAPEvents || len(in.Script) == 0 {
		return d, nil
	}
	parsedAST, err := parser.Parse(string(in.Script))
	if err != nil {
		return d, fmt.Errorf("parse: %w", err)
	}
	script, err := getIMAPInterpreter().Compile(parsedAST)
	if err != nil {
		return d, fmt.Errorf("compile: %w", err)
	}
	env := EnvironmentValues{
		"location":          "MS",
		"phase":             "post",
		"imap.cause":        in.Cause,
		"imap.mailbox":      in.Mailbox,
		"imap.user":         in.User,
		"imap.email":        in.Email,
		"imap.changedflags": strings.Join(in.ChangedFlags, " "),
	}
	h := &imapEventHandler{
		policy:       in.Policy,
		env:          env,
		currentFlags: append([]string(nil), in.CurrentFlags...),
		decision:     &d,
		log:          in.Log,
	}
	if err := runScriptWithTimeout(script, in.Message, h, in.Policy.ExecutionTimeout); err != nil {
		return d, fmt.Errorf("run: %w", err)
	}
	// Implicit keep ran inside the handler; nothing to do here.
	return d, nil
}

// imapEventHandler implements only the safe-for-IMAP subset of sieve-go's
// extension interfaces. Reject/Ereject/Vacation are deliberately not
// registered in the IMAP interpreter and therefore unreachable here.
type imapEventHandler struct {
	policy        Policy
	env           EnvironmentProvider
	currentFlags  []string
	decision      *IMAPEventDecision
	log           mlog.Log
	explicitKeep  bool
	redirectCount int
}

// sieve.Handler (registry.Handler) methods.
func (h *imapEventHandler) Keep() error {
	h.explicitKeep = true
	return nil
}

func (h *imapEventHandler) Discard() error {
	// Per RFC 6785 §3.5: original message marked \Deleted unless explicit keep.
	if !h.explicitKeep {
		h.decision.MarkDeleted = true
	}
	return nil
}

func (h *imapEventHandler) Redirect(addr string) error {
	h.redirectCount++
	if h.redirectCount > h.policy.MaxRedirects {
		return fmt.Errorf("redirect limit %d exceeded", h.policy.MaxRedirects)
	}
	h.decision.RedirectTo = append(h.decision.RedirectTo, addr)
	if !h.explicitKeep {
		h.decision.MarkDeleted = true
	}
	return nil
}

// fileinto.Handler
func (h *imapEventHandler) FileInto(mailbox string) error {
	h.decision.FileInto = append(h.decision.FileInto, FileIntoTarget{Mailbox: mailbox})
	if !h.explicitKeep {
		h.decision.MarkDeleted = true
	}
	return nil
}

// fileinto.FlagsHandler
func (h *imapEventHandler) FileIntoWithFlags(mailbox string, flags []string) error {
	h.decision.FileInto = append(h.decision.FileInto, FileIntoTarget{Mailbox: mailbox, Flags: append([]string(nil), flags...)})
	if !h.explicitKeep {
		h.decision.MarkDeleted = true
	}
	return nil
}

// imap4flags.Handler
func (h *imapEventHandler) SetFlags(flags []string) error {
	h.decision.Flags = append(h.decision.Flags[:0], flags...)
	h.currentFlags = append(h.currentFlags[:0], flags...)
	return nil
}
func (h *imapEventHandler) AddFlags(flags []string) error {
	h.decision.Flags = appendUnique(h.decision.Flags, flags...)
	h.currentFlags = appendUnique(h.currentFlags, flags...)
	return nil
}
func (h *imapEventHandler) RemoveFlags(flags []string) error {
	h.currentFlags = removeAll(h.currentFlags, flags)
	h.decision.Flags = removeAll(h.decision.Flags, flags)
	return nil
}
func (h *imapEventHandler) CurrentFlags() []string {
	return append([]string(nil), h.currentFlags...)
}

// editheader.Handler — transient per RFC 6785 §3.7; recorded in decision and
// applied only to copies (redirect/fileinto).
func (h *imapEventHandler) AddHeader(field, value string, atTop bool) error {
	h.decision.HeaderAdds = append(h.decision.HeaderAdds, HeaderEdit{Name: field, Value: value, AtTop: atTop})
	return nil
}
func (h *imapEventHandler) DeleteHeader(field string, patterns []string, _ func(value, key string) bool, index int, fromLast bool) error {
	h.decision.HeaderDeletes = append(h.decision.HeaderDeletes, HeaderEdit{Name: field, Pattern: patterns, Index: index, FromLast: fromLast})
	return nil
}

// EnvironmentProvider
func (h *imapEventHandler) SieveEnvironment(name string) (string, bool) {
	if h.env == nil {
		return "", false
	}
	return h.env.SieveEnvironment(name)
}

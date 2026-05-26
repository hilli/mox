// Delivery-time Sieve execution.
//
// ExecuteDelivery runs the active Sieve script for a recipient/account against
// an incoming message. It returns a Decision describing what the SMTP delivery
// path should do: deliver to a specific mailbox, discard, reject, redirect (and
// to where), and any flag set/keyword changes.
//
// This file does not import smtpserver. The smtpserver hook is responsible for
// translating the Decision into actual delivery/queue/addError calls. This
// keeps execution policy and side effects testable in isolation.

package sievefilter

import (
	"errors"
	"fmt"
	"log/slog"
	"time"

	sieve "github.com/hilli/sieve-go"
	"github.com/hilli/sieve-go/extensions/vacation"
	sievemsg "github.com/hilli/sieve-go/message"

	"github.com/mjl-/mox/mlog"
)

// sieveScript is a re-export of *sieve.Script to keep delivery_test.go free of
// direct sieve-go dependency for compileScript helper.
type sieveScript = sieve.Script

func compileScript(src string) (*sieveScript, error) {
	return sieve.Compile(src)
}

// Decision is the outcome of a delivery-time Sieve evaluation. Only one of
// Reject, Discard, or store-and-redirect actions applies. RedirectAddresses
// can be non-empty alongside Mailbox/Discard to support `redirect; keep;` and
// future RFC 3894 `:copy` semantics.
type Decision struct {
	Mailbox          string   // Mailbox to deliver into (defaults to inbound mailbox).
	Discard          bool     // True if message should be silently discarded.
	Rejected         bool     // True if Sieve called reject/ereject.
	RejectReason     string   // Reason from reject/ereject.
	Ereject          bool     // True for ereject (vs. reject); affects SMTP code mapping in caller.
	RedirectTo       []string // Email addresses to redirect to via queue.
	Flags            []string // IMAP flags/keywords to set on the stored message.
	Vacation         *VacationParams
	HeaderAdds       []HeaderEdit
	HeaderDeletes    []HeaderEdit
	ExecutionWarning string // non-fatal note (e.g., redirect cap reached).
}

// VacationParams holds Sieve vacation action parameters captured during eval.
type VacationParams struct {
	Reason    string
	Days      int
	Subject   string
	From      string
	Handle    string
	Addresses []string
	Mime      bool
}

// HeaderEdit captures an editheader add/delete request.
type HeaderEdit struct {
	Name    string
	Value   string
	AtTop   bool     // for add
	Pattern []string // for delete
	Index   int      // for delete; 0 means all
	FromLast bool    // for delete
}

// DeliveryInput is the input to a delivery-time Sieve evaluation.
type DeliveryInput struct {
	Policy           Policy
	Script           []byte         // Active script for the account.
	Message          *MoxMessage    // The message being delivered.
	DefaultMailbox   string         // Mailbox chosen by Mox before Sieve runs.
	Environment      EnvironmentValues
	CurrentFlags     []string // Current IMAP flags/keywords (usually empty at delivery).
	Log              mlog.Log
}

// EnvironmentValues snapshot for a single Sieve evaluation. Implements
// EnvironmentProvider via map lookups. Empty entries are treated as unknown
// (test fails) to satisfy RFC 5183.
type EnvironmentValues map[string]string

func (e EnvironmentValues) SieveEnvironment(name string) (string, bool) {
	if v, ok := e[name]; ok && v != "" {
		return v, true
	}
	return "", false
}

// ExecuteDelivery compiles and runs the script against msg with the given
// policy, returning the resulting Decision. If the script is empty or
// disabled by policy, ExecuteDelivery returns a Decision that delivers to
// DefaultMailbox with no other action.
func ExecuteDelivery(in DeliveryInput) (Decision, error) {
	d := Decision{Mailbox: in.DefaultMailbox}
	if !in.Policy.Enabled || !in.Policy.RunOnDelivery || len(in.Script) == 0 {
		return d, nil
	}
	script, err := sieve.Compile(string(in.Script))
	if err != nil {
		return d, fmt.Errorf("compile sieve script: %w", err)
	}
	h := &deliveryHandler{
		policy:       in.Policy,
		env:          in.Environment,
		currentFlags: append([]string(nil), in.CurrentFlags...),
		decision:     &d,
		log:          in.Log,
	}
	if err := runScriptWithTimeout(script, in.Message, h, in.Policy.ExecutionTimeout); err != nil {
		return d, fmt.Errorf("run sieve script: %w", err)
	}
	if h.redirectCount > in.Policy.MaxRedirects {
		d.ExecutionWarning = fmt.Sprintf("redirect limit %d exceeded", in.Policy.MaxRedirects)
	}
	return d, nil
}

// runScriptWithTimeout runs script.Run(msg, handler) in a goroutine. If the
// supplied timeout elapses, it returns context.DeadlineExceeded and the
// running script becomes orphan; the goroutine completes when the script
// finishes. sieve-go's Script.Run does not currently accept a context, so we
// cannot actually preempt the interpreter; this provides an upper-bound on
// time-blocked callers without leaving them hanging. The orphan goroutine's
// result is discarded.
//
// timeout <= 0 disables the bound.
func runScriptWithTimeout(script *sieve.Script, msg sieve.Message, handler sieve.Handler, timeout time.Duration) error {
	if timeout <= 0 {
		return script.Run(msg, handler)
	}
	done := make(chan error, 1)
	go func() {
		// Recover panics from a runaway script so the watchdog doesn't crash
		// the process.
		defer func() {
			if r := recover(); r != nil {
				done <- fmt.Errorf("sieve script panic: %v", r)
			}
		}()
		done <- script.Run(msg, handler)
	}()
	select {
	case err := <-done:
		return err
	case <-time.After(timeout):
		return fmt.Errorf("sieve script execution timed out after %s", timeout)
	}
}

// deliveryHandler implements all sieve.Handler sub-interfaces required by the
// extensions we register. It is used only for delivery-time evaluation.
type deliveryHandler struct {
	policy        Policy
	env           EnvironmentProvider
	currentFlags  []string
	decision      *Decision
	log           mlog.Log
	redirectCount int
	stopped       bool
}

// sieve.Handler (registry.Handler) methods.
func (h *deliveryHandler) Keep() error {
	// Implicit/explicit keep delivers to the default mailbox already in
	// Decision. No-op for delivery context.
	return nil
}

func (h *deliveryHandler) Discard() error {
	h.decision.Discard = true
	h.decision.Mailbox = ""
	return nil
}

func (h *deliveryHandler) Redirect(addr string) error {
	h.redirectCount++
	if h.redirectCount > h.policy.MaxRedirects {
		return fmt.Errorf("redirect limit exceeded (%d)", h.policy.MaxRedirects)
	}
	// Redirect cancels implicit keep per RFC 5228 §4.2.
	h.decision.Discard = true
	h.decision.Mailbox = ""
	h.decision.RedirectTo = append(h.decision.RedirectTo, addr)
	return nil
}

// fileinto.Handler
func (h *deliveryHandler) FileInto(mailbox string) error {
	h.decision.Mailbox = mailbox
	h.decision.Discard = false
	return nil
}

// fileinto.FlagsHandler
func (h *deliveryHandler) FileIntoWithFlags(mailbox string, flags []string) error {
	h.decision.Mailbox = mailbox
	h.decision.Discard = false
	h.decision.Flags = appendUnique(h.decision.Flags, flags...)
	return nil
}

// imap4flags.Handler
func (h *deliveryHandler) SetFlags(flags []string) error {
	h.decision.Flags = append(h.decision.Flags[:0], flags...)
	h.currentFlags = append(h.currentFlags[:0], flags...)
	return nil
}
func (h *deliveryHandler) AddFlags(flags []string) error {
	h.decision.Flags = appendUnique(h.decision.Flags, flags...)
	h.currentFlags = appendUnique(h.currentFlags, flags...)
	return nil
}
func (h *deliveryHandler) RemoveFlags(flags []string) error {
	h.currentFlags = removeAll(h.currentFlags, flags)
	h.decision.Flags = removeAll(h.decision.Flags, flags)
	return nil
}
func (h *deliveryHandler) CurrentFlags() []string {
	return append([]string(nil), h.currentFlags...)
}

// reject.Handler
func (h *deliveryHandler) Reject(reason string) error {
	h.decision.Rejected = true
	h.decision.RejectReason = reason
	h.decision.Discard = false
	h.decision.Mailbox = ""
	return nil
}

// reject.EjectHandler
func (h *deliveryHandler) Ereject(reason string) error {
	h.decision.Rejected = true
	h.decision.Ereject = true
	h.decision.RejectReason = reason
	h.decision.Discard = false
	h.decision.Mailbox = ""
	return nil
}

// vacation.Handler
func (h *deliveryHandler) Vacation(p vacation.Params) error {
	h.decision.Vacation = &VacationParams{
		Reason:    p.Reason,
		Days:      p.Days,
		Subject:   p.Subject,
		From:      p.From,
		Handle:    p.Handle,
		Addresses: append([]string(nil), p.Addresses...),
		Mime:      p.Mime,
	}
	return nil
}

// editheader.Handler
func (h *deliveryHandler) AddHeader(field, value string, atTop bool) error {
	h.decision.HeaderAdds = append(h.decision.HeaderAdds, HeaderEdit{Name: field, Value: value, AtTop: atTop})
	return nil
}
func (h *deliveryHandler) DeleteHeader(field string, patterns []string, _ func(value, key string) bool, index int, fromLast bool) error {
	h.decision.HeaderDeletes = append(h.decision.HeaderDeletes, HeaderEdit{Name: field, Pattern: patterns, Index: index, FromLast: fromLast})
	return nil
}

// EnvironmentProvider (used by Mox environment extension).
func (h *deliveryHandler) SieveEnvironment(name string) (string, bool) {
	if h.env == nil {
		return "", false
	}
	return h.env.SieveEnvironment(name)
}

// mime.MutationHandler: stub. For delivery, mutation actions buffer requests
// but we do not yet materialize a rewritten message file; the smtpserver hook
// may log a warning and skip these for now.
func (h *deliveryHandler) Replace(part sievemsg.MIMEPart, body []byte, contentType, subject, from string) error {
	h.log.Warn("sieve mime replace not yet implemented", slog.String("contentType", contentType))
	return errors.New("mime replace not yet implemented in mox")
}
func (h *deliveryHandler) Enclose(body []byte, subject, headers string) error {
	h.log.Warn("sieve mime enclose not yet implemented")
	return errors.New("mime enclose not yet implemented in mox")
}
func (h *deliveryHandler) ExtractText(part sievemsg.MIMEPart, text string, varName string) error {
	// extracttext is metadata extraction; safe to ignore.
	return nil
}

func appendUnique(dst []string, items ...string) []string {
	for _, it := range items {
		seen := false
		for _, d := range dst {
			if d == it {
				seen = true
				break
			}
		}
		if !seen {
			dst = append(dst, it)
		}
	}
	return dst
}

func removeAll(src []string, items []string) []string {
	out := src[:0]
	for _, s := range src {
		drop := false
		for _, it := range items {
			if s == it {
				drop = true
				break
			}
		}
		if !drop {
			out = append(out, s)
		}
	}
	return out
}

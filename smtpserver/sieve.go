package smtpserver

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"
	"strings"
	"time"

	"github.com/mjl-/mox/dns"
	"github.com/mjl-/mox/mlog"
	mox "github.com/mjl-/mox/mox-"
	"github.com/mjl-/mox/queue"
	"github.com/mjl-/mox/sievefilter"
	"github.com/mjl-/mox/smtp"
	"github.com/mjl-/mox/srs"
	"github.com/mjl-/mox/store"
)

// evalSieveForRecipient runs the active Sieve script (if any) for the recipient
// account in la and returns the resulting decision. The second return value
// indicates whether delivery should be skipped for this recipient because
// Sieve already handled it (reject => addError; discard => silent accept).
//
// On reject/ereject, addError is called with the appropriate SMTP code and
// the function returns (decision, true). Caller should continue to next
// recipient.
//
// On discard or any redirect-without-keep, the function returns
// (decision, true). The caller increments ndelivered for discard counts.
//
// On normal evaluation (including fileinto choosing a different mailbox),
// returns (decision, false) and caller should deliver to decision.Mailbox.
//
// If the account has no active script, or Sieve is disabled by effective
// policy, returns (nil, false) and the caller proceeds with the default
// mailbox.
func evalSieveForRecipient(
	ctx context.Context,
	log mlog.Log,
	c *conn,
	a analysis,
	dataFile *os.File,
	addError func(rcpt recipient, code int, secode string, userError bool, errmsg string),
	rcpt recipient,
) (*sievefilter.Decision, bool) {
	if a.d.acc == nil {
		return nil, false
	}
	// Resolve policy.
	var accDomain dns.Domain
	if accConf, ok := mox.Conf.Account(a.d.acc.Name); ok {
		accDomain = accConf.DNSDomain
	}
	server, dom, acc := mox.Conf.SievePolicy(a.d.acc.Name, accDomain)
	policy := sievefilter.Resolve(server, dom, acc)
	if !policy.Enabled || !policy.RunOnDelivery {
		return nil, false
	}

	// Load active script.
	scriptName, scriptContent, err := a.d.acc.SieveActiveScript()
	if err != nil {
		if !errors.Is(err, store.ErrSieveScriptNotFound) {
			log.Errorx("loading active sieve script", err)
		}
		return nil, false
	}
	if len(scriptContent) == 0 {
		return nil, false
	}

	// Build the Mox message adapter.
	envFrom := ""
	if c.mailFrom != nil {
		envFrom = c.mailFrom.String()
	}
	envTo := []string{rcpt.Addr.String()}
	mm := sievefilter.NewMoxMessage(a.d.m, dataFile, envFrom, envTo)

	// Build environment values for delivery. RFC 5183 §4.1: "domain" is the
	// primary DNS domain of the Sieve execution context, conventionally the
	// recipient's domain so scripts can test against their own domain.
	rcptDomain := mox.Conf.Static.HostnameDomain.Name()
	if !rcpt.Addr.IPDomain.Domain.IsZero() {
		rcptDomain = rcpt.Addr.IPDomain.Domain.Name()
	}
	env := sievefilter.EnvironmentValues{
		"domain":   rcptDomain,
		"host":     mox.Conf.Static.Hostname,
		"location": "MDA",
		"phase":    "during",
		"name":     "mox",
	}
	if remoteIP := remoteIPString(c); remoteIP != "" {
		env["remote-ip"] = remoteIP
	}

	dec, err := sievefilter.ExecuteDelivery(sievefilter.DeliveryInput{
		Policy:         policy,
		Script:         scriptContent,
		Message:        mm,
		DefaultMailbox: a.mailbox,
		Environment:    env,
		Log:            log,
	})
	if err != nil {
		log.Errorx("sieve execution failed", err, slog.String("script", scriptName), slog.String("account", a.d.acc.Name))
		// Failure mode.
		switch policy.FailureMode {
		case "keep":
			// Fall through with no decision: deliver to a.mailbox.
			return nil, false
		default:
			// tempfail.
			addError(rcpt, smtp.C451LocalErr, smtp.SeSys3Other0, false, "sieve filter error")
			return &dec, true
		}
	}
	if dec.ExecutionWarning != "" {
		log.Warn("sieve execution warning", slog.String("warning", dec.ExecutionWarning))
	}

	// Translate decision to SMTP behaviour.
	if dec.Rejected {
		// reject => 550 5.7.1
		code := smtp.C550MailboxUnavail
		secode := smtp.SePol7DeliveryUnauth1
		reason := dec.RejectReason
		if reason == "" {
			reason = "rejected by sieve"
		}
		addError(rcpt, code, secode, true, reason)
		return &dec, true
	}

	// editheader: apply pending header additions/deletions to the MsgPrefix
	// before any other action so subsequent operations (redirect/vacation/
	// store) all see the modified headers. Per RFC 5293, editheader actions
	// affect later actions in the same script run; the in-memory ordering of
	// Decision fields does not reflect script source order, so we apply
	// editheader uniformly before dispatch. Deletions only affect headers
	// present in MsgPrefix; original message-file headers are immutable on
	// delivery.
	applyEditHeaders(a, &dec)

	// Process redirects asynchronously through the queue. Errors here are
	// not fatal to the recipient delivery; we log and continue.
	for _, addr := range dec.RedirectTo {
		if err := submitRedirect(ctx, log, c, a, dataFile, addr); err != nil {
			log.Errorx("sieve redirect submit", err, slog.String("addr", addr))
		}
	}

	// Vacation: respond once via the outgoing queue, subject to suppression
	// rules and history.
	if dec.Vacation != nil {
		if err := sendVacation(ctx, log, c, a, mm, dec.Vacation); err != nil {
			log.Errorx("sieve vacation submit", err)
		}
	}

	if dec.Discard {
		// Silent accept, no storage.
		return &dec, true
	}

	// Otherwise return decision so caller can deliver to dec.Mailbox with
	// possibly modified flags.
	return &dec, false
}

func remoteIPString(c *conn) string {
	if c == nil || c.conn == nil {
		return ""
	}
	addr := c.conn.RemoteAddr()
	if addr == nil {
		return ""
	}
	host, _, err := net.SplitHostPort(addr.String())
	if err != nil {
		return ""
	}
	return host
}

// submitRedirect sends the message to addr via the outgoing queue. It mirrors
// the queue.Add submission pattern used elsewhere in smtpserver.
func submitRedirect(ctx context.Context, log mlog.Log, c *conn, a analysis, dataFile *os.File, addr string) error {
	// Parse target address.
	target, err := smtp.ParseAddress(addr)
	if err != nil {
		return fmt.Errorf("parse redirect target: %w", err)
	}
	if c.mailFrom == nil {
		return errors.New("missing mail from for redirect")
	}
	sender := *c.mailFrom
	// SRS: rewrite the envelope sender so the forwarding hop passes SPF at the
	// destination, and so bounces (DSNs) come back to an address we can decode.
	// Skip the null sender (a bounce being forwarded must keep its empty MAIL
	// FROM). Skip senders already at a domain we host: our own SPF authorises
	// this server for them, so rewriting is unnecessary and lets their bounces
	// flow back natively (this also doubles as the per-domain opt-out). Only the
	// envelope changes; the message's From header and DKIM signatures are
	// untouched, preserving the original DMARC alignment. On any rewrite error we
	// fall back to the original sender rather than dropping mail.
	if srsCfg := moxSRSConfig(); srsCfg != nil && !sender.IsZero() && !senderIsLocal(sender) {
		if rewritten, err := srs.Forward(senderAddress(sender), *srsCfg); err != nil {
			log.Errorx("srs forward rewrite, using original sender", err, slog.String("sender", sender.String()))
		} else {
			sender = rewritten.Path()
		}
	}
	subject := ""
	now := time.Now()
	prefix := a.d.m.MsgPrefix
	size := a.d.m.Size
	qm := queue.MakeMsg(sender, target.Path(), false, c.msgsmtputf8, size, "", prefix, nil, now, subject)
	if err := queue.Add(ctx, log, a.d.acc.Name, dataFile, qm); err != nil {
		return fmt.Errorf("queue add: %w", err)
	}
	log.Info("sieve redirect queued", slog.String("addr", addr))
	return nil
}

// moxSRSConfig returns the resolved SRS config if SRS is enabled and ready, or
// nil to indicate forwarding should keep the original envelope sender.
func moxSRSConfig() *srs.Config {
	s := mox.Conf.Static.SRS
	if s == nil || !s.Enabled || len(s.Secret) == 0 || s.DNSDomain.IsZero() {
		return nil
	}
	return &srs.Config{Secret: s.Secret, Domain: s.DNSDomain, MaxAge: s.MaxAge}
}

// senderAddress converts an envelope smtp.Path to an smtp.Address for SRS. The
// caller has already ensured the path is not the null sender and carries a
// domain (not a bare IP), which holds for envelope senders of forwarded mail.
func senderAddress(p smtp.Path) smtp.Address {
	return smtp.Address{Localpart: p.Localpart, Domain: p.IPDomain.Domain}
}

// senderIsLocal reports whether the envelope sender is at a domain this server
// hosts (a configured domain or the system hostname). Such senders are already
// covered by our own SPF, so SRS rewriting is skipped for them.
func senderIsLocal(p smtp.Path) bool {
	d := p.IPDomain.Domain
	if d.IsZero() {
		return false
	}
	if _, ok := mox.Conf.Domain(d); ok {
		return true
	}
	return d == mox.Conf.Static.HostnameDomain
}

// addheader/deleteheader actions captured in the decision. The on-disk
// message file is never mutated (it is shared between recipients and is
// immutable per the storage layer); deletions therefore only affect
// MsgPrefix-resident headers. Additions go at the top of the prefix (atTop)
// or at the end of MsgPrefix (which is still within the headers section
// before the original message-file headers).
//
// Sizes are recalculated. m.Size += delta.
func applyEditHeaders(a analysis, dec *sievefilter.Decision) {
	if len(dec.HeaderAdds) == 0 && len(dec.HeaderDeletes) == 0 {
		return
	}
	origLen := len(a.d.m.MsgPrefix)

	if len(dec.HeaderDeletes) > 0 {
		a.d.m.MsgPrefix = deleteHeadersFromPrefix(a.d.m.MsgPrefix, dec.HeaderDeletes)
	}

	if len(dec.HeaderAdds) > 0 {
		atTop := make([]byte, 0)
		atEnd := make([]byte, 0)
		for _, h := range dec.HeaderAdds {
			line := []byte(h.Name + ": " + h.Value + "\r\n")
			if h.AtTop {
				atTop = append(atTop, line...)
			} else {
				atEnd = append(atEnd, line...)
			}
		}
		// Combine: top-additions || existing prefix || end-additions.
		newPrefix := make([]byte, 0, len(atTop)+len(a.d.m.MsgPrefix)+len(atEnd))
		newPrefix = append(newPrefix, atTop...)
		newPrefix = append(newPrefix, a.d.m.MsgPrefix...)
		newPrefix = append(newPrefix, atEnd...)
		a.d.m.MsgPrefix = newPrefix
	}

	// Update message size by delta.
	delta := int64(len(a.d.m.MsgPrefix) - origLen)
	a.d.m.Size += delta
}

// deleteHeadersFromPrefix removes header lines from prefix matching any of the
// edits. Matching is case-insensitive on the name; if Pattern is non-empty,
// the header value must match at least one pattern (substring, case-insensitive)
// to be deleted. Index/FromLast are simplified to delete-all semantics for now.
func deleteHeadersFromPrefix(prefix []byte, edits []sievefilter.HeaderEdit) []byte {
	if len(prefix) == 0 {
		return prefix
	}
	// Walk header lines. We assume MsgPrefix consists only of well-formed
	// header lines terminated by CRLF (no body separator).
	lines := bytes.Split(prefix, []byte("\r\n"))
	out := make([][]byte, 0, len(lines))
	for _, ln := range lines {
		if len(ln) == 0 {
			out = append(out, ln)
			continue
		}
		colon := bytes.IndexByte(ln, ':')
		if colon <= 0 {
			out = append(out, ln)
			continue
		}
		name := string(bytes.TrimSpace(ln[:colon]))
		value := string(bytes.TrimSpace(ln[colon+1:]))
		drop := false
		for _, e := range edits {
			if !strings.EqualFold(e.Name, name) {
				continue
			}
			if len(e.Pattern) == 0 {
				drop = true
				break
			}
			vl := strings.ToLower(value)
			for _, p := range e.Pattern {
				if strings.Contains(vl, strings.ToLower(p)) {
					drop = true
					break
				}
			}
			if drop {
				break
			}
		}
		if !drop {
			out = append(out, ln)
		}
	}
	return bytes.Join(out, []byte("\r\n"))
}

// sendVacation submits a vacation response message via the queue, subject to
// the abuse-control checks (no responses to bulk/list/auto-submitted mail,
// no response if same handle has been sent to the same recipient recently).
// mm is the parsed message adapter, used to inspect Auto-Submitted/Precedence
// headers in the on-disk message file (not just MsgPrefix).
func sendVacation(ctx context.Context, log mlog.Log, c *conn, a analysis, mm *sievefilter.MoxMessage, vp *sievefilter.VacationParams) error {
	if c.mailFrom == nil || c.mailFrom.IsZero() {
		// Null sender (DSN/auto). Don't respond.
		return nil
	}
	// Suppress for auto-submitted, list mail, DSN.
	if mm != nil && isAutoSubmittedMsg(mm) {
		log.Debug("vacation suppressed: auto-submitted mail")
		return nil
	}
	if isAutoSubmitted(a.d.m) {
		log.Debug("vacation suppressed: auto-submitted prefix")
		return nil
	}
	if a.d.m.IsMailingList {
		log.Debug("vacation suppressed: mailing list mail")
		return nil
	}
	if a.d.m.IsReject {
		log.Debug("vacation suppressed: rejected/spam mail")
		return nil
	}

	recipient := c.mailFrom.String()
	days := vp.Days
	if days <= 0 {
		days = 7
	}
	handle := vp.Handle
	if handle == "" {
		handle = "default"
	}

	// Check history.
	sent, err := a.d.acc.SieveVacationRecentlySent(handle, recipient, time.Duration(days)*24*time.Hour)
	if err != nil {
		return fmt.Errorf("vacation history check: %w", err)
	}
	if sent {
		log.Debug("vacation suppressed: already sent recently", slog.String("handle", handle), slog.String("recipient", recipient))
		return nil
	}

	// Build response message.
	from := vp.From
	if from == "" {
		// Use postmaster of the account's primary domain, or RCPT TO of the
		// triggering message.
		from = a.d.deliverTo.String()
	}
	subj := vp.Subject
	if subj == "" {
		subj = "Auto: vacation reply"
	}
	body := vp.Reason
	if !vp.Mime {
		var sb strings.Builder
		sb.WriteString("Subject: " + subj + "\r\n")
		sb.WriteString("From: " + from + "\r\n")
		sb.WriteString("To: " + recipient + "\r\n")
		sb.WriteString("Auto-Submitted: auto-replied (vacation)\r\n")
		sb.WriteString("Precedence: bulk\r\n")
		if mid := normalizeMessageID(a.d.m.MessageID); mid != "" {
			sb.WriteString("In-Reply-To: " + mid + "\r\n")
			sb.WriteString("References: " + mid + "\r\n")
		}
		sb.WriteString("Content-Type: text/plain; charset=utf-8\r\n")
		sb.WriteString("\r\n")
		sb.WriteString(vp.Reason)
		body = sb.String()
	}

	tmpFile, err := store.CreateMessageTemp(log, "sieve-vacation")
	if err != nil {
		return fmt.Errorf("create vacation temp file: %w", err)
	}
	defer store.CloseRemoveTempFile(log, tmpFile, "vacation")
	if _, err := tmpFile.WriteString(body); err != nil {
		return fmt.Errorf("write vacation body: %w", err)
	}
	if _, err := tmpFile.Seek(0, 0); err != nil {
		return fmt.Errorf("seek vacation file: %w", err)
	}

	fromAddr, err := smtp.ParseAddress(from)
	if err != nil {
		return fmt.Errorf("parse vacation from: %w", err)
	}
	target, err := smtp.ParseAddress(recipient)
	if err != nil {
		return fmt.Errorf("parse vacation recipient: %w", err)
	}
	qm := queue.MakeMsg(fromAddr.Path(), target.Path(), false, false, int64(len(body)), "", nil, nil, time.Now(), subj)
	if err := queue.Add(ctx, log, a.d.acc.Name, tmpFile, qm); err != nil {
		return fmt.Errorf("queue vacation: %w", err)
	}
	if err := a.d.acc.SieveVacationRecordSent(handle, recipient); err != nil {
		log.Errorx("recording vacation send", err)
	}
	log.Info("sieve vacation queued", slog.String("recipient", recipient), slog.String("handle", handle))
	return nil
}

// isAutoSubmittedMsg consults the parsed message headers (which include the
// on-disk headers, not just the MsgPrefix) to detect auto-submitted mail per
// RFC 3834. Returns true also for Precedence: bulk/list.
func isAutoSubmittedMsg(mm *sievefilter.MoxMessage) bool {
	if mm == nil {
		return false
	}
	for _, v := range mm.Header("Auto-Submitted") {
		if !strings.EqualFold(strings.TrimSpace(v), "no") {
			return true
		}
	}
	for _, v := range mm.Header("Precedence") {
		lv := strings.ToLower(strings.TrimSpace(v))
		if lv == "bulk" || lv == "list" || lv == "junk" {
			return true
		}
	}
	return false
}

// isAutoSubmitted returns true if the MsgPrefix already indicates the
// message is auto-submitted (cheap pre-check). The more thorough check is
// isAutoSubmittedMsg, which consults the on-disk headers.
func isAutoSubmitted(m *store.Message) bool {
	// MsgPrefix may include Auto-Submitted; the on-disk file may have it.
	// We check MsgPrefix only (cheap).
	prefix := strings.ToLower(string(m.MsgPrefix))
	if strings.Contains(prefix, "\nauto-submitted: ") && !strings.Contains(prefix, "\nauto-submitted: no\r\n") {
		return true
	}
	if strings.Contains(prefix, "\nprecedence: bulk") || strings.Contains(prefix, "\nprecedence: list") {
		return true
	}
	return false
}

// normalizeMessageID returns a Message-Id suitable for In-Reply-To/References
// headers. Mox stores Message-Id as the bare token (no angle brackets); we
// add them here unless already present. Returns "" if input is empty so the
// caller can omit the header entirely.
func normalizeMessageID(mid string) string {
	mid = strings.TrimSpace(mid)
	if mid == "" {
		return ""
	}
	if strings.HasPrefix(mid, "<") && strings.HasSuffix(mid, ">") {
		return mid
	}
	return "<" + mid + ">"
}

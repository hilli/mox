package imapserver

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"strings"
	"time"

	"github.com/mjl-/bstore"

	"github.com/mjl-/mox/config"
	"github.com/mjl-/mox/dns"
	mox "github.com/mjl-/mox/mox-"
	"github.com/mjl-/mox/queue"
	"github.com/mjl-/mox/sievefilter"
	"github.com/mjl-/mox/smtp"
	"github.com/mjl-/mox/store"
)

// IMAPSieveScriptMetadataEntry is the IMAP METADATA entry name that names the
// active Sieve script for an IMAP-event mailbox or server (per RFC 6785 §2.3.1).
const IMAPSieveScriptMetadataEntry = "/shared/imapsieve/script"

// sieveCapabilityToken returns the value to advertise for the IMAPSIEVE
// capability, e.g. `IMAPSIEVE=sieve://host:4190`. Returns the empty string
// when ManageSieve is not configured on any listener.
func sieveCapabilityToken() string {
	for _, l := range mox.Conf.Static.Listeners {
		if !l.ManageSieve.Enabled {
			continue
		}
		port := config.Port(l.ManageSieve.Port, 4190)
		host := mox.Conf.Static.Hostname
		if l.Hostname != "" {
			host = l.HostnameDomain.Name()
		}
		return fmt.Sprintf("IMAPSIEVE=sieve://%s:%d", host, port)
	}
	return ""
}

// sieveScriptForMailbox returns the active IMAPSIEVE script content for the
// given mailbox name, applying RFC 6785 §2.3.1 selection: mailbox-level
// metadata entry first, server-level entry as fallback only when the mailbox
// has no entry. If the selected entry value names a non-existent script, no
// script is run (and no fallback to the other level). Returns (nil, nil)
// when no script applies.
func sieveScriptForMailbox(acc *store.Account, mailboxName string) (scriptName string, content []byte, err error) {
	// Find the metadata entry for the mailbox.
	err = acc.DB.Read(context.TODO(), func(tx *bstore.Tx) error {
		var mailboxID int64
		// Look up mailbox (case-sensitive, exact name match).
		mb, e := bstore.QueryTx[store.Mailbox](tx).FilterNonzero(store.Mailbox{Name: mailboxName}).FilterEqual("Expunged", false).Get()
		if e == nil {
			mailboxID = mb.ID
		} else if e != bstore.ErrAbsent {
			return e
		}

		// Mailbox-level entry first.
		if mailboxID > 0 {
			ann, e := bstore.QueryTx[store.Annotation](tx).FilterNonzero(store.Annotation{Key: IMAPSieveScriptMetadataEntry, MailboxID: mailboxID}).FilterEqual("Expunged", false).Get()
			if e == nil {
				if len(ann.Value) == 0 {
					// Selected but empty → no script, no fallback.
					return nil
				}
				scriptName = string(ann.Value)
				return nil
			} else if e != bstore.ErrAbsent {
				return e
			}
		}
		// Server-level entry (MailboxID == 0).
		ann, e := bstore.QueryTx[store.Annotation](tx).FilterNonzero(store.Annotation{Key: IMAPSieveScriptMetadataEntry}).FilterEqual("MailboxID", int64(0)).FilterEqual("Expunged", false).Get()
		if e == nil {
			if len(ann.Value) == 0 {
				return nil
			}
			scriptName = string(ann.Value)
			return nil
		} else if e != bstore.ErrAbsent {
			return e
		}
		return nil
	})
	if err != nil {
		return "", nil, err
	}
	if scriptName == "" {
		return "", nil, nil
	}
	scr, err := acc.SieveGetScript(scriptName)
	if err != nil {
		if errors.Is(err, store.ErrSieveScriptNotFound) {
			// Selected but missing → no script, no fallback.
			return scriptName, nil, nil
		}
		return scriptName, nil, err
	}
	return scriptName, scr, nil
}

// runIMAPSieve runs the active IMAPSIEVE script (if any) for the given event
// and applies the resulting decision (file message into additional mailbox,
// mark original deleted, change flags, etc.). Loop prevention: when c.inSieve is
// already set we return immediately, satisfying RFC 6785 §2.2.3 — flag
// changes (and similar mutations) caused by a Sieve-triggered action do not
// trigger another script invocation.
//
// msg is the message at the heart of the event. For APPEND/COPY, it is the
// newly inserted message in mailboxName; for FLAG, it is the existing
// message whose flags changed. dataFile is the on-disk message file (used to
// re-read content for redirect/fileinto copy). changedFlags is populated for
// FLAG events.
func (c *conn) runIMAPSieve(cause, mailboxName string, msg *store.Message, dataFile *os.File, changedFlags []string) {
	if c.account == nil {
		return
	}
	if c.inSieve {
		// Re-entrant call from a Sieve action; do not fire again.
		return
	}
	// Resolve effective policy.
	var domain dns.Domain
	if accConf, ok := mox.Conf.Account(c.account.Name); ok {
		domain = accConf.DNSDomain
	}
	server, dom, acc := mox.Conf.SievePolicy(c.account.Name, domain)
	policy := sievefilter.Resolve(server, dom, acc)
	if !policy.Enabled || !policy.RunOnIMAPEvents {
		return
	}

	scriptName, scriptContent, err := sieveScriptForMailbox(c.account, mailboxName)
	if err != nil {
		c.log.Errorx("imapsieve script lookup", err, slog.String("mailbox", mailboxName))
		return
	}
	if len(scriptContent) == 0 {
		return
	}

	// Build Mox message adapter; we don't need envelope here (envelope
	// tests are forbidden in IMAPSIEVE), but pass empty values.
	mm := sievefilter.NewMoxMessage(msg, dataFile, "", nil)

	in := sievefilter.IMAPEventInput{
		Policy:       policy,
		Script:       scriptContent,
		Message:      mm,
		Cause:        cause,
		Mailbox:      mailboxName,
		User:         c.username,
		Email:        c.username,
		ChangedFlags: changedFlags,
		CurrentFlags: msgFlagNames(msg),
		Log:          c.log,
	}

	// Set the re-entrancy guard before running so that any action callbacks
	// (which use the same conn for direct store mutations) bypass the hook.
	c.inSieve = true
	defer func() { c.inSieve = false }()

	dec, err := sievefilter.ExecuteIMAPEvent(context.Background(), in)
	if err != nil {
		c.log.Errorx("imapsieve execute", err, slog.String("script", scriptName), slog.String("cause", cause), slog.String("mailbox", mailboxName))
		return
	}
	c.applyIMAPSieveDecision(cause, mailboxName, msg, dataFile, dec)
}

// applyIMAPSieveDecision applies an IMAPEventDecision: fileinto copies,
// redirects via queue, mark-deleted on the original, flag changes.
func (c *conn) applyIMAPSieveDecision(cause, mailboxName string, msg *store.Message, dataFile *os.File, dec sievefilter.IMAPEventDecision) {
	if dec.Warning != "" {
		c.log.Warn("imapsieve warning", slog.String("warning", dec.Warning))
	}

	// fileinto: create an additional copy in each target mailbox.
	for _, target := range dec.FileInto {
		if err := imapSieveFileInto(c, msg, dataFile, target, dec.HeaderAdds, dec.HeaderDeletes); err != nil {
			c.log.Errorx("imapsieve fileinto", err, slog.String("mailbox", target.Mailbox))
		}
	}

	// redirect: queue an outgoing message.
	for _, addr := range dec.RedirectTo {
		if err := imapSieveRedirect(c, msg, dataFile, addr, dec.HeaderAdds, dec.HeaderDeletes); err != nil {
			c.log.Errorx("imapsieve redirect", err, slog.String("addr", addr))
		}
	}

	// MarkDeleted: set \Deleted on the original message.
	if dec.MarkDeleted && msg != nil {
		if err := imapSieveMarkDeleted(c, msg); err != nil {
			c.log.Errorx("imapsieve mark deleted", err, slog.Int64("messageid", msg.ID))
		}
	}

	// RFC 6785 §3.8: imap4flags actions apply to any IMAP event case.
	if dec.FlagsChanged && msg != nil {
		if err := imapSieveSetFlags(c, msg, dec.Flags); err != nil {
			c.log.Errorx("imapsieve set flags", err, slog.Int64("messageid", msg.ID))
		}
	}
}

// imapSieveFileInto creates an additional copy of msg in target.Mailbox with
// the optional flags. HeaderAdds/Deletes are transient (applied to this copy
// only).
func imapSieveFileInto(c *conn, msg *store.Message, dataFile *os.File, target sievefilter.FileIntoTarget, adds, dels []sievefilter.HeaderEdit) error {
	if msg == nil {
		return errors.New("nil source message")
	}
	// Build a copy of msg for delivery into target.Mailbox.
	cp := *msg
	cp.ID = 0
	cp.UID = 0
	cp.MailboxID = 0
	cp.MailboxOrigID = 0
	cp.Expunged = false
	cp.MsgPrefix = applyImapSieveHeaderEdits(msg.MsgPrefix, adds, dels)
	cp.Size = int64(len(cp.MsgPrefix)) + (msg.Size - int64(len(msg.MsgPrefix)))
	// Add flags requested by fileinto :flags.
	for _, f := range target.Flags {
		setStoreFlagKeyword(&cp, f)
	}
	c.account.WithWLock(func() {
		err := c.account.DeliverMailbox(c.log, target.Mailbox, &cp, dataFile)
		if err != nil {
			c.log.Errorx("imapsieve deliver fileinto", err, slog.String("mailbox", target.Mailbox))
			return
		}
		// Broadcast change so other sessions see new UID.
		mb, mberr := bstore.QueryDB[store.Mailbox](context.TODO(), c.account.DB).FilterNonzero(store.Mailbox{ID: cp.MailboxID}).Get()
		if mberr == nil {
			c.broadcast([]store.Change{cp.ChangeAddUID(mb), mb.ChangeCounts()})
		}
	})
	return nil
}

// imapSieveRedirect submits the redirected message to the outbound queue.
func imapSieveRedirect(c *conn, msg *store.Message, dataFile *os.File, addr string, adds, dels []sievefilter.HeaderEdit) error {
	target, err := smtp.ParseAddress(addr)
	if err != nil {
		return fmt.Errorf("parse redirect target: %w", err)
	}
	sender, err := smtp.ParseAddress(c.username)
	if err != nil {
		return fmt.Errorf("parse owner address: %w", err)
	}
	prefix := applyImapSieveHeaderEdits(msg.MsgPrefix, adds, dels)
	size := int64(len(prefix)) + (msg.Size - int64(len(msg.MsgPrefix)))
	qm := queue.MakeMsg(sender.Path(), target.Path(), false, false, size, "", prefix, nil, time.Now(), "")
	if err := queue.Add(context.Background(), c.log, c.account.Name, dataFile, qm); err != nil {
		return fmt.Errorf("queue redirect: %w", err)
	}
	c.log.Info("imapsieve redirect queued", slog.String("addr", addr))
	return nil
}

// imapSieveMarkDeleted sets the \Deleted flag on msg (in the account DB),
// maintains mailbox counts/modseq, and broadcasts the change so other IMAP
// sessions selecting the same mailbox observe \Deleted in real time
// (per IMAPSIEVE behaviour analogous to STORE).
func imapSieveMarkDeleted(c *conn, msg *store.Message) error {
	var changes []store.Change
	err := c.account.DB.Write(context.TODO(), func(tx *bstore.Tx) error {
		fresh := store.Message{ID: msg.ID}
		if err := tx.Get(&fresh); err != nil {
			return err
		}
		if fresh.Expunged || fresh.Deleted {
			return nil
		}
		// Fetch mailbox to maintain counts and HighestModSeq.
		mb := store.Mailbox{ID: fresh.MailboxID}
		if err := tx.Get(&mb); err != nil {
			return err
		}
		mb.Sub(fresh.MailboxCounts())
		origFlags := fresh.Flags
		fresh.Deleted = true
		mb.Add(fresh.MailboxCounts())
		modseq, err := c.account.NextModSeq(tx)
		if err != nil {
			return err
		}
		fresh.ModSeq = modseq
		mb.ModSeq = modseq
		if err := tx.Update(&fresh); err != nil {
			return err
		}
		if err := tx.Update(&mb); err != nil {
			return err
		}
		// Stage broadcast outside the tx (which is committed when this fn
		// returns nil).
		changes = []store.Change{fresh.ChangeFlags(origFlags, mb), mb.ChangeCounts()}
		return nil
	})
	if err != nil {
		return err
	}
	if len(changes) > 0 {
		c.broadcast(changes)
	}
	return nil
}

// imapSieveSetFlags replaces msg's flags with the given final flag list. System flags
// (starting with `\`) update Message.Flags fields; user keywords go into
// Message.Keywords (and the mailbox-level keyword set, broadcast as
// ChangeMailboxKeywords if new). The flag change is broadcast so other
// sessions see it in real time.
func imapSieveSetFlags(c *conn, msg *store.Message, flags []string) error {
	var changes []store.Change
	err := c.account.DB.Write(context.TODO(), func(tx *bstore.Tx) error {
		fresh := store.Message{ID: msg.ID}
		if err := tx.Get(&fresh); err != nil {
			return err
		}
		if fresh.Expunged {
			return nil
		}
		mb := store.Mailbox{ID: fresh.MailboxID}
		if err := tx.Get(&mb); err != nil {
			return err
		}
		mb.Sub(fresh.MailboxCounts())
		origFlags := fresh.Flags
		origKwLen := len(mb.Keywords)
		fresh.Seen = false
		fresh.Answered = false
		fresh.Flagged = false
		fresh.Deleted = false
		fresh.Draft = false
		fresh.Forwarded = false
		fresh.Junk = false
		fresh.Notjunk = false
		fresh.Phishing = false
		fresh.MDNSent = false
		fresh.Keywords = nil
		var newKeywords []string
		for _, f := range flags {
			if !strings.HasPrefix(f, `\`) && !strings.HasPrefix(f, `$`) {
				// Genuine user keyword: collect for mailbox-level merge.
				newKeywords = append(newKeywords, strings.ToLower(f))
			}
			setStoreFlagKeyword(&fresh, f)
		}
		if len(newKeywords) > 0 {
			mb.Keywords, _ = store.MergeKeywords(mb.Keywords, newKeywords)
		}
		mb.Add(fresh.MailboxCounts())
		modseq, err := c.account.NextModSeq(tx)
		if err != nil {
			return err
		}
		fresh.ModSeq = modseq
		mb.ModSeq = modseq
		if err := tx.Update(&fresh); err != nil {
			return err
		}
		if err := tx.Update(&mb); err != nil {
			return err
		}
		changes = []store.Change{fresh.ChangeFlags(origFlags, mb)}
		if len(mb.Keywords) > origKwLen {
			changes = append(changes, mb.ChangeKeywords())
		}
		return nil
	})
	if err != nil {
		return err
	}
	if len(changes) > 0 {
		c.broadcast(changes)
	}
	return nil
}

// applyImapSieveHeaderEdits returns a new MsgPrefix with the given adds at
// the top and the given deletes removed (matching MsgPrefix-resident
// headers only). Returns the original slice if no edits.
func applyImapSieveHeaderEdits(prefix []byte, adds, dels []sievefilter.HeaderEdit) []byte {
	if len(adds) == 0 && len(dels) == 0 {
		return prefix
	}
	out := prefix
	if len(dels) > 0 {
		out = deleteIMAPSieveHeaders(out, dels)
	}
	if len(adds) > 0 {
		topBuf := make([]byte, 0)
		endBuf := make([]byte, 0)
		for _, h := range adds {
			line := []byte(h.Name + ": " + h.Value + "\r\n")
			if h.AtTop {
				topBuf = append(topBuf, line...)
			} else {
				endBuf = append(endBuf, line...)
			}
		}
		newp := make([]byte, 0, len(topBuf)+len(out)+len(endBuf))
		newp = append(newp, topBuf...)
		newp = append(newp, out...)
		newp = append(newp, endBuf...)
		out = newp
	}
	return out
}

func deleteIMAPSieveHeaders(prefix []byte, edits []sievefilter.HeaderEdit) []byte {
	if len(prefix) == 0 {
		return prefix
	}
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

// msgFlagNames returns IMAP flag names currently set on msg (system flags
// like "\Seen", plus keywords).
func msgFlagNames(m *store.Message) []string {
	if m == nil {
		return nil
	}
	var out []string
	if m.Seen {
		out = append(out, `\Seen`)
	}
	if m.Answered {
		out = append(out, `\Answered`)
	}
	if m.Flagged {
		out = append(out, `\Flagged`)
	}
	if m.Deleted {
		out = append(out, `\Deleted`)
	}
	if m.Draft {
		out = append(out, `\Draft`)
	}
	if m.Forwarded {
		out = append(out, `$Forwarded`)
	}
	if m.Junk {
		out = append(out, `$Junk`)
	}
	if m.Notjunk {
		out = append(out, `$NotJunk`)
	}
	if m.Phishing {
		out = append(out, `$Phishing`)
	}
	if m.MDNSent {
		out = append(out, `$MDNSent`)
	}
	out = append(out, m.Keywords...)
	return out
}

// setStoreFlagKeyword sets the named flag on m, distinguishing system flags
// from user keywords.
func setStoreFlagKeyword(m *store.Message, flag string) {
	switch flag {
	case `\Seen`:
		m.Seen = true
	case `\Answered`:
		m.Answered = true
	case `\Flagged`:
		m.Flagged = true
	case `\Deleted`:
		m.Deleted = true
	case `\Draft`:
		m.Draft = true
	case `$Forwarded`:
		m.Forwarded = true
	case `$Junk`:
		m.Junk = true
	case `$NotJunk`:
		m.Notjunk = true
	case `$Phishing`:
		m.Phishing = true
	case `$MDNSent`:
		m.MDNSent = true
	default:
		// User keyword. Mox stores keywords lowercased in IMAP.
		kw := strings.ToLower(flag)
		for _, k := range m.Keywords {
			if k == kw {
				return
			}
		}
		m.Keywords = append(m.Keywords, kw)
	}
}

// imapsieveEnabled reports whether IMAPSIEVE should be advertised in
// capabilities (i.e. ManageSieve is enabled on at least one listener and
// the account isn't disabling it).
func (c *conn) imapsieveEnabled() bool {
	return sieveCapabilityToken() != ""
}

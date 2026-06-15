package imapserver

import (
	"strings"
	"testing"
	"time"

	"github.com/mjl-/bstore"

	"github.com/mjl-/mox/config"
	"github.com/mjl-/mox/imapclient"
	"github.com/mjl-/mox/mox-"
	"github.com/mjl-/mox/store"
)

// enableIMAPSieve sets the server-wide Sieve policy to Enabled=true and
// RunOnIMAPEvents=true. Returns a restore function.
func enableIMAPSieve(t *testing.T) func() {
	t.Helper()
	prev := mox.Conf.Static.Sieve
	yes := true
	mox.Conf.Static.Sieve = &config.Sieve{
		Enabled:         &yes,
		RunOnIMAPEvents: &yes,
	}
	return func() { mox.Conf.Static.Sieve = prev }
}

// addManageSieveListener adds a fake listener with ManageSieve enabled so
// the IMAPSIEVE capability is advertised. Returns a restore function.
func addManageSieveListener(t *testing.T) func() {
	t.Helper()
	prev := mox.Conf.Static.Listeners
	// Clone the map so we don't permanently mutate.
	newm := make(map[string]config.Listener, len(prev)+1)
	for k, v := range prev {
		newm[k] = v
	}
	var l config.Listener
	l.ManageSieve.Enabled = true
	// Port left 0 → defaults to 4190 via config.Port helper.
	newm["sievelistener"] = l
	mox.Conf.Static.Listeners = newm
	return func() { mox.Conf.Static.Listeners = prev }
}

// countMessagesIn returns the number of non-expunged messages in the given
// mailbox name of the account.
func countMessagesIn(t *testing.T, acc *store.Account, mailbox string) int {
	t.Helper()
	mb, err := bstore.QueryDB[store.Mailbox](ctxbg, acc.DB).FilterNonzero(store.Mailbox{Name: mailbox}).FilterEqual("Expunged", false).Get()
	if err == bstore.ErrAbsent {
		return 0
	}
	tcheck(t, err, "lookup mailbox "+mailbox)
	n, err := bstore.QueryDB[store.Message](ctxbg, acc.DB).FilterNonzero(store.Message{MailboxID: mb.ID}).FilterEqual("Expunged", false).Count()
	tcheck(t, err, "count messages")
	return n
}

// messagesIn returns the non-expunged messages in mailbox.
func messagesIn(t *testing.T, acc *store.Account, mailbox string) []store.Message {
	t.Helper()
	mb, err := bstore.QueryDB[store.Mailbox](ctxbg, acc.DB).FilterNonzero(store.Mailbox{Name: mailbox}).FilterEqual("Expunged", false).Get()
	if err == bstore.ErrAbsent {
		return nil
	}
	tcheck(t, err, "lookup mailbox "+mailbox)
	msgs, err := bstore.QueryDB[store.Message](ctxbg, acc.DB).FilterNonzero(store.Message{MailboxID: mb.ID}).FilterEqual("Expunged", false).List()
	tcheck(t, err, "list messages")
	return msgs
}

// waitForSieveEffect polls until cond returns true or 2s elapse. The hook runs
// synchronously after the IMAP response is written; this is a defensive helper
// in case of broadcast/delivery propagation.
func waitForSieveEffect(t *testing.T, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	if !cond() {
		t.Fatalf("sieve effect not observed within timeout")
	}
}

func TestIMAPSieveCapabilityAdvertised(t *testing.T) {
	// Phase 1: without ManageSieve listener, no IMAPSIEVE.
	tc := start(t, false)
	tc.transactf("ok", "capability")
	for _, u := range tc.lastResponse.Untagged {
		if caps, ok := u.(imapclient.UntaggedCapability); ok {
			for _, c := range caps {
				if strings.HasPrefix(string(c), "IMAPSIEVE") {
					t.Fatalf("did not expect IMAPSIEVE capability without ManageSieve listener, got %q", c)
				}
			}
		}
	}
	tc.close()

	// Phase 2: with ManageSieve listener, IMAPSIEVE=sieve://...:4190 must appear.
	tc = start(t, false)
	defer tc.close()
	// start() reloads mox config from disk; install our fake listener after.
	restore := addManageSieveListener(t)
	defer restore()
	tc.transactf("ok", "capability")
	found := ""
	for _, u := range tc.lastResponse.Untagged {
		if caps, ok := u.(imapclient.UntaggedCapability); ok {
			for _, c := range caps {
				if strings.HasPrefix(string(c), "IMAPSIEVE=") {
					found = string(c)
				}
			}
		}
	}
	if found == "" {
		t.Fatalf("expected IMAPSIEVE capability, got untagged: %#v", tc.lastResponse.Untagged)
	}
	if !strings.HasPrefix(strings.ToLower(found), "imapsieve=sieve://") || !strings.HasSuffix(found, ":4190") {
		t.Fatalf("unexpected IMAPSIEVE capability format: %q", found)
	}
}

func TestIMAPSieveAppendFileInto(t *testing.T) {
	tc := start(t, false)
	defer tc.close()
	// start() reloads mox config; enable Sieve policy afterwards.
	restoreSieve := enableIMAPSieve(t)
	defer restoreSieve()
	tc.login("mjl@mox.example", password0)

	// Install the script via store API.
	script := `require ["imapsieve","fileinto"];
fileinto "Filtered";
`
	tcheck(t, tc.account.SievePutScript("appendmove", []byte(script)), "put sieve script")

	// Create target mailbox so fileinto has somewhere to go.
	tc.transactf("ok", "create Filtered")

	// Set mailbox-level metadata pointing to the script.
	tc.transactf("ok", `setmetadata Inbox (/shared/imapsieve/script "appendmove")`)

	// APPEND a message into Inbox.
	tc.transactf("ok", "append Inbox (\\Seen) {%d+}\r\n%s", len(exampleMsg), exampleMsg)

	// Wait for the fileinto copy to appear in Filtered.
	waitForSieveEffect(t, func() bool {
		return countMessagesIn(t, tc.account, "Filtered") == 1
	})

	// Verify: original message in Inbox is marked \Deleted (no explicit keep).
	waitForSieveEffect(t, func() bool {
		msgs := messagesIn(t, tc.account, "Inbox")
		if len(msgs) != 1 {
			return false
		}
		return msgs[0].Deleted
	})

	if got := countMessagesIn(t, tc.account, "Filtered"); got != 1 {
		t.Fatalf("Filtered mailbox: got %d messages, want 1", got)
	}
	msgs := messagesIn(t, tc.account, "Inbox")
	if len(msgs) != 1 {
		t.Fatalf("Inbox: got %d messages, want 1", len(msgs))
	}
	if !msgs[0].Deleted {
		t.Fatalf("Inbox original not marked \\Deleted")
	}
}

func TestIMAPSieveAppendNoScriptIfMetadataMissing(t *testing.T) {
	tc := start(t, false)
	defer tc.close()
	// start() reloads mox config; enable Sieve policy afterwards.
	restoreSieve := enableIMAPSieve(t)
	defer restoreSieve()
	tc.login("mjl@mox.example", password0)

	script := `require ["imapsieve","fileinto"];
fileinto "Filtered";
`
	tcheck(t, tc.account.SievePutScript("would_fileinto", []byte(script)), "put sieve script")
	tc.transactf("ok", "create Filtered")

	// No /shared/imapsieve/script anywhere.

	tc.transactf("ok", "append Inbox (\\Seen) {%d+}\r\n%s", len(exampleMsg), exampleMsg)

	// Give any (incorrect) async work a moment.
	time.Sleep(100 * time.Millisecond)

	if got := countMessagesIn(t, tc.account, "Inbox"); got != 1 {
		t.Fatalf("Inbox: got %d messages, want 1", got)
	}
	if got := countMessagesIn(t, tc.account, "Filtered"); got != 0 {
		t.Fatalf("Filtered: got %d messages, want 0 (no script should have run)", got)
	}
	msgs := messagesIn(t, tc.account, "Inbox")
	if msgs[0].Deleted {
		t.Fatalf("Inbox message should not be marked \\Deleted")
	}
}

func TestIMAPSieveAppendEmptyMetadataMeansNoScript(t *testing.T) {
	tc := start(t, false)
	defer tc.close()
	// start() reloads mox config; enable Sieve policy afterwards.
	restoreSieve := enableIMAPSieve(t)
	defer restoreSieve()
	tc.login("mjl@mox.example", password0)

	script := `require ["imapsieve","fileinto"];
fileinto "Filtered";
`
	tcheck(t, tc.account.SievePutScript("appendmove", []byte(script)), "put sieve script")
	tc.transactf("ok", "create Filtered")

	// Set mailbox-level metadata to empty value: explicitly disabled, no fallback.
	tc.transactf("ok", `setmetadata Inbox (/shared/imapsieve/script "")`)

	tc.transactf("ok", "append Inbox (\\Seen) {%d+}\r\n%s", len(exampleMsg), exampleMsg)

	time.Sleep(100 * time.Millisecond)

	if got := countMessagesIn(t, tc.account, "Filtered"); got != 0 {
		t.Fatalf("Filtered: got %d messages, want 0 (empty metadata = no script)", got)
	}
	if got := countMessagesIn(t, tc.account, "Inbox"); got != 1 {
		t.Fatalf("Inbox: got %d messages, want 1", got)
	}
}

func TestIMAPSieveServerLevelMetadataFallback(t *testing.T) {
	tc := start(t, false)
	defer tc.close()
	// start() reloads mox config; enable Sieve policy afterwards.
	restoreSieve := enableIMAPSieve(t)
	defer restoreSieve()
	tc.login("mjl@mox.example", password0)

	script := `require ["imapsieve","fileinto"];
fileinto "Filtered";
`
	tcheck(t, tc.account.SievePutScript("globalscript", []byte(script)), "put sieve script")
	tc.transactf("ok", "create Filtered")

	// Set server-level (mailbox "") metadata, mailbox-level has nothing.
	tc.transactf("ok", `setmetadata "" (/shared/imapsieve/script "globalscript")`)

	tc.transactf("ok", "append Inbox (\\Seen) {%d+}\r\n%s", len(exampleMsg), exampleMsg)

	waitForSieveEffect(t, func() bool {
		return countMessagesIn(t, tc.account, "Filtered") == 1
	})

	if got := countMessagesIn(t, tc.account, "Filtered"); got != 1 {
		t.Fatalf("Filtered: got %d, want 1 (server-level fallback should have applied)", got)
	}
}

func TestIMAPSieveEnvelopeForbidden(t *testing.T) {
	tc := start(t, false)
	defer tc.close()
	// start() reloads mox config; enable Sieve policy afterwards.
	restoreSieve := enableIMAPSieve(t)
	defer restoreSieve()
	tc.login("mjl@mox.example", password0)

	// envelope tests are forbidden in IMAPSIEVE per RFC 6785 §4.6, and Mox
	// returns a runtime error from the envelope test in this context.
	script := `require ["imapsieve","envelope","fileinto"];
if envelope :is "from" "x" { fileinto "X"; }
`
	tcheck(t, tc.account.SievePutScript("badenv", []byte(script)), "put sieve script")
	tc.transactf("ok", "create X")
	tc.transactf("ok", `setmetadata Inbox (/shared/imapsieve/script "badenv")`)

	tc.transactf("ok", "append Inbox (\\Seen) {%d+}\r\n%s", len(exampleMsg), exampleMsg)

	// Give the (failing) hook time to run.
	time.Sleep(150 * time.Millisecond)

	// Original stays in Inbox unchanged, no fileinto.
	if got := countMessagesIn(t, tc.account, "X"); got != 0 {
		t.Fatalf("X: got %d, want 0 (envelope test should have errored, no fileinto)", got)
	}
	msgs := messagesIn(t, tc.account, "Inbox")
	if len(msgs) != 1 {
		t.Fatalf("Inbox: got %d messages, want 1", len(msgs))
	}
	if msgs[0].Deleted {
		t.Fatalf("Inbox message should not be marked \\Deleted on script runtime error")
	}
}

func TestIMAPSieveDisabled(t *testing.T) {
	// Sieve.Enabled=true but RunOnIMAPEvents=false → IMAPSIEVE must not run.
	tc := start(t, false)
	defer tc.close()
	// start() reloads config; mutate after.
	prev := mox.Conf.Static.Sieve
	defer func() { mox.Conf.Static.Sieve = prev }()
	yes := true
	no := false
	mox.Conf.Static.Sieve = &config.Sieve{
		Enabled:         &yes,
		RunOnIMAPEvents: &no,
	}
	tc.login("mjl@mox.example", password0)

	script := `require ["imapsieve","fileinto"];
fileinto "Filtered";
`
	tcheck(t, tc.account.SievePutScript("appendmove", []byte(script)), "put sieve script")
	tc.transactf("ok", "create Filtered")
	tc.transactf("ok", `setmetadata Inbox (/shared/imapsieve/script "appendmove")`)

	tc.transactf("ok", "append Inbox (\\Seen) {%d+}\r\n%s", len(exampleMsg), exampleMsg)

	time.Sleep(100 * time.Millisecond)

	if got := countMessagesIn(t, tc.account, "Filtered"); got != 0 {
		t.Fatalf("Filtered: got %d, want 0 (RunOnIMAPEvents=false should disable IMAPSIEVE)", got)
	}
	if got := countMessagesIn(t, tc.account, "Inbox"); got != 1 {
		t.Fatalf("Inbox: got %d, want 1", got)
	}
}

// TestIMAPSieveStoreFlagTrigger verifies that a STORE command setting a flag
// triggers the IMAPSIEVE FLAG-cause script and that the script's actions are
// applied (fileinto copy created). Loop prevention is implicit because the
// script's own flag/fileinto actions go via the in-Sieve store helpers, not
// via the IMAP command loop.
func TestIMAPSieveStoreFlagTrigger(t *testing.T) {
	tc := start(t, false)
	defer tc.close()
	restoreSieve := enableIMAPSieve(t)
	defer restoreSieve()
	tc.login("mjl@mox.example", password0)

	// Script: when a FLAG event sets \Flagged, copy the message into "Important".
	// (Without RFC 3894 :copy, fileinto cancels implicit keep, which is fine
	// for verifying the action ran.)
	script := `require ["imapsieve","fileinto","environment"];
if anyof (environment :contains "imap.changedflags" "\\Flagged",
           environment :contains "imap.changedflags" "Flagged") {
  fileinto "Important";
}
`
	tcheck(t, tc.account.SievePutScript("onflag", []byte(script)), "put sieve script")
	tc.transactf("ok", "create Important")
	tc.transactf("ok", `setmetadata Inbox (/shared/imapsieve/script "onflag")`)

	// Append a message into Inbox (with \Seen so APPEND event triggers nothing
	// destructive; the script also runs for the APPEND but \Flagged isn't set).
	tc.transactf("ok", "append Inbox (\\Seen) {%d+}\r\n%s", len(exampleMsg), exampleMsg)
	waitForSieveEffect(t, func() bool { return countMessagesIn(t, tc.account, "Inbox") == 1 })

	// Select and STORE \Flagged on the message; this should trigger FLAG
	// cause and fileinto Important.
	tc.transactf("ok", "select Inbox")
	tc.transactf("ok", "store 1 +flags (\\Flagged)")

	waitForSieveEffect(t, func() bool {
		return countMessagesIn(t, tc.account, "Important") >= 1
	})
}

func TestIMAPSieveCopyRemoveSeen(t *testing.T) {
	tc := start(t, false)
	defer tc.close()
	restoreSieve := enableIMAPSieve(t)
	defer restoreSieve()
	tc.login("mjl@mox.example", password0)

	script := `require ["imap4flags"];
removeflag "\\Seen";
keep;
`
	tcheck(t, tc.account.SievePutScript("markunseen", []byte(script)), "put sieve script")
	tc.transactf("ok", "create TODO")
	tc.transactf("ok", `setmetadata TODO (/shared/imapsieve/script "markunseen")`)

	tc.transactf("ok", "append Inbox (\\Seen) {%d+}\r\n%s", len(exampleMsg), exampleMsg)
	tc.transactf("ok", "select Inbox")
	tc.transactf("ok", "copy 1 TODO")

	waitForSieveEffect(t, func() bool {
		msgs := messagesIn(t, tc.account, "TODO")
		return len(msgs) == 1 && !msgs[0].Seen
	})

	msgs := messagesIn(t, tc.account, "TODO")
	if len(msgs) != 1 {
		t.Fatalf("TODO: got %d messages, want 1", len(msgs))
	}
	if msgs[0].Seen {
		t.Fatalf("TODO copy is still marked \\Seen")
	}
}

func TestIMAPSieveMoveRemoveSeen(t *testing.T) {
	tc := start(t, false)
	defer tc.close()
	restoreSieve := enableIMAPSieve(t)
	defer restoreSieve()
	tc.login("mjl@mox.example", password0)

	script := `require ["imap4flags"];
removeflag "\\Seen";
keep;
`
	tcheck(t, tc.account.SievePutScript("markunseen", []byte(script)), "put sieve script")
	tc.transactf("ok", "create TODO")
	tc.transactf("ok", `setmetadata TODO (/shared/imapsieve/script "markunseen")`)

	tc.transactf("ok", "append Inbox (\\Seen) {%d+}\r\n%s", len(exampleMsg), exampleMsg)
	tc.transactf("ok", "select Inbox")
	tc.transactf("ok", "move 1 TODO")

	waitForSieveEffect(t, func() bool {
		msgs := messagesIn(t, tc.account, "TODO")
		return len(msgs) == 1 && !msgs[0].Seen
	})

	msgs := messagesIn(t, tc.account, "TODO")
	if len(msgs) != 1 {
		t.Fatalf("TODO: got %d messages, want 1", len(msgs))
	}
	if msgs[0].Seen {
		t.Fatalf("TODO move is still marked \\Seen")
	}
}

// TestIMAPSieveStoreLoopPrevention verifies that a script which adds a flag
// in response to a flag change does not infinitely recurse. The script
// installs a flag if missing, but the second invocation (re-entered) is
// suppressed by the c.inSieve guard.
func TestIMAPSieveStoreLoopPrevention(t *testing.T) {
	tc := start(t, false)
	defer tc.close()
	restoreSieve := enableIMAPSieve(t)
	defer restoreSieve()
	tc.login("mjl@mox.example", password0)

	// Script: any time a FLAG event fires, add \Answered. Without the loop
	// guard this would trigger another FLAG event (script adds \Answered →
	// flag change → fires script again → adds \Answered → ...). The guard
	// suppresses re-entry.
	script := `require ["imapsieve","imap4flags"];
addflag "\\Answered";
`
	tcheck(t, tc.account.SievePutScript("addansweralways", []byte(script)), "put sieve script")
	tc.transactf("ok", `setmetadata Inbox (/shared/imapsieve/script "addansweralways")`)

	tc.transactf("ok", "append Inbox {%d+}\r\n%s", len(exampleMsg), exampleMsg)
	waitForSieveEffect(t, func() bool { return countMessagesIn(t, tc.account, "Inbox") == 1 })

	tc.transactf("ok", "select Inbox")
	tc.transactf("ok", "store 1 +flags (\\Flagged)")

	// Give re-entry, if any, time to manifest. The hook is synchronous, so
	// a real loop would have already deadlocked or run many times. Just
	// confirm the connection is still responsive.
	tc.transactf("ok", "noop")
}

// TestIMAPSieveFetchSeenTrigger verifies that a FETCH BODY[] that implicitly
// sets \Seen triggers the IMAPSIEVE FLAG-cause script.
func TestIMAPSieveFetchSeenTrigger(t *testing.T) {
	tc := start(t, false)
	defer tc.close()
	restoreSieve := enableIMAPSieve(t)
	defer restoreSieve()
	tc.login("mjl@mox.example", password0)

	// Script: on \Seen, copy into "ReadArchive". Without RFC 3894 :copy,
	// fileinto cancels implicit keep, marking the original \Deleted.
	script := `require ["imapsieve","fileinto","environment"];
if environment :contains "imap.changedflags" "\\Seen" {
  fileinto "ReadArchive";
}
`
	tcheck(t, tc.account.SievePutScript("onseen", []byte(script)), "put sieve script")
	tc.transactf("ok", "create ReadArchive")
	tc.transactf("ok", `setmetadata Inbox (/shared/imapsieve/script "onseen")`)

	// Append the message WITHOUT \Seen so FETCH BODY[] flips it.
	tc.transactf("ok", "append Inbox {%d+}\r\n%s", len(exampleMsg), exampleMsg)
	waitForSieveEffect(t, func() bool { return countMessagesIn(t, tc.account, "Inbox") == 1 })

	tc.transactf("ok", "select Inbox")
	tc.transactf("ok", "fetch 1 (body[])")

	waitForSieveEffect(t, func() bool {
		return countMessagesIn(t, tc.account, "ReadArchive") >= 1
	})
}

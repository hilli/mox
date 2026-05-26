package sievefilter

import (
	"context"
	"strings"
	"testing"

	"github.com/hilli/sieve-go/message"
	"github.com/hilli/sieve-go/parser"

	"github.com/mjl-/mox/mlog"
)

func imapEventInput(script string) IMAPEventInput {
	return IMAPEventInput{
		Policy: Policy{
			Enabled:         true,
			RunOnIMAPEvents: true,
			MaxRedirects:    4,
		},
		Script:  []byte(script),
		Message: nil, // Replaced in test.
		Cause:   IMAPCauseAppend,
		Mailbox: "Inbox",
		User:    "mjl@mox.example",
		Email:   "mjl@mox.example",
		Log:     mlog.New("sievefilter-test", nil),
	}
}

// executeIMAPEventWithMessage is a test-only entry point that accepts a
// message.Message directly rather than a *MoxMessage, so unit tests don't need
// a real on-disk file.
func executeIMAPEventWithMessage(ctx context.Context, in IMAPEventInput, msg message.Message) (IMAPEventDecision, error) {
	d := IMAPEventDecision{}
	if !in.Policy.Enabled || !in.Policy.RunOnIMAPEvents || len(in.Script) == 0 {
		return d, nil
	}
	parsedAST, err := parser.Parse(string(in.Script))
	if err != nil {
		return d, err
	}
	script, err := getIMAPInterpreter().Compile(parsedAST)
	if err != nil {
		return d, err
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
	if err := runScriptWithTimeout(script, msg, h, in.Policy.ExecutionTimeout); err != nil {
		return d, err
	}
	return d, nil
}

func runIMAPScript(t *testing.T, in IMAPEventInput, msg message.Message) IMAPEventDecision {
	t.Helper()
	d, err := executeIMAPEventWithMessage(context.Background(), in, msg)
	if err != nil {
		t.Fatalf("ExecuteIMAPEvent: %v", err)
	}
	return d
}

func TestIMAPEventFileInto(t *testing.T) {
	in := imapEventInput(`require ["fileinto"];
fileinto "Archive";`)
	msg := message.NewBuilder().AddHeader("Subject", "test").Build()
	d := runIMAPScript(t, in, msg)
	if len(d.FileInto) != 1 || d.FileInto[0].Mailbox != "Archive" {
		t.Fatalf("expected FileInto=Archive, got %+v", d.FileInto)
	}
	if !d.MarkDeleted {
		t.Fatalf("expected MarkDeleted=true when fileinto without explicit keep")
	}
}

func TestIMAPEventKeepWithFileInto(t *testing.T) {
	in := imapEventInput(`require ["fileinto"];
keep;
fileinto "Archive";`)
	msg := message.NewBuilder().AddHeader("Subject", "test").Build()
	d := runIMAPScript(t, in, msg)
	if d.MarkDeleted {
		t.Fatalf("expected MarkDeleted=false when explicit keep ran first")
	}
}

func TestIMAPEventDiscard(t *testing.T) {
	in := imapEventInput(`discard;`)
	msg := message.NewBuilder().Build()
	d := runIMAPScript(t, in, msg)
	if !d.MarkDeleted {
		t.Fatalf("expected MarkDeleted=true for discard")
	}
}

func TestIMAPEventRejectForbidden(t *testing.T) {
	in := imapEventInput(`require ["reject"];
reject "no";`)
	msg := message.NewBuilder().Build()
	if _, err := executeIMAPEventWithMessage(context.Background(), in, msg); err == nil {
		t.Fatalf("expected error from require[reject], got nil")
	}
}

func TestIMAPEventVacationForbidden(t *testing.T) {
	in := imapEventInput(`require ["vacation"];
vacation "ooo";`)
	msg := message.NewBuilder().Build()
	if _, err := executeIMAPEventWithMessage(context.Background(), in, msg); err == nil {
		t.Fatalf("expected error from require[vacation], got nil")
	}
}

func TestIMAPEventEnvelopeForbidden(t *testing.T) {
	in := imapEventInput(`require ["envelope","fileinto"];
if envelope :is "from" "a@b" { fileinto "X"; }
`)
	msg := message.NewBuilder().SetEnvelope("from", "a@b").Build()
	if _, err := executeIMAPEventWithMessage(context.Background(), in, msg); err == nil {
		t.Fatalf("expected runtime error from envelope test, got nil")
	}
}

func TestIMAPEventEnvironmentImapCause(t *testing.T) {
	in := imapEventInput(`require ["environment","fileinto"];
if environment :is "imap.cause" "APPEND" {
  fileinto "AppendedHere";
}
`)
	in.Cause = IMAPCauseAppend
	msg := message.NewBuilder().Build()
	d := runIMAPScript(t, in, msg)
	if len(d.FileInto) != 1 || d.FileInto[0].Mailbox != "AppendedHere" {
		t.Fatalf("expected FileInto=AppendedHere, got %+v", d.FileInto)
	}
}

func TestIMAPEventFlagsCurrentAndAdd(t *testing.T) {
	in := imapEventInput(`require ["imap4flags"];
addflag "\\Seen";
`)
	in.CurrentFlags = []string{"Important"}
	msg := message.NewBuilder().Build()
	d := runIMAPScript(t, in, msg)
	found := false
	for _, f := range d.Flags {
		if f == `\Seen` {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected \\Seen in flags, got %v", d.Flags)
	}
}

func TestIMAPEventImapSieveRequire(t *testing.T) {
	in := imapEventInput(`require ["imapsieve","fileinto"];
fileinto "X";
`)
	msg := message.NewBuilder().Build()
	d := runIMAPScript(t, in, msg)
	if len(d.FileInto) != 1 {
		t.Fatalf("expected one fileinto, got %+v", d.FileInto)
	}
}

func TestIMAPEventDisabled(t *testing.T) {
	in := imapEventInput(`fileinto "X";`)
	in.Policy.Enabled = false
	msg := message.NewBuilder().Build()
	d, err := executeIMAPEventWithMessage(context.Background(), in, msg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(d.FileInto) != 0 || d.MarkDeleted {
		t.Fatalf("expected empty decision when disabled")
	}
}

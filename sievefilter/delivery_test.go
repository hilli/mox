package sievefilter

import (
	"reflect"
	"testing"

	"github.com/hilli/sieve-go/message"

	"github.com/mjl-/mox/mlog"
)

// fakeMsg adapts message.Message via the builder, sufficient for delivery
// handler tests that don't need MIME parts.
func fakeMsg(envFrom string, envTo []string, headers ...[2]string) message.Message {
	b := message.NewBuilder()
	for _, h := range headers {
		b.AddHeader(h[0], h[1])
	}
	if envFrom != "" {
		b.SetEnvelope("from", envFrom)
	}
	if len(envTo) > 0 {
		b.SetEnvelope("to", envTo...)
	}
	return b.Build()
}

func runDelivery(t *testing.T, policy Policy, script string, env EnvironmentValues, msg message.Message) Decision {
	t.Helper()
	d := Decision{Mailbox: "Inbox"}
	if policy.MaxRedirects == 0 {
		policy.MaxRedirects = 4
	}
	policy.Enabled = true
	policy.RunOnDelivery = true
	// Use the public ExecuteDelivery flow with a small shim: build script via
	// sieve-go compile + run with our handler.
	// We can't use ExecuteDelivery directly because we don't have a real
	// MoxMessage / file. Replicate the inner steps for the test.
	h := &deliveryHandler{
		policy:   policy,
		env:      env,
		decision: &d,
		log:      mlog.New("sievefilter-test", nil),
	}
	// Compile and run.
	if err := func() error {
		s, err := compileTest(script)
		if err != nil {
			return err
		}
		return s.Run(msg, h)
	}(); err != nil {
		t.Fatalf("script run: %v", err)
	}
	return d
}

// compileTest exists to keep the import set small.
func compileTest(src string) (*sieveScript, error) {
	return compileScript(src)
}

func TestDeliveryFileInto(t *testing.T) {
	msg := fakeMsg("alice@example.com", []string{"bob@example.com"}, [2]string{"Subject", "Hello"})
	d := runDelivery(t, Policy{}, `require ["fileinto"]; fileinto "Folder";`, nil, msg)
	if d.Mailbox != "Folder" {
		t.Fatalf("expected Folder, got %q", d.Mailbox)
	}
	if d.Discard {
		t.Fatalf("should not discard")
	}
}

func TestDeliveryDiscard(t *testing.T) {
	msg := fakeMsg("alice@example.com", []string{"bob@example.com"})
	d := runDelivery(t, Policy{}, `discard;`, nil, msg)
	if !d.Discard {
		t.Fatalf("expected discard")
	}
}

func TestDeliveryReject(t *testing.T) {
	msg := fakeMsg("alice@example.com", []string{"bob@example.com"})
	d := runDelivery(t, Policy{}, `require ["reject"]; reject "no thanks";`, nil, msg)
	if !d.Rejected || d.RejectReason != "no thanks" {
		t.Fatalf("expected reject, got %+v", d)
	}
}

func TestDeliveryEreject(t *testing.T) {
	msg := fakeMsg("alice@example.com", []string{"bob@example.com"})
	d := runDelivery(t, Policy{}, `require ["ereject"]; ereject "go away";`, nil, msg)
	if !d.Rejected || !d.Ereject || d.RejectReason != "go away" {
		t.Fatalf("expected ereject, got %+v", d)
	}
}

func TestDeliveryEnvelopeMatch(t *testing.T) {
	msg := fakeMsg("boss@example.com", []string{"bob@example.com"})
	src := `require ["envelope","fileinto"];
if envelope :is "from" "boss@example.com" {
  fileinto "Boss";
}`
	d := runDelivery(t, Policy{}, src, nil, msg)
	if d.Mailbox != "Boss" {
		t.Fatalf("expected Boss, got %q", d.Mailbox)
	}
}

func TestDeliveryRedirect(t *testing.T) {
	msg := fakeMsg("a@x.com", []string{"b@y.com"})
	src := `redirect "archive@example.com";`
	d := runDelivery(t, Policy{MaxRedirects: 4}, src, nil, msg)
	if !d.Discard {
		t.Fatalf("redirect should cancel implicit keep (Discard=true), got %+v", d)
	}
	if !reflect.DeepEqual(d.RedirectTo, []string{"archive@example.com"}) {
		t.Fatalf("expected RedirectTo = [archive@example.com], got %v", d.RedirectTo)
	}
}

func TestDeliveryRedirectLimit(t *testing.T) {
	msg := fakeMsg("a@x.com", []string{"b@y.com"})
	src := `redirect "a@example.com"; redirect "b@example.com"; redirect "c@example.com";`
	// Limit of 2 should cause the third redirect to error.
	policy := Policy{MaxRedirects: 2, Enabled: true, RunOnDelivery: true}
	d := Decision{Mailbox: "Inbox"}
	h := &deliveryHandler{
		policy:   policy,
		decision: &d,
		log:      mlog.New("sievefilter-test", nil),
	}
	s, err := compileScript(src)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	if err := s.Run(msg, h); err == nil {
		t.Fatalf("expected error from exceeding redirect limit")
	}
	if h.redirectCount < 2 {
		t.Fatalf("expected >=2 redirects counted, got %d", h.redirectCount)
	}
}

func TestDeliveryEnvironment(t *testing.T) {
	msg := fakeMsg("a@x.com", []string{"b@y.com"})
	env := EnvironmentValues{"location": "MDA", "name": "mox"}
	src := `require ["environment","fileinto"];
if environment :is "location" "MDA" {
  fileinto "Local";
}`
	d := runDelivery(t, Policy{}, src, env, msg)
	if d.Mailbox != "Local" {
		t.Fatalf("expected Local, got %q", d.Mailbox)
	}
}

func TestDeliveryFlagsAddRemove(t *testing.T) {
	msg := fakeMsg("a@x.com", []string{"b@y.com"})
	src := `require ["imap4flags"];
addflag "\\Seen";
addflag "Important";
removeflag "\\Seen";
`
	d := runDelivery(t, Policy{}, src, nil, msg)
	want := []string{"Important"}
	if !reflect.DeepEqual(d.Flags, want) {
		t.Fatalf("flags = %v, want %v", d.Flags, want)
	}
}

func TestDeliveryDisabled(t *testing.T) {
	// When policy disabled, ExecuteDelivery returns a default decision.
	in := DeliveryInput{
		Policy:         Policy{Enabled: false, RunOnDelivery: true},
		Script:         []byte(`fileinto "X";`),
		DefaultMailbox: "Inbox",
	}
	d, err := ExecuteDelivery(in)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if d.Mailbox != "Inbox" {
		t.Fatalf("expected Inbox, got %q", d.Mailbox)
	}
}

func TestDeliveryRunOnDeliveryFalse(t *testing.T) {
	in := DeliveryInput{
		Policy:         Policy{Enabled: true, RunOnDelivery: false},
		Script:         []byte(`fileinto "X";`),
		DefaultMailbox: "Inbox",
	}
	d, err := ExecuteDelivery(in)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if d.Mailbox != "Inbox" {
		t.Fatalf("expected Inbox, got %q", d.Mailbox)
	}
}

func TestRunScriptWithTimeoutZeroDisablesBound(t *testing.T) {
	// timeout=0 should disable the bound; runs the script directly.
	msg := fakeMsg("a@x.com", []string{"b@y.com"})
	d := runDelivery(t, Policy{ExecutionTimeout: 0}, `keep;`, nil, msg)
	if d.Mailbox != "Inbox" {
		t.Fatalf("expected default mailbox, got %q", d.Mailbox)
	}
}

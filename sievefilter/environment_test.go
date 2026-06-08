package sievefilter

import (
	"strings"
	"testing"

	sieve "github.com/hilli/sieve-go"
	"github.com/hilli/sieve-go/message"
)

// fakeHandler implements both sieve.Handler and EnvironmentProvider.
type fakeHandler struct {
	delivered string
	env       map[string]string
}

func (h *fakeHandler) Keep() error                { h.delivered = "INBOX"; return nil }
func (h *fakeHandler) Discard() error             { h.delivered = "/dev/null"; return nil }
func (h *fakeHandler) Redirect(addr string) error { return nil }
func (h *fakeHandler) FileInto(mb string) error   { h.delivered = mb; return nil }
func (h *fakeHandler) SieveEnvironment(name string) (string, bool) {
	v, ok := h.env[name]
	return v, ok
}

func runScript(t *testing.T, src string, h *fakeHandler, msg message.Message) {
	t.Helper()
	s, err := sieve.Compile(src)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	if err := s.Run(msg, h); err != nil {
		t.Fatalf("run: %v", err)
	}
}

func TestEnvironmentMatch(t *testing.T) {
	h := &fakeHandler{env: map[string]string{
		"location": "MDA",
		"name":     "mox",
	}}
	msg := message.NewBuilder().
		AddHeader("Subject", "test").
		Build()

	src := `require ["environment","fileinto"];
if environment :is "location" "MDA" {
  fileinto "Filtered";
}`
	runScript(t, src, h, msg)
	if h.delivered != "Filtered" {
		t.Fatalf("expected Filtered, got %q", h.delivered)
	}
}

func TestEnvironmentUnknownItemFails(t *testing.T) {
	h := &fakeHandler{env: map[string]string{}}
	msg := message.NewBuilder().Build()

	src := `require ["environment","fileinto"];
if environment :is "no.such.item" "anything" {
  fileinto "Wrong";
}`
	runScript(t, src, h, msg)
	if h.delivered != "INBOX" {
		t.Fatalf("expected implicit keep to INBOX, got %q", h.delivered)
	}
}

func TestEnvironmentContainsMatch(t *testing.T) {
	h := &fakeHandler{env: map[string]string{
		"remote-ip": "192.0.2.42",
	}}
	msg := message.NewBuilder().Build()

	src := `require ["environment","fileinto"];
if environment :contains "remote-ip" "192.0.2" {
  fileinto "Net";
}`
	runScript(t, src, h, msg)
	if h.delivered != "Net" {
		t.Fatalf("expected Net, got %q", h.delivered)
	}
}

func TestValidateEnvironment(t *testing.T) {
	// Compile-only check that scripts using "environment" validate.
	src := `require ["environment"];
if environment :is "location" "MS" { discard; }`
	if _, err := Validate([]byte(src)); err != nil {
		t.Fatalf("expected ok, got %v", err)
	}
	// Without require, validation should fail.
	bad := `if environment :is "location" "MS" { discard; }`
	if _, err := Validate([]byte(bad)); err == nil || !strings.Contains(err.Error(), "environment") {
		t.Fatalf("expected error about environment, got %v", err)
	}
}

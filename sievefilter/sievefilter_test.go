package sievefilter

import (
	"testing"
	"time"

	"github.com/mjl-/mox/config"
)

func ptrBool(b bool) *bool { return &b }

func TestResolveDefault(t *testing.T) {
	p := Resolve(nil, nil, nil)
	if p.Enabled {
		t.Fatalf("default should be disabled")
	}
	if p.MaxScripts != config.SieveDefaultMaxScripts {
		t.Fatalf("default MaxScripts mismatch")
	}
	if p.FailureMode != "tempfail" {
		t.Fatalf("default FailureMode mismatch")
	}
}

func TestResolveInheritance(t *testing.T) {
	server := &config.Sieve{
		Enabled:       ptrBool(true),
		MaxScriptSize: 1000,
		MaxScripts:    5,
	}
	domain := &config.Sieve{
		MaxScriptSize: 2000,
	}
	account := &config.Sieve{
		Enabled: ptrBool(false),
	}
	p := Resolve(server, domain, account)
	if p.Enabled {
		t.Fatalf("account false should override")
	}
	if p.MaxScriptSize != 2000 {
		t.Fatalf("domain MaxScriptSize should win, got %d", p.MaxScriptSize)
	}
	if p.MaxScripts != 5 {
		t.Fatalf("server MaxScripts should be inherited, got %d", p.MaxScripts)
	}
}

func TestResolveTimings(t *testing.T) {
	server := &config.Sieve{ExecutionTimeout: 5 * time.Second}
	p := Resolve(server, nil, nil)
	if p.ExecutionTimeout != 5*time.Second {
		t.Fatalf("got %v", p.ExecutionTimeout)
	}
}

func TestValidateOK(t *testing.T) {
	tests := []string{
		`keep;`,
		`discard;`,
		`require ["fileinto"]; fileinto "Folder";`,
		`require ["fileinto","envelope"]; if envelope :is "to" "x@y" { fileinto "X"; }`,
		`require ["reject"]; reject "spam not allowed";`,
		`require ["vacation"]; vacation "On holiday";`,
		`require ["imap4flags"]; setflag "\\Seen";`,
		`require ["editheader"]; addheader "X-Mox" "test";`,
	}
	for _, src := range tests {
		if _, err := Validate([]byte(src)); err != nil {
			t.Errorf("expected ok for %q, got %v", src, err)
		}
	}
}

func TestValidateBad(t *testing.T) {
	tests := []string{
		``,
		`not_a_command;`,
		`if header :mime :contains "content-type" "text" { keep; }`, // :mime tag without require "mime"
		`require ["nonexistent-cap-xyz"];`,
	}
	for _, src := range tests {
		if _, err := Validate([]byte(src)); err == nil {
			t.Errorf("expected error for %q", src)
		}
	}
}

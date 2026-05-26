// Package sievefilter integrates Sieve mail filtering into mox. It owns the
// embedding of github.com/hilli/sieve-go (compilation, validation, execution),
// configuration policy inheritance (server -> domain -> account), and host
// extensions such as the RFC 5183 "environment" extension that requires
// host-supplied values.
//
// The Sieve language and ManageSieve protocol code is split:
//   - this package implements compile/validate/execute and the policy model.
//   - package managesieveserver implements RFC 5804 (ManageSieve).
//   - SMTP and IMAP server hook points call into ExecuteDelivery and
//     ExecuteIMAPEvent as appropriate.
package sievefilter

import (
	"fmt"
	"strings"
	"time"

	sieve "github.com/hilli/sieve-go"

	"github.com/mjl-/mox/config"
)

// Policy is the effective Sieve policy after inheritance. All fields are
// populated with defaults if not explicitly set anywhere in the chain.
type Policy struct {
	Enabled             bool
	MaxScriptSize       int64
	MaxScripts          int
	MaxTotalScriptSize  int64
	ExecutionTimeout    time.Duration
	MaxRedirects        int
	AutoCreateMailboxes bool
	RunOnDelivery       bool
	RunOnIMAPEvents     bool
	FailureMode         string // "tempfail" or "keep".
}

// DefaultPolicy returns the default Sieve policy used when no scope sets any
// values. Sieve is disabled by default.
func DefaultPolicy() Policy {
	return Policy{
		Enabled:             false,
		MaxScriptSize:       config.SieveDefaultMaxScriptSize,
		MaxScripts:          config.SieveDefaultMaxScripts,
		MaxTotalScriptSize:  config.SieveDefaultMaxTotalScriptSize,
		ExecutionTimeout:    config.SieveDefaultExecutionTimeout,
		MaxRedirects:        config.SieveDefaultMaxRedirects,
		AutoCreateMailboxes: true,
		RunOnDelivery:       true,
		RunOnIMAPEvents:     false,
		FailureMode:         "tempfail",
	}
}

// Resolve returns the effective Policy given server, domain and account level
// settings, applying inheritance. A more specific (later) non-nil pointer
// overrides an earlier one. Booleans use tri-state semantics via pointer fields
// in config.Sieve. Numeric/string fields use "most specific non-zero wins".
func Resolve(server, domain, account *config.Sieve) Policy {
	p := DefaultPolicy()
	apply := func(s *config.Sieve) {
		if s == nil {
			return
		}
		if s.Enabled != nil {
			p.Enabled = *s.Enabled
		}
		if s.MaxScriptSize > 0 {
			p.MaxScriptSize = s.MaxScriptSize
		}
		if s.MaxScripts > 0 {
			p.MaxScripts = s.MaxScripts
		}
		if s.MaxTotalScriptSize > 0 {
			p.MaxTotalScriptSize = s.MaxTotalScriptSize
		}
		if s.ExecutionTimeout > 0 {
			p.ExecutionTimeout = s.ExecutionTimeout
		}
		if s.MaxRedirects > 0 {
			p.MaxRedirects = s.MaxRedirects
		}
		if s.AutoCreateMailboxes != nil {
			p.AutoCreateMailboxes = *s.AutoCreateMailboxes
		}
		if s.RunOnDelivery != nil {
			p.RunOnDelivery = *s.RunOnDelivery
		}
		if s.RunOnIMAPEvents != nil {
			p.RunOnIMAPEvents = *s.RunOnIMAPEvents
		}
		if s.FailureMode != "" {
			p.FailureMode = s.FailureMode
		}
	}
	apply(server)
	apply(domain)
	apply(account)
	return p
}

// Validate parses and validates a Sieve script using github.com/hilli/sieve-go
// with the package-default interpreter and all bundled extensions registered.
// It returns nil on success. Returned errors are user-facing and suitable for
// inclusion in a ManageSieve NO response.
func Validate(script []byte) (warnings string, err error) {
	if len(script) == 0 {
		return "", fmt.Errorf("empty script")
	}
	if err := sieve.Validate(string(script)); err != nil {
		return "", fmt.Errorf("invalid sieve script: %s", strings.TrimSpace(err.Error()))
	}
	return "", nil
}

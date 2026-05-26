// Package envelope implements the Sieve "envelope" extension
// (RFC 5228 §5.4). The test compares the SMTP envelope (MAIL FROM,
// RCPT TO) — supplied by the host via message.Message.Envelope — to
// keys, with optional address-part and match-type tags.
package envelope

import (
	"github.com/hilli/sieve-go"
	"github.com/hilli/sieve-go/interpreter"
)

const Capability = "envelope"

func Register(i *sieve.Interpreter) {
	i.Registry().RegisterTest("envelope", interpreter.TestEnvelope, Capability)
}

func init() { Register(sieve.Default()) }

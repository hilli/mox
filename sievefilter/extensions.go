package sievefilter

// Blank imports register the bundled Sieve extensions with sieve-go's default
// interpreter, making them available to scripts via `require ["..."];`.
//
// We enable all upstream-supported extensions. Risky actions (reject, ereject,
// vacation, editheader, redirect side effects) are handled by Mox's Handler
// implementation at execution time, not by gating capability registration.
import (
	_ "github.com/hilli/sieve-go/extensions/body"
	_ "github.com/hilli/sieve-go/extensions/editheader"
	_ "github.com/hilli/sieve-go/extensions/envelope"
	_ "github.com/hilli/sieve-go/extensions/fileinto"
	_ "github.com/hilli/sieve-go/extensions/imap4flags"
	_ "github.com/hilli/sieve-go/extensions/mime"
	_ "github.com/hilli/sieve-go/extensions/regex"
	_ "github.com/hilli/sieve-go/extensions/reject"
	_ "github.com/hilli/sieve-go/extensions/relational"
	_ "github.com/hilli/sieve-go/extensions/subaddress"
	_ "github.com/hilli/sieve-go/extensions/vacation"
	_ "github.com/hilli/sieve-go/extensions/variables"
)

// Package subaddress implements the Sieve "subaddress" extension
// (RFC 5233). It adds the address parts `:user` and `:detail`, which
// split the local-part of an address around the recipient-delimiter
// (defaults to '+').
//
// Example:
//
//	require ["envelope", "subaddress"];
//	if envelope :user "to" "alice"   { fileinto "Inbox"; }
//	if envelope :detail "to" "spam"  { fileinto "Junk"; }
//
// The delimiter is fixed at '+' per the most common deployment; hosts
// needing a different delimiter can use SetDelimiter from their setup.
package subaddress

import (
	"strings"

	"github.com/hilli/sieve-go"
)

const Capability = "subaddress"

var delimiter = "+"

// SetDelimiter overrides the local-part recipient-delimiter (default
// "+"). Affects all future evaluations on the default interpreter.
func SetDelimiter(d string) { delimiter = d }

// Register installs the :user and :detail address-part tags.
func Register(i *sieve.Interpreter) {
	r := i.Registry()
	r.RegisterAddressPart(":user", func(addr string) string {
		local := localOf(addr)
		if idx := strings.Index(local, delimiter); idx >= 0 {
			return local[:idx]
		}
		return local
	}, Capability)
	r.RegisterAddressPart(":detail", func(addr string) string {
		local := localOf(addr)
		if idx := strings.Index(local, delimiter); idx >= 0 {
			return local[idx+len(delimiter):]
		}
		return ""
	}, Capability)
}

func init() { Register(sieve.Default()) }

func localOf(addr string) string {
	if at := strings.LastIndexByte(addr, '@'); at >= 0 {
		return addr[:at]
	}
	return addr
}

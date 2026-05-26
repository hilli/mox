// Package regex implements the Sieve ":regex" match type from
// draft-ietf-sieve-regex (the "regex" capability). Once registered, any
// test that takes a match-type tag (header, address, envelope, body, ...)
// can use :regex with regular expressions in Go's regexp/syntax (RE2;
// add explicit ^ / $ anchors if you want full-string matching).
package regex

import (
	"regexp"
	"sync"

	"github.com/hilli/sieve-go"
)

const Capability = "regex"

func Register(i *sieve.Interpreter) {
	i.Registry().RegisterMatchType(":regex", matchRegex, Capability)
}

func init() { Register(sieve.Default()) }

// regexCache memoises compiled patterns. Sieve scripts tend to reuse the
// same handful of patterns per evaluation, so this avoids recompiling on
// every header value.
var (
	regexMu    sync.RWMutex
	regexCache = map[string]*regexp.Regexp{}
)

func compile(pat string) *regexp.Regexp {
	regexMu.RLock()
	if r, ok := regexCache[pat]; ok {
		regexMu.RUnlock()
		return r
	}
	regexMu.RUnlock()
	r, err := regexp.Compile(pat)
	if err != nil {
		// On bad patterns we cache nil so we only complain once. Match
		// then deterministically returns false.
		regexMu.Lock()
		regexCache[pat] = nil
		regexMu.Unlock()
		return nil
	}
	regexMu.Lock()
	regexCache[pat] = r
	regexMu.Unlock()
	return r
}

func matchRegex(value, key string) bool {
	r := compile(key)
	if r == nil {
		return false
	}
	return r.MatchString(value)
}

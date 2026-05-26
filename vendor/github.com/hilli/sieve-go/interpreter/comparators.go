package interpreter

import "strings"

// asciiCasemap implements the i;ascii-casemap comparator (RFC 4790,
// referenced by RFC 5228): case-insensitive ASCII.
type asciiCasemap struct{}

func (asciiCasemap) Equal(a, b string) bool { return strings.EqualFold(a, b) }
func (asciiCasemap) Contains(s, key string) bool {
	return strings.Contains(strings.ToLower(s), strings.ToLower(key))
}
func (asciiCasemap) Matches(s, pat string) bool {
	_, ok := matchAndCapture(s, pat, true)
	return ok
}

// octet implements the i;octet comparator: byte-exact comparison.
type octet struct{}

func (octet) Equal(a, b string) bool      { return a == b }
func (octet) Contains(s, key string) bool { return strings.Contains(s, key) }
func (octet) Matches(s, pat string) bool {
	_, ok := matchAndCapture(s, pat, false)
	return ok
}

// matchAndCapture runs the Sieve glob match (RFC 5228 §2.7.1) and
// returns the captures for `${0}..${9}` (RFC 5229 §6.1) if the match
// succeeds. captures[0] is the entire matched string; captures[i] (i>=1)
// corresponds to the i-th '?' or '*' in pattern order. foldCase enables
// the i;ascii-casemap fold; equality is still measured on the original
// strings for capture extraction.
func matchAndCapture(s, pat string, foldCase bool) ([]string, bool) {
	eq := func(a, b byte) bool {
		if foldCase {
			if a >= 'A' && a <= 'Z' {
				a += 'a' - 'A'
			}
			if b >= 'A' && b <= 'Z' {
				b += 'a' - 'A'
			}
		}
		return a == b
	}
	var caps []string
	var match func(si, pi int) bool
	match = func(si, pi int) bool {
		for pi < len(pat) {
			c := pat[pi]
			switch {
			case c == '\\' && pi+1 < len(pat):
				if si >= len(s) || !eq(s[si], pat[pi+1]) {
					return false
				}
				si++
				pi += 2
			case c == '?':
				if si >= len(s) {
					return false
				}
				caps = append(caps, s[si:si+1])
				si++
				pi++
			case c == '*':
				// Greedy with backtracking.
				saved := len(caps)
				for k := len(s); k >= si; k-- {
					caps = append(caps[:saved], s[si:k])
					if match(k, pi+1) {
						return true
					}
				}
				caps = caps[:saved]
				return false
			default:
				if si >= len(s) || !eq(s[si], c) {
					return false
				}
				si++
				pi++
			}
		}
		return si == len(s)
	}
	if !match(0, 0) {
		return nil, false
	}
	return append([]string{s}, caps...), true
}

// wildcardMatch is kept for compatibility with callers that only need a
// boolean and the legacy lower-case semantics.
func wildcardMatch(s, pat string) bool {
	_, ok := matchAndCapture(s, pat, true)
	return ok
}


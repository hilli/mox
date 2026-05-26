// Package token defines the lexical tokens produced by the Sieve lexer.
//
// RFC 5228 has only a small number of structurally significant tokens. Most
// names (commands like "fileinto", tests like "address", tagged arguments
// like ":matches") are parsed as identifiers/tags and resolved later by the
// extension registry. Keeping the lexer minimal makes it easy to add new
// extensions without changing tokenization.
package token

type TokenType string

type Token struct {
	Type    TokenType
	Literal string
	Line    int
	Col     int
}

const (
	ILLEGAL TokenType = "ILLEGAL"
	EOF     TokenType = "EOF"

	IDENT  TokenType = "IDENT"  // require, if, fileinto, address, ...
	TAG    TokenType = ":TAG"   // :matches, :is, :domain, ...
	STRING TokenType = "STRING" // "text" or multi-line text:...
	NUMBER TokenType = "NUMBER" // 123, 1K, 2M, 3G (canonicalized to bytes)

	COMMA     TokenType = ","
	SEMICOLON TokenType = ";"
	LPAREN    TokenType = "("
	RPAREN    TokenType = ")"
	LBRACE    TokenType = "{"
	RBRACE    TokenType = "}"
	LBRACK    TokenType = "["
	RBRACK    TokenType = "]"
)

// Reserved identifiers that the parser treats specially (control flow and
// the require directive). Everything else is a plain IDENT resolved through
// the extension registry at parse/run time.
var reservedIdents = map[string]bool{
	"require": true,
	"if":      true,
	"elsif":   true,
	"else":    true,
	"stop":    true,
	"true":    true,
	"false":   true,
	"not":     true,
	"anyof":   true,
	"allof":   true,
}

// IsReserved reports whether an identifier is one of the reserved Sieve
// control identifiers. The lexer does not use this — it's exposed for the
// parser.
func IsReserved(ident string) bool {
	return reservedIdents[ident]
}

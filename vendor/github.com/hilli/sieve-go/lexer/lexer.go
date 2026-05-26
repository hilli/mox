// Package lexer turns Sieve source text into a stream of tokens.
//
// It implements the lexical rules of RFC 5228 §2.1–§2.4: identifiers,
// tagged arguments (:tag), quoted strings, multi-line strings (text:),
// numbers with K/M/G quantifiers, hash and bracket comments, and the
// structural punctuation. Position information (1-based line and column)
// is attached to each token to aid error reporting.
package lexer

import (
	"fmt"
	"strings"

	"github.com/hilli/sieve-go/token"
)

type Lexer struct {
	input string
	pos   int // current position (points to current char)
	read  int // next read position
	ch    byte

	line int // 1-based current line
	col  int // 1-based current column (of ch)
}

func New(input string) *Lexer {
	l := &Lexer{input: input, line: 1, col: 0}
	l.readChar()
	return l
}

func (l *Lexer) readChar() {
	if l.read >= len(l.input) {
		l.ch = 0
	} else {
		l.ch = l.input[l.read]
	}
	l.pos = l.read
	l.read++
	if l.ch == '\n' {
		l.line++
		l.col = 0
	} else {
		l.col++
	}
}

func (l *Lexer) peek() byte {
	if l.read >= len(l.input) {
		return 0
	}
	return l.input[l.read]
}

// NextToken returns the next token. EOF tokens are returned indefinitely
// once the input is exhausted.
func (l *Lexer) NextToken() token.Token {
	l.skipWhitespaceAndComments()

	startLine, startCol := l.line, l.col

	switch l.ch {
	case 0:
		return token.Token{Type: token.EOF, Literal: "", Line: startLine, Col: startCol}
	case ',':
		l.readChar()
		return token.Token{Type: token.COMMA, Literal: ",", Line: startLine, Col: startCol}
	case ';':
		l.readChar()
		return token.Token{Type: token.SEMICOLON, Literal: ";", Line: startLine, Col: startCol}
	case '(':
		l.readChar()
		return token.Token{Type: token.LPAREN, Literal: "(", Line: startLine, Col: startCol}
	case ')':
		l.readChar()
		return token.Token{Type: token.RPAREN, Literal: ")", Line: startLine, Col: startCol}
	case '{':
		l.readChar()
		return token.Token{Type: token.LBRACE, Literal: "{", Line: startLine, Col: startCol}
	case '}':
		l.readChar()
		return token.Token{Type: token.RBRACE, Literal: "}", Line: startLine, Col: startCol}
	case '[':
		l.readChar()
		return token.Token{Type: token.LBRACK, Literal: "[", Line: startLine, Col: startCol}
	case ']':
		l.readChar()
		return token.Token{Type: token.RBRACK, Literal: "]", Line: startLine, Col: startCol}
	case '"':
		s, ok := l.readQuotedString()
		if !ok {
			return token.Token{Type: token.ILLEGAL, Literal: s, Line: startLine, Col: startCol}
		}
		return token.Token{Type: token.STRING, Literal: s, Line: startLine, Col: startCol}
	case ':':
		if isIdentStart(l.peek()) {
			l.readChar() // consume ':'
			name := l.readIdentifier()
			return token.Token{Type: token.TAG, Literal: ":" + name, Line: startLine, Col: startCol}
		}
		ch := l.ch
		l.readChar()
		return token.Token{Type: token.ILLEGAL, Literal: string(ch), Line: startLine, Col: startCol}
	}

	if isIdentStart(l.ch) {
		name := l.readIdentifier()
		// "text:" introduces a multi-line string (RFC 5228 §2.4.2).
		if name == "text" && l.ch == ':' {
			l.readChar() // consume ':'
			s, ok := l.readMultilineString()
			if !ok {
				return token.Token{Type: token.ILLEGAL, Literal: s, Line: startLine, Col: startCol}
			}
			return token.Token{Type: token.STRING, Literal: s, Line: startLine, Col: startCol}
		}
		return token.Token{Type: token.IDENT, Literal: name, Line: startLine, Col: startCol}
	}

	if isDigit(l.ch) {
		lit, ok := l.readNumber()
		if !ok {
			return token.Token{Type: token.ILLEGAL, Literal: lit, Line: startLine, Col: startCol}
		}
		return token.Token{Type: token.NUMBER, Literal: lit, Line: startLine, Col: startCol}
	}

	ch := l.ch
	l.readChar()
	return token.Token{Type: token.ILLEGAL, Literal: string(ch), Line: startLine, Col: startCol}
}

func (l *Lexer) skipWhitespaceAndComments() {
	for {
		switch l.ch {
		case ' ', '\t', '\r', '\n':
			l.readChar()
		case '#':
			for l.ch != 0 && l.ch != '\n' {
				l.readChar()
			}
		case '/':
			if l.peek() == '*' {
				l.readChar() // '/'
				l.readChar() // '*'
				for l.ch != 0 {
					if l.ch == '*' && l.peek() == '/' {
						l.readChar()
						l.readChar()
						break
					}
					l.readChar()
				}
			} else {
				return
			}
		default:
			return
		}
	}
}

// readIdentifier reads an identifier per RFC 5228: starts with ASCII letter
// or '_', continues with letters, digits, or '_'.
func (l *Lexer) readIdentifier() string {
	start := l.pos
	for isIdentPart(l.ch) {
		l.readChar()
	}
	return l.input[start:l.pos]
}

// readQuotedString reads a "..."-style string with backslash escapes for
// `\\` and `\"`. The returned string contains the decoded value (without
// surrounding quotes).
func (l *Lexer) readQuotedString() (string, bool) {
	l.readChar() // consume opening "
	var b strings.Builder
	for {
		switch l.ch {
		case 0:
			return b.String(), false
		case '"':
			l.readChar() // consume closing "
			return b.String(), true
		case '\\':
			l.readChar()
			switch l.ch {
			case '\\', '"':
				b.WriteByte(l.ch)
				l.readChar()
			case 0:
				return b.String(), false
			default:
				// RFC 5228 §2.4.2: an undefined escape is the character
				// itself (the backslash is ignored).
				b.WriteByte(l.ch)
				l.readChar()
			}
		default:
			b.WriteByte(l.ch)
			l.readChar()
		}
	}
}

// readMultilineString reads a multi-line string introduced by "text:".
// The opening must be followed by optional whitespace, optional hash
// comment, and a newline. The string is terminated by a line containing
// only a single "." (dot-stuffing per RFC 5228 §2.4.2 is reversed: a
// leading ".." becomes "."). The caller has already consumed "text:".
func (l *Lexer) readMultilineString() (string, bool) {
	// Skip horizontal whitespace and optional hash comment up to newline.
	for l.ch == ' ' || l.ch == '\t' {
		l.readChar()
	}
	if l.ch == '#' {
		for l.ch != 0 && l.ch != '\n' {
			l.readChar()
		}
	}
	if l.ch != '\n' {
		return "", false
	}
	l.readChar() // consume newline

	var b strings.Builder
	for {
		if l.ch == 0 {
			return b.String(), false
		}
		// Capture current line.
		lineStart := l.pos
		for l.ch != 0 && l.ch != '\n' {
			l.readChar()
		}
		line := l.input[lineStart:l.pos]
		// Terminator: a line containing only ".".
		if line == "." {
			if l.ch == '\n' {
				l.readChar()
			}
			return b.String(), true
		}
		// Dot-stuffing reversal.
		if strings.HasPrefix(line, "..") {
			line = line[1:]
		}
		b.WriteString(line)
		if l.ch == '\n' {
			b.WriteByte('\n')
			l.readChar()
		}
	}
}

// readNumber reads a non-negative decimal integer, optionally followed by
// a K/M/G quantifier (RFC 5228 §2.4.1). The token's Literal is the
// canonical decimal form in bytes.
func (l *Lexer) readNumber() (string, bool) {
	start := l.pos
	for isDigit(l.ch) {
		l.readChar()
	}
	digits := l.input[start:l.pos]

	mult := uint64(1)
	switch l.ch {
	case 'K', 'k':
		mult = 1024
		l.readChar()
	case 'M', 'm':
		mult = 1024 * 1024
		l.readChar()
	case 'G', 'g':
		mult = 1024 * 1024 * 1024
		l.readChar()
	}

	var n uint64
	for _, c := range digits {
		d := uint64(c - '0')
		n = n*10 + d
	}
	return fmt.Sprintf("%d", n*mult), true
}

func isIdentStart(ch byte) bool {
	return ('a' <= ch && ch <= 'z') || ('A' <= ch && ch <= 'Z') || ch == '_'
}

func isIdentPart(ch byte) bool {
	return isIdentStart(ch) || isDigit(ch)
}

func isDigit(ch byte) bool {
	return '0' <= ch && ch <= '9'
}

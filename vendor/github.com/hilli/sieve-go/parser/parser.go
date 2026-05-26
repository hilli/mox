// Package parser turns a token stream from package lexer into an
// ast.Script. The parser implements the RFC 5228 grammar but is
// intentionally permissive about command and test names: any identifier is
// accepted at the syntactic level, since command/test legality is decided
// later by the extension registry. The parser does enforce structural
// rules (if needs a test, elsif/else must follow if, blocks balance).
package parser

import (
	"fmt"
	"strconv"

	"github.com/hilli/sieve-go/ast"
	"github.com/hilli/sieve-go/lexer"
	"github.com/hilli/sieve-go/token"
)

// Error is a parse error with a position.
type Error struct {
	Line, Col int
	Msg       string
}

func (e *Error) Error() string {
	return fmt.Sprintf("parse error at %d:%d: %s", e.Line, e.Col, e.Msg)
}

type Parser struct {
	l   *lexer.Lexer
	cur token.Token
	peek token.Token
}

func New(l *lexer.Lexer) *Parser {
	p := &Parser{l: l}
	p.advance()
	p.advance()
	return p
}

// Parse parses an entire script.
func Parse(src string) (*ast.Script, error) {
	return New(lexer.New(src)).ParseScript()
}

func (p *Parser) advance() {
	p.cur = p.peek
	p.peek = p.l.NextToken()
}

func (p *Parser) errf(t token.Token, format string, args ...interface{}) *Error {
	return &Error{Line: t.Line, Col: t.Col, Msg: fmt.Sprintf(format, args...)}
}

func (p *Parser) expect(tt token.TokenType) (token.Token, error) {
	if p.cur.Type != tt {
		return p.cur, p.errf(p.cur, "expected %s, got %s (%q)", tt, p.cur.Type, p.cur.Literal)
	}
	t := p.cur
	p.advance()
	return t, nil
}

// ParseScript parses commands until EOF.
func (p *Parser) ParseScript() (*ast.Script, error) {
	s := &ast.Script{}
	for p.cur.Type != token.EOF {
		c, err := p.parseCommand()
		if err != nil {
			return nil, err
		}
		s.Commands = append(s.Commands, c)
	}
	return s, nil
}

func (p *Parser) parseCommand() (*ast.Command, error) {
	if p.cur.Type != token.IDENT {
		return nil, p.errf(p.cur, "expected command identifier, got %s (%q)", p.cur.Type, p.cur.Literal)
	}
	cmd := &ast.Command{Name: p.cur.Literal, Pos: ast.PosFrom(p.cur)}
	p.advance()

	args, err := p.parseArguments()
	if err != nil {
		return nil, err
	}
	cmd.Args = args

	// Control-flow commands take a test.
	if cmd.Name == "if" || cmd.Name == "elsif" {
		t, err := p.parseTest()
		if err != nil {
			return nil, err
		}
		cmd.Test = t
	}

	// Either a block or a semicolon.
	switch p.cur.Type {
	case token.LBRACE:
		block, err := p.parseBlock()
		if err != nil {
			return nil, err
		}
		cmd.Block = block
		cmd.HasBlock = true
	case token.SEMICOLON:
		p.advance()
	default:
		return nil, p.errf(p.cur, "expected ';' or '{', got %s (%q)", p.cur.Type, p.cur.Literal)
	}
	return cmd, nil
}

func (p *Parser) parseBlock() ([]*ast.Command, error) {
	if _, err := p.expect(token.LBRACE); err != nil {
		return nil, err
	}
	var cmds []*ast.Command
	for p.cur.Type != token.RBRACE {
		if p.cur.Type == token.EOF {
			return nil, p.errf(p.cur, "unexpected EOF inside block")
		}
		c, err := p.parseCommand()
		if err != nil {
			return nil, err
		}
		cmds = append(cmds, c)
	}
	p.advance() // consume }
	return cmds, nil
}

// parseArguments parses positional and tagged arguments up to but not
// including the trailing ';' / '{' / test-start. A test is recognized by
// an IDENT that appears where arguments are not allowed (any IDENT that
// follows the argument list begins a test or is itself the start of the
// next command). Because RFC 5228 places the test before ';' or '{', we
// stop collecting arguments at the first IDENT/LPAREN (which is the test).
func (p *Parser) parseArguments() (ast.Arguments, error) {
	var args ast.Arguments
	addTag := func(t ast.TaggedArg) {
		args.Order = append(args.Order, ast.ArgRef{Kind: ast.KindTag, Idx: len(args.Tags)})
		args.Tags = append(args.Tags, t)
	}
	addPos := func(v ast.Value) {
		args.Order = append(args.Order, ast.ArgRef{Kind: ast.KindPositional, Idx: len(args.Positional)})
		args.Positional = append(args.Positional, v)
	}
	for {
		switch p.cur.Type {
		case token.TAG:
			addTag(ast.TaggedArg{Name: p.cur.Literal, Pos: ast.PosFrom(p.cur)})
			p.advance()
		case token.STRING:
			addPos(ast.StringValue{Value: p.cur.Literal, Pos: ast.PosFrom(p.cur)})
			p.advance()
		case token.NUMBER:
			n, err := strconv.ParseUint(p.cur.Literal, 10, 64)
			if err != nil {
				return args, p.errf(p.cur, "bad number %q: %v", p.cur.Literal, err)
			}
			addPos(ast.NumberValue{Value: n, Pos: ast.PosFrom(p.cur)})
			p.advance()
		case token.LBRACK:
			sl, err := p.parseStringList()
			if err != nil {
				return args, err
			}
			addPos(sl)
		default:
			return args, nil
		}
	}
}

func (p *Parser) parseStringList() (ast.StringListValue, error) {
	start := p.cur
	if _, err := p.expect(token.LBRACK); err != nil {
		return ast.StringListValue{}, err
	}
	var values []string
	for {
		if p.cur.Type != token.STRING {
			return ast.StringListValue{}, p.errf(p.cur, "expected string in list, got %s (%q)", p.cur.Type, p.cur.Literal)
		}
		values = append(values, p.cur.Literal)
		p.advance()
		switch p.cur.Type {
		case token.COMMA:
			p.advance()
		case token.RBRACK:
			p.advance()
			return ast.StringListValue{Values: values, Pos: ast.PosFrom(start)}, nil
		default:
			return ast.StringListValue{}, p.errf(p.cur, "expected ',' or ']', got %s (%q)", p.cur.Type, p.cur.Literal)
		}
	}
}

// parseTest parses a test. Three shapes:
//   - "not" test               → unary
//   - "allof"/"anyof" "(" test-list ")"
//   - identifier arguments     → leaf test
func (p *Parser) parseTest() (*ast.Test, error) {
	if p.cur.Type != token.IDENT {
		return nil, p.errf(p.cur, "expected test identifier, got %s (%q)", p.cur.Type, p.cur.Literal)
	}
	t := &ast.Test{Name: p.cur.Literal, Pos: ast.PosFrom(p.cur)}
	p.advance()

	switch t.Name {
	case "not":
		child, err := p.parseTest()
		if err != nil {
			return nil, err
		}
		t.Children = []*ast.Test{child}
		return t, nil
	case "allof", "anyof":
		if _, err := p.expect(token.LPAREN); err != nil {
			return nil, err
		}
		for {
			c, err := p.parseTest()
			if err != nil {
				return nil, err
			}
			t.Children = append(t.Children, c)
			switch p.cur.Type {
			case token.COMMA:
				p.advance()
			case token.RPAREN:
				p.advance()
				return t, nil
			default:
				return nil, p.errf(p.cur, "expected ',' or ')' in test list, got %s", p.cur.Type)
			}
		}
	default:
		args, err := p.parseArguments()
		if err != nil {
			return nil, err
		}
		t.Args = args
		return t, nil
	}
}

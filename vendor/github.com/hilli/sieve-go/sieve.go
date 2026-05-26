// Package sieve is the top-level façade for the Sieve interpreter.
//
// Typical use:
//
//	script, err := sieve.Compile(src)
//	if err != nil { /* syntax/validation error */ }
//	if err := script.Run(msg, handler); err != nil { /* runtime error */ }
//
// For one-off validation use Validate. To register additional extensions,
// use NewInterpreter and access its Registry, then Compile through it.
package sieve

import (
	"github.com/hilli/sieve-go/interpreter"
	"github.com/hilli/sieve-go/message"
	"github.com/hilli/sieve-go/parser"
	"github.com/hilli/sieve-go/registry"
)

// Handler is the host application's action receiver. Extensions that
// define additional actions (e.g. fileinto) define richer interfaces in
// their own packages and type-assert this one.
type Handler = registry.Handler

// Message is the abstract message view consulted by tests.
type Message = message.Message

// Script is a compiled, validated Sieve script.
type Script = interpreter.Script

// Interpreter wraps the registry and core builtins.
type Interpreter = interpreter.Interpreter

// NewInterpreter returns a fresh Interpreter with RFC 5228 builtins
// registered. Extensions can be added via i.Registry().
func NewInterpreter() *Interpreter { return interpreter.New() }

// defaultInterp is used by the package-level helpers Compile/Validate.
// Tests/extensions that need a custom registry should use NewInterpreter.
var defaultInterp = interpreter.New()

// Default returns the package-level interpreter used by Compile and
// Validate. Extension packages call this from their init() to self-register.
func Default() *Interpreter { return defaultInterp }

// Compile parses and validates src using the default interpreter.
func Compile(src string) (*Script, error) {
	a, err := parser.Parse(src)
	if err != nil {
		return nil, err
	}
	return defaultInterp.Compile(a)
}

// Validate parses and validates src without keeping the compiled script.
func Validate(src string) error {
	a, err := parser.Parse(src)
	if err != nil {
		return err
	}
	return defaultInterp.Validate(a)
}

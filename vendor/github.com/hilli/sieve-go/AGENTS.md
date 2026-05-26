# AGENTS.md

Instructions for AI coding agents (Claude, GPT, Copilot, …) working in
this repository. Humans should read `readme.md` and `docs/extensions.md`
instead.

## What this project is

`sieve-go` is a Go library that **parses, validates, and executes Sieve
mail-filtering scripts** (RFC 5228 and selected extensions). It is
embedded into mail-handling applications; it is not a daemon or CLI.

## Module layout

```
sieve.go             top-level façade: Compile, Validate, NewInterpreter, Default
token/               token types
lexer/               source → tokens
ast/                 AST node types
parser/              tokens → ast.Script
registry/            extensible actions / tests / match-types / capabilities
interpreter/         AST walker + RFC 5228 builtins (core.go) + façade types (interpreter.go)
message/             Message interface + net/mail adapter + Builder
extensions/          one package per Sieve extension; each self-registers via init()
  fileinto/          RFC 5232
  envelope/          RFC 5228 §5.4
  body/              RFC 5173
  imap4flags/        RFC 5232 subset
  regex/             draft-ietf-sieve-regex
  mime/              RFC 5703 subset (:mime, :anychild)
examples/
  simple/            embed the library
  validate/          stdin → ok / error CLI
```

## Architectural ground rules

* **The lexer is dumb.** Identifiers, including command and test names,
  are never matched to a fixed keyword list. The parser treats every
  IDENT uniformly; only the parser recognises the control words `if`,
  `elsif`, `else`, `require`, `stop`. Everything else is resolved
  through the registry. Do not add keywords to `token/`.
* **The registry is the source of truth.** Actions, tests, and
  match-types are all registered values, each optionally guarded by a
  capability string. Validation walks the AST and checks the registry;
  nothing in `parser/` or `lexer/` knows about specific extensions.
* **Extensions are leaf packages.** They depend on `sieve`,
  `sieve/ast`, `sieve/registry`, and (for body-style tests) on
  `sieve/interpreter`. They must never be imported by core packages —
  that would create a cycle and defeat the registry pattern.
* **Capabilities mirror `require`.** If an extension adds anything that
  is not RFC 5228 core, it must declare a `Capability` constant and
  pass it as the `requires` argument to register calls. Scripts that
  use the feature without `require ["cap"];` should fail at `Compile`,
  not at `Run`.
* **Host interaction is via interfaces.** Core actions go through
  `registry.Handler` (`Keep`, `Discard`, `Redirect`). Extensions that
  need richer actions define a sub-interface in their own package and
  type-assert it from `ctx.Handler()`. They must return a clear error
  when the assertion fails.

## Public API contract

`sieve.Compile(src) (*Script, error)` and `sieve.Validate(src) error`
use a package-level default interpreter. `sieve.NewInterpreter()`
returns a fresh one for callers that need an isolated registry. Both
`Compile` and `Validate` perform full semantic validation; `Validate`
discards the compiled `Script`.

`Script.Run(msg sieve.Message, h sieve.Handler) error` executes the
script. `Message` is an interface, not a struct — keep it that way.

## Conventions and house style

* Standard Go formatting (`gofmt`). No external linters configured;
  rely on `go vet ./...` and `go test ./...`.
* Doc comments on every exported identifier. Lead with the
  identifier's name. Reference the relevant RFC section when the
  behaviour is RFC-driven.
* Errors are plain `fmt.Errorf` with `%w` wrapping where useful. The
  parser uses a `*parser.Error` with line/col. There is no global
  error registry; do not introduce one without strong reason.
* Tests are table-driven where it improves clarity; otherwise one
  `Test*` per behaviour. Tests for new extensions go in
  `extensions_test.go` (an integration-style test against
  `sieve.Compile`/`Run`) unless the extension also needs unit tests.
* No external dependencies beyond the Go standard library. Adding one
  must be justified.

## Workflow expectations

* Before any code change, read `plan.md` if present in the session
  state for the higher-level intent.
* Run `go vet ./... && go test ./...` after every meaningful change.
  Commits without a passing build are not acceptable.
* **Every new exported function, action, test, match-type, or
  extension must ship with a test in the same package.** A package
  without a `_test.go` file is a bug. The only intentionally untested
  code is the `examples/` directory.
* Aim for ≥ 80 % statement coverage per package; the current baseline
  is in `docs/coverage.md` (regenerate with `go test -cover ./...`).
  Coverage drops are reviewed; if you cannot exercise a branch, add a
  comment explaining why.
* Commit messages use a single short subject line and a body that
  describes *why* and *what*, grouped by bullet points. Always include
  the `Co-authored-by: Copilot` trailer (see workspace instructions).
* Surgical changes only. Do not refactor adjacent code "while you're
  in there" unless the change is required to make the new code work.

## How to add a Sieve extension

See `docs/extensions.md` for the full recipe. The short version: a new
package under `extensions/<name>/`, a `Capability` constant, a
`Register(*sieve.Interpreter)` function, an `init()` that registers on
`sieve.Default()`, an entry in `extensions_test.go`, and a one-line
mention in `readme.md`.

## Things to avoid

* Importing `extensions/*` from any non-extension package.
* Adding command-specific or test-specific logic to the parser.
* Hard-coding tag names (`":is"`, `":domain"`, …) in places other than
  the package that owns them. Match-type tags belong in the registry;
  address-part and other tags currently live with the test that uses
  them.
* Returning typed errors from extension packages unless the type is
  meant to be inspected by callers; prefer `fmt.Errorf`.
* Mutating the registry after first `Compile` — registration should
  happen at process start (`init()` or program startup), not during
  execution.

## Out of scope (for now)

* Sieve variables (RFC 5229) — would unlock many other extensions but
  requires AST and runtime changes.
* ManageSieve (RFC 5804) — out of repository scope.
* A standalone CLI binary. The `examples/validate` and
  `examples/simple` commands are demonstrations, not products.

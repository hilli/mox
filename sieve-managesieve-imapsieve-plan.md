# Sieve, ManageSieve, and IMAPSIEVE Integration Plan

## Goals

- Integrate `github.com/hilli/sieve-go` as Mox's Sieve filtering backend.
- Implement ManageSieve RFC 5804 on port 4190.
- Implement RFC 6785 IMAPSIEVE using IMAP METADATA.
- Enable Sieve policy inheritance: server defaults -> domain overrides -> account overrides.
- Enable risky Sieve actions with context-specific RFC behavior and operational guardrails.
- Enable Sieve and ManageSieve in `mox quickstart`.
- Enable ManageSieve in `mox localserve`.

## Core Design

- Add a `sievefilter` package for Mox-specific embedding.
- Add a `managesieveserver` package modeled after `imapserver`.
- Use separate Sieve execution contexts:
  - `delivery`
  - `imapsieve`
- Use context-specific interpreters/registries and runtime checks.
- Store user scripts in each account DB.
- Use existing `store.Annotation` and IMAP METADATA for RFC 6785 script selection.
- Do not implement proprietary folder-named script behavior.

## sieve-go Changes

- Add `Registry.RegisterCapability(name string)` for capability-only extensions such as `imapsieve`.
- Add or implement RFC 3894 `copy` support before claiming complete RFC 6785 semantics.
- Confirm extension registration supports context-specific interpreters.
- Keep `environment` out of generic `sieve-go`; Mox supplies it.

## Mox Environment Extension

Implement `environment` in Mox as a host-supplied extension registered into `sieve-go`.

Behavior:

- Capability: `environment`.
- Test syntax: `environment [COMPARATOR] [MATCH-TYPE] <name: string> <key-list: string-list>`.
- Use handler/provider interface such as `SieveEnvironment(name string) (value string, ok bool)`.
- Unknown environment items make the test false.
- Use `sieve-go` match/comparator handling.

Delivery values:

- `domain`
- `host`
- `location = MDA`
- `phase = during`
- `name = mox`
- `version`
- `remote-ip`
- `remote-host` when available

IMAPSIEVE values:

- `location = MS`
- `phase = post`
- `imap.user`
- `imap.email`
- `imap.cause`
- `imap.mailbox`
- `imap.changedflags`

## Configuration

Add Sieve policy with inheritance:

- Server defaults.
- Domain overrides.
- Account overrides.

Use nullable/tri-state fields for booleans so explicit `false` can override inherited `true`.

Candidate fields:

- `Enabled`
- `MaxScriptSize`
- `MaxScripts`
- `MaxTotalScriptSize`
- `ExecutionTimeout`
- `MaxRedirects`
- `MaxVacationResponses`
- `AutoCreateMailboxes`
- `RunOnDelivery`
- `RunOnIMAPEvents`
- `FailureMode`

Add listener config:

```sconf
ManageSieve:
	Enabled: true
	Port: 4190
	NoRequireSTARTTLS: false
```

Validation:

- Public ManageSieve should require TLS before password auth unless `NoRequireSTARTTLS` is explicitly set.
- Validate size/count/time limits.
- Validate inheritance rules.
- Add config docs.

## Script Storage

Add account DB records:

```go
type SieveScript struct {
	Name string `bstore:"nonzero"`
	Content []byte
	Created time.Time `bstore:"default now"`
	Updated time.Time `bstore:"default now"`
}

type SieveSettings struct {
	ID byte
	ActiveScript string
}
```

Storage requirements:

- Add to `store.DBTypes`.
- Add upgrade/migration handling.
- Add backup/export/import coverage.
- Enforce RFC 5804 script-name restrictions.
- Enforce script count, per-script size, and total script size.
- Compile cache with invalidation on script changes, metadata changes, and config reload.
- ManageSieve active script is separate from RFC 6785 metadata references.

## ManageSieve RFC 5804

Implement in `managesieveserver`.

Commands:

- `CAPABILITY`
- `STARTTLS`
- `AUTHENTICATE`
- `LOGOUT`
- `NOOP`
- `HAVESPACE`
- `PUTSCRIPT`
- `LISTSCRIPTS`
- `SETACTIVE`
- `GETSCRIPT`
- `DELETESCRIPT`
- `RENAMESCRIPT`
- `CHECKSCRIPT`

Protocol requirements:

- Initial greeting capabilities.
- `IMPLEMENTATION`
- `VERSION`
- `SIEVE`
- `STARTTLS`
- `SASL`
- `OWNER` after auth.
- `MAXREDIRECTS`.
- Reissue capabilities after STARTTLS and successful AUTHENTICATE.
- SASL service name `sieve`.
- RFC response codes including quota, active, nonexistent, already exists, trylater.
- STARTTLS and auth behavior modeled after IMAP/SMTP auth paths.
- Use existing login attempt tracking and auth rate limiting.

## Delivery-Time Sieve

Hook before `DeliverMailbox` in SMTP final delivery.

Behavior:

- Use analyzed mailbox as implicit keep target.
- Use full message as `MsgPrefix + dataFile`.
- One execution per effective destination account/recipient.
- `fileinto` changes target mailbox.
- `discard` accepts without storing.
- `redirect` submits through queue.
- `vacation` submits through queue with suppression and rate limits.
- `reject`/`ereject` integrate with per-recipient DATA outcomes.
- `editheader` and MIME mutation require materializing a rewritten message for delivery.
- Record intended external side effects during evaluation and execute after DB locks/transactions where possible.

Multi-recipient handling:

- One recipient's Sieve rejection must not blindly fail all accepted recipients.
- Integrate with existing `deliverErrors`/DSN logic.

Risk guardrails:

- Redirect loop detection.
- Max redirects.
- Vacation response history.
- Suppress vacation for bulk/list/auto-submitted/DSN mail.
- Logging and metrics.

## RFC 6785 IMAPSIEVE

Use existing IMAP METADATA and `store.Annotation`.

Capability:

- Advertise `IMAPSIEVE=sieve://<host>:4190` only when ManageSieve and IMAPSIEVE are enabled and tested.
- ManageSieve `SIEVE` capability must include `imapsieve`, `environment`, and `imap4flags` when available.

Script selection:

- Check mailbox `/shared/imapsieve/script`.
- If absent, check server/global `/shared/imapsieve/script`.
- If selected metadata is empty, invalid, or names a missing script, run no script and do not fall back.
- Metadata value is a ManageSieve script name.

Events:

- `APPEND`
- `COPY`
- `FLAG`
- Include `FETCH`-caused `\Seen`.
- Treat `MOVE` destination creation as Mox COPY-like behavior, documented as Mox behavior rather than RFC-required.

Runtime rules:

- Original IMAP operation completes normally first.
- One script execution per affected message.
- `fileinto` creates an additional message and marks the original `\Deleted` unless keep applies.
- `redirect` sends the message and may mark original `\Deleted`.
- `discard` marks original `\Deleted` unless keep applies.
- `reject`, `ereject`, and `vacation` are invalid and terminate the script with an error.
- `envelope` tests are invalid at runtime for IMAPSIEVE.
- `editheader` and MIME edits are transient only and never mutate kept originals.
- Sieve-caused `fileinto` and flag changes must not trigger further IMAPSIEVE executions.

Hooks:

- IMAP APPEND.
- IMAP COPY.
- IMAP MOVE destination creation as COPY-like.
- IMAP STORE flag changes.
- FETCH paths that set `\Seen`.
- Consider webmail/webapi message mutation consistency separately from strict RFC 6785.

## Quickstart

In `quickstart.go`:

- Enable Sieve in generated config.
- Enable public ManageSieve.
- Server/domain/account policy should inherit normally.
- Default generated config should have delivery Sieve and IMAPSIEVE enabled if implementation is complete.

DNS records:

- RFC 5804 SRV record:
  - `_sieve._tcp.<domain>. SRV 0 1 4190 <target>.`
- Use client settings domain target (`csd`) consistently with `_imaps` and `_submissions`.
- Update `admin.DomainRecords`.
- Update `webadmin/admin.go` SRV validation for `_sieve`.

## Localserve

In `localserve.go`:

- Enable ManageSieve on the local listener.
- Use regular port + 1000:
  - `4190 + 1000 = 5190`
- Set `NoRequireSTARTTLS = true` for local testing consistency.
- Print ManageSieve URL in startup output:
  - `sieve://mox%40localhost:moxmoxmox@localhost:5190`

## Implementation Sequence

1. Update `sieve-go`.
   - Add `RegisterCapability`.
   - Add RFC 3894 `copy`.
   - Confirm context-specific interpreters.

2. Add Mox Sieve embedding.
   - Add `sievefilter`.
   - Add Mox `environment`.
   - Add delivery and IMAPSIEVE contexts.
   - Add context-specific runtime checks.

3. Add config and inheritance.
   - Server defaults.
   - Domain overrides.
   - Account overrides.
   - Listener `ManageSieve`.
   - Validation and docs.

4. Add account script storage.
   - DB records.
   - Accessors.
   - Quotas.
   - Cache invalidation.
   - Backup/export/import.

5. Add ManageSieve server.
   - Listener/startup wiring.
   - STARTTLS/auth.
   - Full RFC 5804 command set.
   - Protocol tests.

6. Add delivery-time Sieve.
   - Hook before `DeliverMailbox`.
   - Implement delivery actions.
   - Multi-recipient behavior.
   - Side-effect sequencing.

7. Add risky action completeness.
   - Redirect.
   - Vacation.
   - Editheader.
   - MIME mutation.
   - Abuse controls.

8. Add RFC 6785 IMAPSIEVE.
   - Capability advertisement.
   - Metadata selection.
   - APPEND/COPY/MOVE/FLAG/FETCH hooks.
   - Loop prevention.

9. Update setup flows.
   - Quickstart config.
   - DNS `_sieve`.
   - Admin DNS checks.
   - Localserve config and output.

10. Docs and release notes.
    - Config docs.
    - Protocol support docs.
    - User examples.

## Required Tests

- Config inheritance server/domain/account.
- ManageSieve auth, STARTTLS, literals, quotas, script validation, active script semantics.
- Script name validation.
- Delivery `keep`, `fileinto`, `discard`, `redirect`, `reject`, `ereject`, `vacation`.
- Multi-recipient SMTP where one recipient rejects and another accepts.
- Header/body mutation persistence on delivery.
- IMAPSIEVE metadata selection and no-fallback behavior.
- IMAPSIEVE `APPEND`, `COPY`, `MOVE`, `STORE`, and `FETCH \Seen`.
- IMAPSIEVE invalid `envelope`, `reject`, `ereject`, `vacation`.
- RFC 3894 `:copy`.
- Loop prevention.
- Quickstart generated config and `_sieve` DNS output.
- Localserve generated config and printed ManageSieve URL.

## Integration Testing

Mox already has three layers of test infrastructure beyond unit tests:

- Per-package in-process tests that drive full protocol over `net.Pipe`/socketpairs (e.g. `imapserver`, `smtpserver`, `webmail`, `managesieveserver`).
- Docker-based interop tests run via `make test-integration` (`integration_test.go` build-tagged `integration`, two Mox containers + Pebble ACME + unbound DNS + postfix from `docker-compose-integration.yml` and `testdata/integration/`).
- `make imaptest-run` against Dovecot's `imaptest` for IMAP server interop.

Add Sieve-related integration coverage:

- New build-tagged `TestManageSieve` in `integration_test.go` that uses the running `moxacmepebble`/`moxmail2` containers to:
  - Connect to port 4190 with STARTTLS.
  - Authenticate over PLAIN and SCRAM-SHA-256.
  - Run `HAVESPACE`, `PUTSCRIPT`, `LISTSCRIPTS`, `GETSCRIPT`, `CHECKSCRIPT`, `RENAMESCRIPT`, `SETACTIVE`, `DELETESCRIPT`.
  - Verify `_sieve._tcp.<domain>` SRV record resolves correctly against the unbound DNS container.
- Once delivery-time Sieve lands: send a message via SMTP from `moxacmepebble` to `moxmail2`, verify the active script's `fileinto` routes it into the expected mailbox via IMAP IDLE.
- Optional: run Dovecot Pigeonhole's `sievec` against Mox's ManageSieve port in a follow-up docker compose smoke test, mirroring the existing `imaptest` setup.

## Deferred Phases After Initial Scaffolding

Phase 1 (config, storage, ManageSieve protocol, quickstart, localserve, DNS) is complete in-tree. Remaining phases, executable independently:

- Phase 2: integrate `github.com/hilli/sieve-go`; wire `sievefilter` Compile/Validate; replace placeholder `ScriptValidator` in `managesieveserver`. **Done**.
- Phase 3: Mox `environment` extension for `sieve-go` plus delivery/IMAPSIEVE EnvironmentProvider impls. **Done.**
- Phase 4: delivery-time Sieve hook in `smtpserver` before `DeliverMailbox`; respect `FailureMode`. **Done** (fileinto, discard, reject, ereject, redirect, flags wired; vacation + editheader wired with abuse controls; MIME mutation stub still returns errors).
- Phase 5: risky actions full integration:
  - `redirect`: queued via `queue.Add`. **Done**.
  - `vacation`: response history table (`SieveVacationResponse`), 7-day default suppression window, abuse controls (auto-submitted/list/null-sender/spam suppression). **Done.**
  - `editheader`: addheader/deleteheader applied to MsgPrefix on delivery. **Done.**
  - MIME mutation: still stubbed; needs a rewrite-on-delivery path.
- Phase 6: RFC 6785 IMAPSIEVE — **Done**:
  - `IMAPSIEVE=sieve://<host>:<port>` advertised in IMAP CAPABILITY when ManageSieve enabled.
  - `/shared/imapsieve/script` metadata selection (mailbox-level, server-level fallback, empty/missing → no script).
  - APPEND, COPY, MOVE, STORE, FETCH (`\Seen`) hooks. MOVE destination creation treated as COPY-like Mox behaviour.
  - Restricted interpreter forbids `reject`/`ereject`/`vacation`; envelope test errors at runtime per RFC 6785 §4.6.
  - `imap.cause`/`imap.mailbox`/`imap.user`/`imap.email`/`imap.changedflags`/`location=MS`/`phase=post` environment values.
  - FileInto creates additional copy; \Deleted marked on original unless explicit keep. Mailbox counts/modseq maintained correctly.
  - Loop prevention: `c.inSieve` re-entrancy guard suppresses script invocations triggered by Sieve actions (RFC 6785 §2.2.3 / §6).
- Phase 7: integration test additions:
  - `TestManageSieve` against docker-compose containers (STARTTLS, auth, full RFC 5804 command set). **Done.**
  - `TestSieveDelivery` against docker-compose containers (install fileinto script via ManageSieve, submit message from one container to another, verify Sieve-routed mailbox). **Done.**

## Remaining Work

The following is the only sub-feature deliberately not yet wired:

- MIME mutation (`replace` / `enclose`) on delivery requires materializing a rewritten message file (the on-disk file is shared between recipients and immutable in the storage layer). `extracttext` already works (metadata-only, no mutation). The handler returns an error for the mutation actions, so scripts that use them will fail the script and (per `FailureMode`) be temp-failed or implicitly-keep'd. A proper implementation would write a per-recipient rewritten temp file before `DeliverMailbox`.

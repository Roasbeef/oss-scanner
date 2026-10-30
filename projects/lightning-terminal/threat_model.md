# Threat model: lightning-terminal (litd)

## What this project does and where untrusted input enters

`litd` is a supervisor. It starts `lnd` in process (or connects to a remote
one), can start `tapd`, `loopd`, `poold`, and `faradayd` in the same process, and
exposes every one of those daemons' gRPC and REST services through a single TLS
listener. On top it adds its own services: sessions, accounts, the firewall and
its privacy mapper, autopilot sessions, and status. A request on that one port
is inspected, authorized against a macaroon, optionally logged and gated by
rules, then routed to whichever daemon owns the method name.

That design is where the risk concentrates. Each daemon keeps its own
authentication; `litd`'s job is to decide, once, who is calling and what they may
reach, and to make the same decision for every daemon behind the port. So the
interesting flaw class here is not memory safety but **cross-system authority**: a
macaroon, session, or account minted for one subserver reaching another, a
permission check that composes wrongly when two daemons own similarly named
methods, or a proxy forwarding on a credential the caller did not earn.

Untrusted input arrives as:

1. **gRPC and REST calls on the main listener.** `rpc_proxy.go`
   (`rpcProxy.UnaryServerInterceptor`, `StreamServerInterceptor`, `makeDirector`,
   `convertSuperMacaroon`) terminates them, then the subservers' own interceptors
   continue. `terminal.go`'s `LightningTerminal.ValidateMacaroon` is lnd's
   external validator when lnd runs in process. Every protobuf field is
   caller-controlled.
2. **Macaroons and their caveats.** A caller presents a macaroon and `litd`
   reads caveats out of it. Three families matter: the account caveat
   (`accounts/interceptor.go`, `CaveatFromID`, `IDFromCaveats`), the firewall's
   rules and meta-information caveats (`firewall/caveats.go`, `ParseRuleCaveat`,
   `ParseMetaInfoCaveat`), and the session-binding caveat
   (`firewall/request_info.go`, `bindSessionToMacaroon`). Caveats are
   attacker-chosen strings inside an attacker-supplied macaroon.
3. **Sessions.** `session_rpcserver.go` (`AddSession`, `resumeSession`,
   `RevokeSession`, `AddAutopilotSession`) and `session/server.go`
   (`StartSession`). An autopilot session carries a rule set and a permission
   recipe.
4. **The autopilot server's answers.** `autopilotserver/client.go`
   (`ListFeatures`, `RegisterSession`, `ActivateSession`, `ListFeaturePerms`)
   talks to a remote service returning feature names, permission maps, rule
   values, and a minimum version. That server is not under our control.
5. **The web UI's basic-auth path.** The browser gets a static app that
   authenticates with HTTP basic auth, which `rpc_proxy.go` turns into a macaroon
   (`basicAuthToMacaroon`). Frontend code is not scannable, but the server side
   of that conversion is.
6. **Sub-daemon traffic.** For a remote subserver, `litd` dials it and forwards
   with a stored macaroon (`subservers/manager.go`, `ReadRemoteMacaroon`,
   `MacaroonPath`), so credential selection is ours even when authorization is
   theirs.
7. **The database.** Accounts (`accounts/store_sql.go`, `accounts/tlv.go`), the
   action log (`firewalldb/actions_sql.go`, `firewalldb/privacy_mapper_sql.go`),
   and sessions (`session/sql_store.go`, `session/tlv.go`), all of which migrate
   across versions (`db/migrations.go`, `db/migsets`, `accounts/sql_migration.go`,
   `firewalldb/sql_migration.go`).

State which layer you are blaming. A bug in `lnd`'s own `SendPayment` handling
is upstream's; a bug in `litd`'s decision to let a caller reach it is ours. The
most useful findings sit on that line, so make the line explicit.

## Components that matter most

Ordered by damage if the component is wrong.

1. **`perms/` — the permission map everything else trusts.** `perms/manager.go`
   (`NewManager`, `RegisterSubServer`, `OnLNDBuildTags`, `URIPermissions`,
   `MatchRegexURI`, `ActivePermissions`, `GetLitPerms`, `IsSubServerURI`,
   `IsWhiteListedURL`) plus `perms/permissions.go`. This decides which URI needs
   which `(entity, action)` pair, which need nothing, and which subserver owns a
   URI at all. Every authorization question in the process resolves here, so an
   unmapped, double-mapped, or accidentally white-listed URI is the
   highest-leverage bug in the repository. Note the two maps: `fixedPerms` per
   subserver, and a flat `perms` where the last registration wins.
2. **`rpc_proxy.go` — the front door.** `UnaryServerInterceptor` and
   `StreamServerInterceptor` reject unknown methods, check that the owning
   subsystem started, convert basic auth or a super macaroon into a per-daemon
   credential, and hand the request to `makeDirector`, which picks the upstream
   connection. A mistake either admits a request that should have been rejected
   or forwards it with a credential the caller did not qualify for.
   `isStatusReq`, `isProxyReq`, and `checkSubSystemStarted` define the boundary.
3. **`session_rpcserver.go` and `session/` — minting authority.** `AddSession`
   bakes a macaroon from a caller-supplied recipe and `resumeSession` re-bakes
   one on reconnect; `session/macaroon.go` derives the session identity.
   `session/sql_store.go` and `session/kvdb_store.go` persist sessions and their
   recipes. The property that matters: a session's macaroon, on creation and on
   every resume, may contain only the permissions and caveats that its recipe
   authorizes, and no more.
4. **`accounts/` — spending authority delegated to a sub-macaroon.** The service
   (`accounts/service.go`: `NewAccount`, `CreditAccount`, `DebitAccount`,
   `CheckBalance`, `TrackPayment`), the interceptor enforcing it
   (`accounts/interceptor.go`), the per-method checkers (`accounts/checkers.go`:
   `checkSend`, `checkSendToRoute`, `checkMaxPaymentSize`, `filterPayments`), and
   the durable side (`accounts/store_sql.go`, `accounts/tlv.go`). An account is a
   balance plus restrictions that must hold across every method that moves value,
   including ones added later. An lnd method that spends and that the checker map
   does not cover makes the account a suggestion.
5. **`firewall/` — the rule and privacy layer.** `firewall/rule_enforcer.go`
   (`Intercept`, `handleRequest`, `handleResponse`) applies per-session and
   per-feature rules; `firewall/privacy_mapper.go` (`Intercept`,
   `checkAndReplaceIncomingRequest`, `resolveLNCSession`) rewrites requests and
   responses to hide values and enforces that on remote connections;
   `firewall/request_logger.go` writes the action log, and `firewall/caveats.go`
   parses the rules out of the macaroon. Rules arrive in a caveat, so a parse
   that accepts more than intended changes what the caller may do.
6. **`subservers/` — what runs where.** `subservers/manager.go` (`AddServer`,
   `StartIntegratedServers`, `ConnectRemoteSubServers`, `RegisterRPCServices`,
   `ValidateMacaroon`, `Handles`, `GetRemoteConn`), `subservers/subserver.go`,
   and `subservers/taproot-assets.go`, `subservers/loop.go`,
   `subservers/pool.go`, `subservers/faraday.go`. Here integrated versus remote
   mode changes who validates; a method reachable in one mode and unchecked in
   the other is a real bug.
7. **`terminal.go` and `app.go`/`app_noui.go`.** `LightningTerminal.start`,
   `RegisterGrpcSubserver`, `RegisterRestSubserver`, `ValidateMacaroon`,
   `startMainWebServer`, `createRESTProxy`, `allowCORS`: which services land on
   which listener, and the CORS policy for the web surface.
8. **`autopilotserver/`.** `autopilotserver/client.go` consumes a remote
   server's feature list, permission map, and rule values, and
   `session_rpcserver.go`'s `AddAutopilotSession` turns them into a session.
   Those remote-supplied values are the input to a decision about how much
   authority an external actor gets.
9. **`rules/`.** `rules/manager_set.go` (`InitEnforcer`, `InitRuleValues`) and
   the per-rule files `rules/rate_limit.go`, `rules/onchain_budget.go`,
   `rules/chan_policy_bounds.go`, `rules/channel_restrictions.go`,
   `rules/peer_restrictions.go`, and `rules/history_limit.go`. Each rule's
   `VerifySane` and handlers decide whether an autopilot session is bounded.
10. **`db/` and persistence migrations.** `db/migrations.go`, `db/migsets`,
    `accounts/sql_migration.go`, `firewalldb/sql_migration.go`,
    `session/sql_migration.go`. Both SQLite and Postgres are supported; a
    migration that loses a session, an account balance, or an action-log entry
    turns an old bug into a permanent one.

## Out of scope or low priority

- **The web frontend under `app/`.** The image for this enrolment is Go-only:
  no Node, no yarn, and `app/build` is a stub the image creates so that
  `app.go`'s `//go:embed app/build/*` compiles. Nothing under `app/src/` is
  built, run, or inspected, so React, TypeScript, CSS, and `app/package.json`
  findings cannot be verified or executed and are out of scope. Server-side
  handling of what the frontend sends *is* in scope: the basic-auth path in
  `rpc_proxy.go`, the CORS policy in `terminal.go`, and `ClientRouteWrapper`.
- **Generated protobuf and sqlc code.** `litrpc/*.pb.go`, `litrpc/*.pb.gw.go`,
  `litrpc/*.pb.json.go`, `litrpc/*_grpc.pb.go`, `autopilotserverrpc/*.pb.go`, and
  everything under `db/sqlc/` is generated from the `.proto` and `.sql` sources.
  Report the hand-written caller, or a defect the generator reproduces.
- **`proto/` and `third_party/lnd/tlv/`.** Vendored `.proto` copies kept for
  cross-version compatibility, and a pinned copy of lnd's TLV package as its own
  module. Not our schema. Report the TLV copy only with a concrete reachable
  consequence inside `litd`'s own parsers.
- **`itest/`.** Needs a Bitcoin node binary plus a network of `litd` and `lnd`
  nodes, under tags `dev integration itest lowscrypt`. Not runnable offline.
- **`tools/`, `tools/linters/`, and `docs/`.** Build tooling and prose, including
  `docs/WALKTHROUGH.md` and the per-mode config guides.
- **`cmd/litcli`.** A CLI; the operator running it is the user, not an attacker.
  A finding that needs a hostile local user already holding an admin macaroon is
  out of scope unless the same bytes can arrive over the network.
- **Wrappers over lnd, tapd, loopd, poold, and faradayd behaviour.** A defect
  inside a sub-daemon's own handler belongs in that project's scan (lnd and
  taproot-assets are both enrolled). Report it here only when the mistake is
  `litd`'s: which credential it selected, which listener a method was registered
  on, or which interceptor ran or did not.

## How to exercise it

The image is a Go image over a clean checkout of
`https://github.com/lightninglabs/lightning-terminal` on `master`. The root
`go.mod` declares `go 1.27.3`; the other Go modules in the tree are
`autopilotserverrpc/`, `litrpc/`, `perms/`, `third_party/lnd/tlv/`, `tools/`, and
`tools/linters/`.

**There is no Node and no yarn in this image, and `app/build` is a stub.** That
is deliberate. `app.go` sits behind the build tag `!litd_no_ui` and embeds
`app/build/*`, so the build needs one file there; `make unit` creates it with
`mkdir -p app/build && touch app/build/index.html` and the image does the same
once. Delete it and the root package will not compile. To skip the embed
entirely, build with `-tags=litd_no_ui`, which selects `app_noui.go`.

Tags come from `make/compile_flags.mk`, whose `COMPILE_TAGS` is
`autopilotrpc signrpc walletrpc chainrpc invoicesrpc watchtowerrpc neutrinorpc
monitoring peersrpc kvdb_postgres kvdb_etcd kvdb_sqlite`, and
`make/testing_flags.mk` adds `DEV_TAGS = dev` plus `test_db_postgres` or
`test_db_sqlite` for the backend you pick. With `TAGS` set to that list:

```
mkdir -p app/build && touch app/build/index.html
go build -gcflags='all=-N -l' -tags="$TAGS" ./...
go test -count=1 -tags="$TAGS" ./...
go test -count=1 -run '^$' -tags="$TAGS" ./...   # compile test binaries only
```

`make unit` wraps the same commands and recreates the `app/build` stub; `make
unit pkg=perms`, `pkg=accounts`, `pkg=firewall`, `pkg=subservers`, and
`pkg=session` narrow it, and `make unit-race` adds `-race`. `dbbackend=sqlite` or
`dbbackend=postgres` picks the backend tag; Postgres needs a live server, so
prefer SQLite.

Where the tests live and how to reach each layer without a network:

- **Permissions.** `perms/manager_test.go` builds a manager and asserts URI
  mappings, white-listing, and regex matching, with fixtures from `perms/mock.go`
  and `perms/mock_dev.go`. A test here is the cheapest demonstration of a
  mapping problem, and `perms/` is its own module, so `cd perms && go test ./...`
  runs in seconds.
- **The proxy and interceptors.** `rpc_proxy.go` has no test file of its own;
  exercise it through `terminal.go`'s wiring, or construct an `rpcProxy` directly
  with a fake `perms.Manager` and a `bufconn` upstream.
  `macaroons/super_mac_test.go` covers super-macaroon parsing.
- **Accounts.** `accounts/service_test.go`, `accounts/interceptor_test.go`,
  `accounts/checkers_test.go`, `accounts/store_test.go`, and
  `accounts/sql_migration_test.go`, with `accounts/test_sqlite.go` and
  `accounts/test_postgres.go` as backend fixtures. The checkers are plain
  functions over `lnrpc` messages (`checkSend`, `checkSendToRoute`), so a
  value-movement bug is usually a self-contained test over a hand-built
  `lnrpc.SendRequest`.
- **Sessions.** `session/sql_store_test.go`, `session/tlv_test.go`,
  `session/store_test.go`, and `session/privacy_flags_test.go`, with
  `session/migtest` driving the migration packages.
- **Firewall.** `firewall/caveats_test.go`, `firewall/request_info_test.go`,
  `firewall/privacy_mapper_test.go`, and `firewalldb/privacy_mapper_test.go`.
  Caveat parsing is a pure function over a string, so start there.
- **Rules.** Each rule has a sibling test: `rules/rate_limit_test.go`,
  `rules/onchain_budget_test.go`, `rules/chan_policy_bounds_test.go`,
  `rules/channel_constraints_test.go`, `rules/channel_restrictions_test.go`,
  `rules/peer_restrictions_test.go`, `rules/history_limit_test.go`.
  `rules/mock.go` supplies fakes; the rule protos are in
  `litrpc/lit-sessions.proto`.
- **Autopilot.** `autopilotserver/client_test.go` with `autopilotserver/mock`,
  which is the place to serve a hostile feature list, a permissive permission
  map, or an out-of-range rule value.
- **Subservers.** `subservers/shutdown_test.go` is the package's only test; for
  anything else construct a `Manager` with fake `SubServer` implementations,
  which `subservers/interface.go` is small enough to implement in a test file.

What the image cannot do: there is no running `lnd`, `tapd`, `loopd`, `poold`, or
autopilot server, no second host, and no privileged port, so `itest/` cannot run.
Substitute rather than skip: a `bufconn` gRPC server for an upstream sub-daemon,
`autopilotserver/mock` for the remote autopilot, and direct construction of
`rpcProxy`, `perms.Manager`, `accounts.InterceptorService`,
`firewall.RuleEnforcer`, or `firewall.PrivacyMapper`. Concurrency findings need
`-race` to be reliable.

A reproducer needing several real daemons, a chain, or a real autopilot server is
still in scope; say which substitute you used and what production adds. These
layers are mostly pure functions over protobufs and macaroons, so most authority
bugs are expressible without a daemon.

## How we rate severity

Rate on demonstrated impact in a real deployment, not on where the code sits. Two
readers should reach the same number for the same bug.

**Critical: cross-system authority escalation.** A caller holding credentials for
one subserver, account, session, or feature reaching another's method with
authority it was not granted: a macaroon baked for `tapd` satisfying an `lnd`
method, an account session reaching a value-moving call its checkers do not
cover, a resume granting more than the recipe, an autopilot session reaching a
daemon its recipe excludes. This is the flaw class the project exists to prevent,
and a unit test against `perms` or a `bufconn` proxy establishes it. Also
critical:

- An unauthenticated caller reaching a protected method, or a white-listed
  method that changes state.
- Moving a user's channel, wallet, or asset value without delegated authority: a
  bypassable rule, a defeated privacy mapping that makes the user send somewhere
  unintended, a limit that silently does not apply.
- Remote, unauthenticated memory corruption or panic-on-demand in the proxy or a
  pre-authentication parser.
- Fund loss through account accounting: a balance spent twice, a debit without
  settlement, a reservation released while the spend is live.

**High.**

- A rule or restriction enforced on one path but not its equivalent: unary
  versus streaming, gRPC versus REST, integrated versus remote mode, fresh
  session versus resumed session. These are authorization gaps even when each
  path looks locally correct.
- A rule missing where something else still bounds the residual authority (a
  rate limit absent while a per-payment cap holds). Say what remains.
- Session or auth state confusion letting a caller act under another session's
  identity without gaining permissions.
- Correlating a privacy-mapped value across sessions, revealing a user's peer,
  channel, or payment identities to the autopilot server.
- Authenticated but cheap and unbounded denial of service: blocking the RPC
  middleware stream, unbounded action-log writes per request, an unbounded
  goroutine or subscription per session.
- Durable corruption reachable from normal operation that loses a session, a
  balance, or the action log, including a migration that drops a field.

**Medium.** A panic, nil dereference, or bad type assertion in a caveat
parser, request-info parser, or rule handler reachable from a caller-supplied
macaroon or protobuf where the process survives and no authority changes: a
malformed caveat crashing the interceptor is real and worth fixing, not
critical. Disclosure of one caller's non-key data to another outside a privacy
mapping. A rule accepting values outside its documented sane range with no path
to value movement. A CORS policy broader than documented, absent a demonstrated
credential-bearing cross-origin attack.

**Low.** Missing validation with no demonstrable effect on authority, value, or
confidentiality; a check a second layer also performs; a defect needing a hostile
local operator or a hand-edited database; hardening suggestions and log noise.

**Out of scope for a rating, though still worth reporting:** style, lint, unused
code, and test-only defects. A finding confined to `itest/`, a mock, or the
`app/` frontend is not a production vulnerability; report it at low at most with
the reason stated. A bug in `lnd`, `tapd`, `loopd`, `poold`, or `faradayd` is
that project's; rate the `litd`-side mistake that let it matter.

Two tie-breakers. Who is the attacker? An unauthenticated caller beats one with a
low-privilege macaroon, who beats a session holder, who beats the operator. What
did they gain? Authority over funds outranks authority over policy, which
outranks data. A method reachable only with a local admin macaroon is a low bug.

## Report and patch preferences

- Lead with the authority claim in one sentence: who can now do what that they
  could not before. Then the shortest path, naming each layer it crosses, and
  which layer you believe already handles it. The common question is "why is
  this ours, not lnd's".
- A runnable Go test is the ideal reproducer, and most need no daemon: a
  `perms.Manager` mapping case, a `firewall.ParseRuleCaveat` input, an
  `accounts.checkSend` call with a crafted `lnrpc.SendRequest`, an
  `accounts.InterceptorService.Intercept` with a hand-built macaroon, a
  `rpcProxy` with a fake upstream. Reuse `perms/mock.go`, `rules/mock.go`,
  `autopilotserver/mock`, and `firewalldb/mock.go`.
- When the path needs a daemon, express it against a `bufconn` upstream or a fake
  `SubServer` from `subservers/interface.go`, and say what production adds.
- For a missing permission mapping, a table is most useful: the method, the
  daemon that owns it, the permission it should require, and the one it does. A
  test asserting the mapping holds is a good regression artifact.
- A patch is welcome and should be minimal: add the missing mapping or check,
  keep error types and sentinels, do not widen an allowlist, disable a rule, or
  add a test-only bypass. Do not change an exported signature in `perms/` or
  `subservers/interface.go` without saying why; other projects consume both.
- Do not weaken authentication, session validation, or firewall enforcement to
  make a reproducer pass, and say so if a fix requires the UI to change.
- Group findings sharing a root cause: the same missing check in the unary and
  streaming interceptors is one finding with two paths.
- State the commit tested, the package and function, the build tags, and whether
  you needed `-race`.
- If the finding is a hypothesis rather than a demonstrated effect, say so.
  Labelled unproven concerns about an authority path are useful; unproven
  concerns dressed as an exploit are not.

## Anything to leave alone

Specific false-positive generators in this codebase:

- **`-N -l` build flags.** The image builds with `-gcflags='all=-N -l'`, so
  optimisation and inlining are off: locals live longer, stacks are larger,
  generated code differs. Do not report "the secret is not zeroed", a timing
  observation, or a memory ceiling that holds only in a debug build.
- **The `app/build` stub.** `app.go`'s `//go:embed app/build/*` needs one file,
  and the image creates an empty `index.html`. A report that the served index is
  empty, or that the frontend is missing, is reporting the harness.
- **Basic auth being accepted at all.** `basicAuthToMacaroon` converts HTTP
  basic auth into a macaroon only when the header exactly matches the configured
  password, and it returns the same macaroon error whether or not basic auth is
  enabled so a caller cannot probe for it, as the comment above it says. "Basic
  auth is weaker than macaroons" is not a finding; bypassing the comparison
  would be.
- **The sub-daemons' own authentication, and remote passthrough.** In integrated
  mode `lnd` and `tapd` run their own interceptors, so `litd`'s
  `ValidateMacaroon` returns nil for URIs it does not own; for a remote
  subserver `subservers/manager.go`'s `ValidateMacaroon` returns `true, nil`
  because the remote process validates the converted macaroon. Both are the
  design. A finding must show that `litd` was the only thing that could have
  checked, or that the *conversion* picked a credential with more authority than
  the caller had.
- **White-listed methods with no permissions.** `perms.Manager` intentionally
  maps some methods (status, version, proxy, accounts helpers) to an empty
  permission list, and `IsWhiteListedURL` returning true for those is correct.
  Name the method and what it can do before claiming one is wrong.
- **Sessions trusting their own stored recipe.** A resumed session re-bakes
  exactly the caveats and permissions persisted at creation. Creating a broadly
  permissioned session in the first place is the finding; the resume path
  faithfully reproducing it is not.
- **Privacy-mapper replacements being lossy or per session.** The mapper
  replaces channel IDs, hashes, and peer keys with tokens so an autopilot server
  cannot learn them, and the mapping is intentionally per session. Two real
  values mapping to tokens, no cross-session unmapping, and non-reversibility
  from the client are all intended.
- **Rule enforcers that reject by default.** `rules/` enforcers must error on a
  request they cannot verify, including an unparseable rule value. A rejected
  request is the safe outcome; it is a denial of service only if the rejection
  is attacker-triggerable for *other* sessions and unbounded.
- **Test helpers, mocks, and frozen migrations.** `accounts/test_sql.go`,
  `firewalldb/test_sql.go`, `session/test_sql.go`, `session/migtest`,
  `perms/mock.go`, `rules/mock.go`, `autopilotserver/mock`, `firewalldb/mock.go`,
  and the `perms/permissions.go` tables are fixtures and data.
  `session/migration1` and `session/migration2` are frozen packages that must not
  be "fixed": a finding there matters only if the current path
  (`session/sql_migration.go`, `accounts/sql_migration.go`,
  `firewalldb/sql_migration.go`) mishandles their output.
- **SQLite versus Postgres differences the code handles.** Both backends are
  first-class (`accounts/store_sql.go` and `accounts/store_kvdb.go`,
  `firewalldb/actions_sql.go` and `firewalldb/actions_kvdb.go`). Error text, code,
  or isolation-level differences are not findings unless an accepted
  authorization or balance state differs; serialisation retry is expected.
- **Vendored and generated code**, per the out-of-scope section: report the
  `.proto` or `.sql` only when the generated result is itself insecure.
- **CORS being enabled at all.** `terminal.go`'s `allowCORS` exists because the
  UI and reverse-proxy deployments need it. A finding needs a cross-origin
  request that carries a credential and changes state, not merely an
  `Access-Control-Allow-*` header.

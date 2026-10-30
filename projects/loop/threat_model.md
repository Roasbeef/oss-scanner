# Threat model: loop

## What this project does and where untrusted input enters

Loop moves bitcoin between the Lightning Network and the Bitcoin chain without
closing a channel. A user runs `loopd`, a daemon holding the client side of every
swap in a local database and talking to a remote Loop server and to the user's own
`lnd` node; a small CLI, `loop`, drives `loopd` over gRPC. The protocols are
submarine swaps (Loop Out: pay off-chain, receive on-chain; Loop In: the reverse),
instant loop-outs built on MuSig2 reservations, and static-address deposits, where
a reusable Taproot address accumulates UTXOs that the client later loops in or
withdraws. The design assumes the server is not trusted with funds, but it is
still trusted for data the client has to check itself: `docs/architecture.md`
states the intent that the client validates the swap terms and the server cannot
reach the funds. This document is about where that validation happens, or should.

The untrusted inputs and their transports:

- The swap server's gRPC responses, over the client in `swap_server_client.go`.
  Every server-supplied number and identifier arrives here: terms and amount bounds
  from `GetLoopOutTerms` and `GetLoopInTerms`, quotes from `GetLoopOutQuote` and
  `GetLoopInQuote`, the two invoices and the server's HTLC keys from
  `NewLoopOutSwap`, receiver keys and HTLC expiry from `NewLoopInSwap`, MuSig2
  nonces and partial signatures from `MuSig2SignSweep` and `MultiMuSig2SignSweep`,
  and updates pushed over `SubscribeLoopInUpdates` and `SubscribeLoopOutUpdates`.
- The same server's notification stream, handled in `notifications/manager.go`:
  reservation notifications, static-address sweep requests, confirmation-risk
  decisions, unfinished-swap and HTLC-confirmed notifications.
- The user's `lnd` node over `lndclient`. Normally trusted, but the heights, invoice
  states and channel state it returns drive decisions about when to reveal a
  preimage and when a swap has completed. The chain, through `lnd`'s chain notifier,
  brings blocks, spends of the client's HTLCs and deposits, confirmations and
  reorgs, and whoever can mine or race a spend controls the ordering of those
  events.
- Deposits to a static address. Anyone can pay there, so the number, timing and
  amounts of tracked deposits are attacker-influenced, though the outputs are
  constrained by the address script.
- The local `loopd` gRPC API in `loopd/swapclient_server.go`, authenticated by
  macaroons from `loopd/macaroons.go`. A local process holding a macaroon is
  untrusted relative to the daemon's own state.
- The `tapd` node, for the asset flows in `assets/client.go`.

## Components that matter most

In order of damage if wrong.

1. `staticaddr/`: `staticaddr/deposit/`, `staticaddr/loopin/`,
   `staticaddr/withdraw/`, `staticaddr/address/`, `staticaddr/script/`. One Taproot
   address holds real UTXOs behind a cooperative MuSig2 keyspend path and a
   unilateral CSV timeout path. `staticaddr/deposit/fsm.go` tracks each deposit,
   `staticaddr/loopin/actions.go` and `staticaddr/loopin/loopin.go` sign HTLC
   transactions over a set of deposits, and `staticaddr/withdraw/manager.go` signs
   cooperative withdrawals. The properties that must hold: a tracked deposit has
   one owner and one outcome, every spend of a deposit is attributed to the state
   machine that owns the result, and a deposit whose HTLC signature has reached the
   server is not offered to anything else while that HTLC can still confirm.
   Damage here is direct fund loss.
2. `swap_server_client.go` with the contract validation in `loopout.go`
   (`validateLoopOutContract`) and `loopin.go` (`ValidateLoopInContract`). Every
   server-supplied term must be checked against the client's own request and
   bounds: invoice hashes and amounts, the server's HTLC and internal keys, the
   absolute expiry of an on-chain HTLC, and the swap destination.
3. The submarine swap state machines in `loopout.go` and `loopin.go`: the preimage
   reveal decision in `loopOutSwap.canSweep`, the sweep and timeout paths,
   `payInvoices`, and the resume paths in `Resume` and `resumeManager`. The preimage
   is the client's only lever; once it is on-chain the server can claim the
   off-chain side.
4. `swap/`: `swap/htlc.go` (`NewHtlcV2`, `NewHtlcV3`, the success and timeout
   witnesses, `IsSuccessWitness`), `swap/tx.go`, `swap/fees.go` (`DecodeInvoice`,
   `CalcFee`) and `swap/keychain.go`. Scripts and witness assembly are what make the
   swap non-custodial.
5. `fsm/` (`fsm/fsm.go`, `fsm/observer.go`) and the stores behind every state
   machine: `instantout/store.go`, `staticaddr/deposit/deposit.go`,
   `staticaddr/loopin/sql_store.go`, `staticaddr/withdraw/sql_store.go`. A machine
   that resumes in the wrong state either strands funds or re-signs.
6. `instantout/`: `instantout/fsm.go`, `instantout/manager.go`,
   `instantout/reservation/`. Reservations are 2-of-2 MuSig2 outputs the server can
   propose, so a protocol where the server chooses nonces and receives client-signed
   transactions deserves the closest reading.
7. `sweepbatcher/`: `sweepbatcher/sweep_batcher.go`,
   `sweepbatcher/sweep_batch.go`, `sweepbatcher/presigned.go`, `sweepbatcher/store.go`
   and `sweepbatcher/greedy_batch_selection.go`. Batches many sweeps into one
   transaction, RBF-bumps it, and in the pre-signed path has the server co-sign;
   `CheckSignedTx` verifies a returned signed transaction against the unsigned one.
8. `loopdb/`: `loopdb/store.go`, `loopdb/sql_store.go`, `loopdb/sqlc/migrations/` and
   the codec in `loopdb/codec.go`. Every swap's history, contract and cost is
   persisted here and replayed on restart, and `notifications/manager.go` is the
   server-driven stream that feeds the reservation, sweep and loop-in managers, where
   backpressure, replay and ordering matter.
9. `liquidity/`: `liquidity/liquidity.go`, `liquidity/parameters.go`,
   `liquidity/threshold_rule.go`, the builders and the fee budget. Autoloop spends the
   user's money on rules, so a rule firing larger or more often than configured spends
   what the user did not authorize. Then `loopd/swapclient_server.go` and
   `loopd/macaroons.go` for the local API and its permissions, and `assets/client.go`,
   `routing_plugin.go`, `utils.go`, `labels/labels.go`.

## Out of scope or low priority

- `looprpc/*.pb.go`, `looprpc/*.pb.gw.go`, `swapserverrpc/*.pb.go` and the
  `*_grpc.pb.go` counterparts. These are generated from `looprpc/client.proto`,
  `looprpc/debug.proto` and the five `.proto` files under `swapserverrpc/` by
  `looprpc/gen_protos.sh` and `swapserverrpc/gen_protos.sh`. A finding in the
  marshalling must be demonstrated through a served RPC to count.
- The `sqlc` output under `loopdb/sqlc/` and the queries it is generated from. A
  bug in a hand-written wrapper in `loopdb/sql_store.go` is in scope; a style
  complaint about generated code is not.
- `docs/`, `AGENTS.md` and `README.md`. `docs/architecture.md` and the state
  machine diagrams (`fsm/fsm.md`, `staticaddr/deposit/fsm.md`,
  `staticaddr/loopin/fsm.md`, `instantout/fsm.md`) are the orientation reading.
- `test/`, the mocks that stand in for `lnd` (`test/lnd_services_mock.go`,
  `test/lightning_client_mock.go`, `test/chainnotifier_mock.go`,
  `test/walletkit_mock.go`, `test/signer_mock.go`, `test/router_mock.go`,
  `test/invoices_mock.go`, `test/versioner_mock.go`, `test/context.go`), plus
  `server_mock_test.go` and `testcontext_test.go`, which hold the mock Loop server
  and the shared swap fixture. Test-only, and also the harness a reproducer should
  use.
- `cmd/loop/`, a thin gRPC client where `cmd/loop/session_recorder.go` records and
  replays CLI sessions for tests and `cmd/loop/debug.go` is behind the `dev` tag;
  `cmd/loopd/main.go` is process wiring. Then `tools/` (a separate Go module for
  lint and doc generation), `scripts/` and `release.sh`.
- `regtest/`, a docker-compose environment around a Loop server published only as a
  Docker image: documentation, not runnable here. `loopdb/postgres_fixture.go` and
  the `//go:build test_db_postgres` files are a test-only fixture driven by
  `ory/dockertest` that starts a container, and `loopdb/migrate_test.go` with the
  `//go:build test_migration` files exercise forward-only schema migrations.
- Anything that needs the caller to hand in an already-inconsistent struct, or to
  call an unexported helper with arguments no production path produces.

## How to exercise it

A Go module at `/src` with three nested modules in the tree, `looprpc/`,
`swapserverrpc/` and `tools/`, each with its own `go.mod`; the root module is
`github.com/lightninglabs/loop`. The image fetches everything the build and the
tests need while the network is up, and the scan then runs offline. No cgo is
needed for the default build (`GOBUILD` sets `CGO_ENABLED=0`), though `-race`
does; bbolt and the SQLite driver are both pure Go. The commands below are the
ones the repository's own Makefile runs.

- `make unit` is `go list github.com/lightninglabs/loop/... | grep -v '/vendor/'`
  piped through `xargs -L 1 env GO111MODULE=on go test -v -test.timeout=20m`, so
  it covers the root module only. `go test ./...` from the root is equivalent.
- `make unit-race` adds `-race`, worth running for the state machine and store
  packages. `make build` produces `loop-debug` and `loopd-debug` with `-tags=dev`.
- `make unit-postgres` adds `-tags=test_db_postgres`, which selects
  `loopdb/test_postgres.go` and the dockertest fixture; it needs Docker, so use the
  default SQLite backend instead. `make rpc` regenerates protobufs through Docker
  and is not available offline.
- Targeted runs are cheaper than the whole suite: `go test ./staticaddr/...`,
  `./instantout/...`, `./sweepbatcher/...`, `./fsm/...`, `./liquidity/...`,
  `./loopdb/...` and `go test .` for the root package.

The test layout is how you build a reproducer without a server or a chain.

- The root package runs a whole swap against a mock server. `server_mock_test.go`
  defines `serverMock`, which serves the `swapServerClient` interface, and
  `testcontext_test.go` assembles a `lndclient.LndServices` from the mocks in
  `test/`. `loopout_test.go` and `loopin_test.go` drive complete swaps that way,
  and `test/context.go` gives you `ReceiveTx`, `NotifySpend`, `NotifyConf`,
  `AssertPaid`, `AssertSettled`, `NotifyServerHeight` and `AssertEpochListeners`,
  so the chain and `lnd` are scripted by hand.
- Each stateful subsystem has mock-based tests to start from:
  `staticaddr/deposit/manager_test.go`, `staticaddr/loopin/loopin_test.go`,
  `staticaddr/loopin/actions_test.go`, `staticaddr/loopin/risk_watcher_test.go`,
  `staticaddr/withdraw/manager_test.go`, `instantout/instantout_test.go`,
  `sweepbatcher/sweep_batcher_test.go` and `sweepbatcher/presigned_test.go`.
  `staticaddr/script/script_test.go` covers script and witness construction with no
  mocks at all, the fastest place to prove a script-level claim.
- `notifications/manager_test.go` has `mockNotificationsClient` and
  `mockSubscribeNotificationsRecvClient`, which push arbitrary server notifications
  into the manager; that is the cheapest way to play a hostile server on that
  stream. Database tests use SQLite through `loopdb.NewTestDB`, resolving to
  `NewTestSqliteDB` in `loopdb/test_sqlite.go`, so no server is required.

A live environment is genuinely needed for three things, and you should say so
rather than fake it: real `lnd` or `tapd` behaviour (channel policies, the chain
notifier's actual notification ordering, macaroon enforcement at the gRPC layer);
a real Loop server's wire behaviour, which `regtest/regtest.sh` and
`regtest/docker-compose.yml` can start but only with Docker; and real consensus
interaction, deep reorgs or mempool fees, since `test/` models heights and
notifications rather than blocks. A reproducer that cannot be demonstrated in the
image is still in scope and worth reporting: weaker evidence, which we will say when
we rate it, but a careful argument with the exact code path and precondition beats
nothing.

## How we rate severity

Critical:

- Any path to loss of the client's funds: a preimage revealed where the server
  gains and the client does not, an HTLC the client can no longer sweep in time, a
  deposit spent twice, a deposit's spend attributed to the wrong state machine, a
  withdrawal paying a destination the user did not choose, or a signed transaction
  submitted with more value or different outputs than the user approved.
- Any path where the client accepts server-supplied terms worse than it asked for
  or outside its configured bounds: a fee or prepay amount over the user's cap, an
  on-chain HTLC expiry beyond the acceptance window, an invoice whose hash or
  amount does not match the request. The server choosing the terms is the failure
  mode the protocol exists to prevent.
- A path where the server gets the client to sign a transaction spending a deposit
  or a reservation somewhere the client did not authorize, including through MuSig2
  nonce or partial-signature handling.
- Memory corruption reachable from a server response or a chain event, and any
  panic from those inputs that the caller cannot recover.

High:

- A state machine bug that strands funds rather than losing them: a swap stuck with
  no outgoing transition, a deposit locked in the active set forever, a batch that
  can never complete or be abandoned. A restart or recovery bug that leaves
  persisted state inconsistent with the chain belongs here too, since the client's
  model of what it still controls is then wrong.
- An authorization failure on the local gRPC API: a request succeeding with a
  macaroon that does not carry the permission for it. Local, but it is the only
  access control `loopd` has.
- A defect letting the server or a third party make the client publish a transaction
  it should not, or stop publishing one it should, where the effect is a missed
  expiry window but funds remain recoverable. The same rank applies to unbounded
  memory, CPU or disk growth driven by server responses or by deposits anyone can
  create, where the daemon stops working.

Medium:

- A remote DoS needing a cooperating or repeatedly reconnecting swap server, the
  attacker being the client's chosen server, or an authenticated local caller. The
  prerequisite is what moves it down, so name it. Crashes and panics needing a
  malformed local database record, a hand-built struct, or a persisted state a
  production path would have to reach first rank the same way.
- Fee or amount arithmetic costing the user a bounded amount relative to the swap
  without transferring control of funds. Privacy belongs here too: telling the
  server which client is which, linking two swaps, or leaking a wallet balance
  through a quote is real, but the server learns a lot by design, so say what is new
  and what the client could do differently.
- A notification-stream defect dropping or reordering a server message so a
  subscriber misses it, with no fund consequences, or a `liquidity` defect making
  autoloop dispatch a swap the user's parameters do not allow while the ordinary
  client path still validates it.

Low: missing validation with no demonstrated impact, where you should state what
you tried to reach; an error or log line that would mislead an operator; a defect
reachable only from a `dev`-tagged binary, a migration or a CLI argument;
inefficiency with no attacker in the loop.

Out of scope for a rating, though worth a sentence as context: anything needing the
server to be honest anyway, since it is a participant and "it could stop
responding" is not a vulnerability; SQLite versus PostgreSQL differences with no
observable effect on what the client reports; anything in generated protobuf code,
the mocks or a test fixture; two daemons sharing a database directory, which the
daemon's exclusive lock already refuses.

## Report and patch preferences

A useful report here looks like this.

- A Go test in the package that owns the behaviour, using the mocks already there.
  For a root-package swap, `serverMock` and `testcontext_test.go` give you a hostile
  server and a scripted chain in a few dozen lines; copy the setup from
  `loopout_test.go` or `loopin_test.go`. For a static-address finding, start from the
  manager tests listed above.
- Name the file, the function and the line, and name the attacker: the swap server,
  an arbitrary third party paying to the static address, a local process with a
  macaroon, or the chain.
- State the property that broke in terms of observable behaviour and money: which
  deposit, which HTLC, which transaction, and what the user loses or cannot do. "The
  state machine reached `Failed` from a state with no funding path" is useful; "the
  FSM looks wrong" is not.
- If the reproducer needs `lnd`, `tapd` or a real server, include the test you would
  write and say plainly that it does not run in the image. Include the persisted
  state where it matters: many findings here are about what survives a restart, so
  show the database content before and after.

A patch is welcome, and a small merge-ready one beats a large one. Keep it to the
component at fault, add a regression test, and prefer making the bad state
unrepresentable — a transition that cannot be taken, a check in the constructor —
over a new flag or a retry loop. Do not change exported signatures or the protobuf
definitions, do not add configuration options, and do not weaken a validation to
make a reproducer pass. If a fix needs a schema migration, say so in the report
rather than including one, since migrations here are ordered and reviewed by hand.
Group findings that share one root cause into one report, and separate different
attackers into separate reports even when the code is the same, because the
severities differ.

## Anything to leave alone

The shapes in this tree that look wrong and are not. This is the section that saves
us the most time, so read it before writing anything up.

- `server_mock_test.go`'s `mockMuSig2SigningData` returns size-correct placeholder
  nonces and partial signatures, with a comment saying the tests do not assert
  cryptographic validity. "The mock accepts an invalid MuSig2 signature" has found
  the mock.
- `test/` is a mock `lnd` whose `LndMockServices`, channels and `Assert*` helpers
  are deliberately synchronous and permissive. So are `loopdb/postgres_fixture.go`
  and the mocks in `sweepbatcher/store_mock.go`, `loopdb/store_mock.go` and
  `liquidity/mock.go`.
- The `fsm` package rejects an event with no transition from the current state with
  `ErrEventRejected` and deliberately does not fall through to a default. `OnError`
  and `OnRecover` are the documented escape hatches, and `NoOp`, `EmptyState` and
  the no-op events are part of the observer protocol rather than dead code. A
  report needs a real state with no legitimate outgoing transition.
- `fsm/observer.go`'s `CachedObserver` keeps a bounded ring (`FixedSizeSlice`), so
  dropping old notifications is the design rather than a lost-update bug. State names
  are `string`s that change between versions, which is why migrations sit beside each
  store, and `staticaddr/version/` exists so old static addresses keep working.
- The static address's timeout path is CSV-gated and spendable by the client alone,
  while the cooperative path is a MuSig2 keyspend with the server. Both sit in the
  taptree on purpose. "The server's key can spend the address" without a path that
  skips the client's consent has misread the script.
- `swap.NewHtlcV2` and `swap.NewHtlcV3` implement two live script versions selected
  by the swap contract's `ProtocolVersion`. Two script shapes is not dead code.
- The pre-signed sweep path exists so the server can co-sign a sweep the client
  could publish itself. `CheckSignedTx` comparing outputs and sequences to the
  unsigned transaction is the intended guard; a report needs a signed transaction
  that passes it and still moves funds somewhere the user did not choose. RBF fee
  bumping re-signing and republishing a batch is intended, as is a delayed first
  publication.
- `liquidity/liquidity.go` returning "no action" for a channel that looks imbalanced
  is the designed outcome when a rule's conditions are unmet, so autoloop being
  conservative is not a bug. The L402 interceptor in `swap_server_client.go` paying
  for a macaroon and retrying is the designed authentication flow for a paid server,
  and `assets/client.go`'s asset swaps requiring `tapd` means logic skipped when
  `tapd` is unconfigured is describing the configuration.
- The `dev` build tag. `cmd/loop/debug.go` and
  `loopd/swapclient_server_debug.go` compile only with `-tags=dev`, and
  `loopd/register_default.go` only without it, so a debug RPC in a debug build is
  not an exposed endpoint.
- The `go.mod` `replace` directives pinning `dario.cat/mergo`, `gonum.org`,
  `go.augendre.info/*` and `lightningnetwork/lnd/sqldb` work around unavailable or
  vulnerable upstream modules. Do not report a `replace` as suspicious on its own;
  if you think a replaced module is itself the problem, say which and why.
- `bbolt` remaining a dependency for the legacy path in `loopdb/store.go`, beside
  the SQL store, is the migration story rather than a duplicated implementation.

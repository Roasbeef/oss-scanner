# Threat model: pool

## What this project does and where untrusted input enters

Lightning Pool is a non-custodial, batched, uniform-clearing-price auction for Lightning channel leases. A node that wants inbound liquidity submits a bid; a node with capital to allocate submits an ask; a periodic batch matches them at a single clearing price per lease duration; and every match in the batch is funded by one on-chain Batch Execution Transaction. Traders keep custody throughout. Funds sit in a timelocked account that is a two-of-two between the trader and the auctioneer, and each trader independently verifies the batch and signs only its own input, so a trader never signs a transaction paying someone other than the counterparty it was matched with.

The repository contains the trader side of the protocol in full, and the generated client surface for the auctioneer side. That asymmetry is the first thing to get right when reading a candidate finding.

- `poold` is the trader daemon. It speaks gRPC to a backing `lnd` node, opens and manages accounts, signs batches, and speaks a separate gRPC order protocol outbound to an auctioneer. Practically all of the hand-written protocol logic in this tree runs here, and it runs on messages that arrive from a remote auctioneer.
- `pool` is the trader command line client, talking to `poold`'s own gRPC API.
- The auctioneer is a separate service that this repository does not implement. `auctioneerrpc/auctioneer.proto` defines what the trader sends and expects, and the generated server interface exists so the stubs compile, but there is no matchmaking or order-book implementation in this tree. A finding about "the auctioneer accepting a malformed order" therefore lands, in this codebase, on the trader's parsers and verifiers rather than on a server.

That makes the trust model unusual and worth stating plainly. From the trader's point of view:

- The auctioneer is an untrusted counterparty that also happens to coordinate the batch. Every message it sends is parsed here: `order/rpc_parse.go` turns the wire messages into native types, and `order/batch_verifier.go` decides whether the trade the auctioneer claims to have made is one the trader is willing to sign. A bug in either is a way for a hostile auctioneer to extract value or wedge a trader, and both are in scope.
- The other traders in a batch are untrusted in a narrower way. They supply node identifiers and node addresses that the trader connects out to, and they are on the other side of a channel funding handshake.
- The trader's own operator is trusted. Calling a `poolrpc` method with an already-malformed request is not an attacker capability.
- A sidecar recipient is a third party who receives a ticket string. `sidecar/codec.go` and `sidecar/tlv.go` decode that string, so the ticket is attacker-authored bytes.

Concretely, the entry points that consume bytes from someone else are:

- `order/rpc_parse.go`. `ParseRPCOrder`, `ParseRPCServerOrder`, `ParseRPCServerAsk`, `ParseRPCServerBid`, `ParseRPCBatch`, `ParseRPCMatchedOrders` and `ParseRPCSign` convert `auctioneerrpc` messages into the trader's own types. `ParseRPCBatch` is the one that matters most: it takes an `OrderMatchPrepare`, the auctioneer's claim about which orders matched at what price against which node, and builds the `order.Batch` the trader will verify and eventually sign.
- `order/batch_verifier.go`. `batchVerifier.Verify`, `validateMatchedOrder` and `validateChannelOutput` re-derive the expected outcome of the batch from the trader's own order and account state and refuse to accept a batch that differs. This is the code that stands between a lying auctioneer and a signature.
- `auctioneer/client.go` and `auctioneer/account_subscription.go`. The gRPC client, the two-way message stream, the three-way authentication handshake a trader completes for each account, and the reconnection logic.
- `rpcserver.go`. `handleServerMessage` is where a `ServerAuctionMessage` is dispatched: prepare, sign, finalize. Each branch parses, validates, and then acts, and the ordering of those three is the property that matters.
- `sidecar/codec.go` and `sidecar/tlv.go`. `DecodeString`, `DeserializeTicket`, `deserializeOffer`, `deserializeRecipient`, `deserializeOrder` and `deserializeExecution` parse a base58 string with a human-readable prefix and a checksum into a ticket. Anyone who is handed a ticket can hand over a hostile one.
- `account/manager.go` and `account/recovery.go`. Account state transitions driven by on-chain confirmations and spends, plus the recovery path that reconstructs accounts from a batch key. The inputs here are chain data rather than network peers, but they are not the trader's own assertions.
- `funding/manager.go`. `PrepChannelFunding` and `BatchChannelSetup` connect out to matched peers and register funding shims with `lnd`. The peer's parameters arrive from the auctioneer's match message.
- `poolscript/script.go`. The account script, the taproot variants, the key tweaking, and the witness-spend classifiers `IsExpirySpend`, `IsTaprootExpirySpend`, `IsMultiSigSpend` and `IsTaprootMultiSigSpend`.
- The trader's own gRPC API in `rpcserver.go` behind `poolrpc/trader.proto`, gated by the macaroons in `macaroons.go` and `server.go`.

The properties we care about: a trader signs only a batch that conserves its own value and matches its own terms; a batch cannot double-match an account or an order; neither side can be wedged by a counterparty who stalls, lies or disappears; and the account state machine cannot be driven into a state where a trader's funds are stuck or spendable by someone else.

## Components that matter most

In order of damage if wrong.

1. `order/batch_verifier.go`. The single most important file. `Verify` walks every order of ours the auctioneer claims was matched, recomputes the clearing price, the units filled, the fee owed, the account's ending balance and the channel output that results, and rejects the batch on any disagreement. If it can be made to accept a batch whose numbers do not add up, the trader signs a transaction that spends its account for less than it agreed to, or into an output it did not choose. Read `validateMatchedOrder`, `validateChannelOutput` and `DetermineCommitmentType` with `order/batch.go`'s `AccountDiff.validateEndingState` beside them, because the arithmetic is split across the two.
2. `order/rpc_parse.go`. Everything the verifier later checks comes through here. The parsers decide what a batch even contains: which orders matched, at which lease duration, against which node, with which fee rate, and which accounts are charged. A parser that silently drops, duplicates or accepts an inconsistent entry hands the verifier a batch it was not designed to check. `ParseRPCBatch` validating that each matched order's lease duration agrees with the market bucket it arrived in is the shape of the invariant that should hold throughout.
3. `order/batch.go` and `order/batch_signer.go`. `Batch`, `AccountDiff`, `MatchedOrder`, `BatchVersion` and the signing flow. `BatchVersion` gates which features a batch may use, and a version negotiation that can be talked down is a way to get a newer check skipped. `order.AccountDiff.validateEndingState` is where the transaction's actual outputs are compared against the balance the batch claims, so the arithmetic spans `order/batch.go` and `order/batch_verifier.go` and needs to be read as one piece.
4. `order/manager.go`. `OrderMatchValidate`, `BatchSign` and `BatchFinalize`. The ordering here is load-bearing: validate, then store the pending batch durably, then sign, then accept only the finalize that names the batch we validated. `BatchFinalize` comparing the ID against the last validated batch is the property to hold onto.
5. `account/manager.go`. The account state machine: `resumeAccount`, `handleStateOpen`, `HandleAccountConf`, `HandleAccountSpend`, `HandleAccountExpiry`, `DepositAccount`, `WithdrawAccount`, `RenewAccount`, `CloseAccount`, `spendAccount`, `sanityCheckAccountSpendTx`, `valueAfterAccountUpdate` and the MuSig2 signing path. A fault here is a funds-loss bug: an account output that can be spent by the wrong party, an update that loses value, a spend transaction that pays a fee the trader did not agree to.
6. `poolscript/script.go`. `AccountScript`, `TaprootKey`, `TaprootExpiryScript`, `TraderKeyTweak`, `AuctioneerKeyTweak`, `IncrementKey`, `DecrementKey`, `SpendExpiry`, `SpendMultiSig`, `SpendMuSig2Taproot`, and the spend classifiers used to decide how an account output was consumed. The tweaking scheme is what makes each batch's key unique; a fault makes two batches interchangeable or lets the wrong witness be classified as a legitimate spend.
7. `auctioneer/client.go` and `auctioneer/account_subscription.go`. The connection to the auctioneer, including the handshake in `acctSubscription.authenticate` and the dispatch of `ServerAuctionMessage` types. A message routed to the wrong subscription, or a challenge accepted for the wrong commitment hash, is a cross-account confusion.
8. `rpcserver.go`. `handleServerMessage`, `validateOrder`, `SubmitOrder`, `QuoteOrder`, `sendAcceptBatch`, `sendSignBatch`, `sendRejectBatch`, `parseRPCOutputs`, `parseOutputScript`, and the recovery entry points. This is where a trader's operator request and an auctioneer's message meet, and where a rejection has to be complete: a reject that leaves funding shims or pending channels behind wedges the next batch.
9. `funding/manager.go`. `PrepChannelFunding`, `BatchChannelSetup`, `deriveFundingShim`, `registerFundingShim`, `connectToMatchedTrader`, `waitForPeerConnections`, `rejectDuplicateChannels`, `RemovePendingBatchArtifacts` and `DeletePendingBatch`. Channel parameters arrive from the auctioneer's match, and the peer on the other end is a stranger the auctioneer chose.
10. `sidecar/` — `sidecar/codec.go`, `sidecar/tlv.go`, `sidecar/verification.go` and `sidecar/interfaces.go`, together with `sidecar_acceptor.go`. Ticket decoding plus `SignOffer`/`VerifyOffer`/`SignOrder`/`VerifyOrder`. The ticket is handed around as a string, so anything that parses it must be robust, and the signatures are what stop a recipient from rewriting the terms.
11. `clientdb/` — `clientdb/account.go`, `clientdb/order.go`, `clientdb/batch.go`, `clientdb/batch_snapshot.go`, `clientdb/event.go` and `clientdb/codec.go`. The durable ledger of accounts, orders, pending batches and events. `clientdb/codec.go` serializes each of them, so a decode that mangles a record across a restart matters.
12. `terms/fees.go` and `terms/terms.go`, with `order/tradingfees.go` and `order/supplyunit.go`. The fee schedule the trader applies when it checks a batch, and the unit arithmetic every amount in the protocol is expressed in. A rounding or unit fault here is a value leak that shows up only in aggregate.

## Out of scope or low priority

- `auctioneerrpc/` and `poolrpc/`: `auctioneerrpc/auctioneer.pb.go`, `auctioneerrpc/auctioneer_grpc.pb.go`, `poolrpc/trader.pb.go`, `poolrpc/trader_grpc.pb.go`, `poolrpc/trader.pb.gw.go` and `poolrpc/trader.pb.json.go`. All generated by protoc. A defect in the generated marshalling belongs to the protobuf runtime. The `.proto` files next to them are the readable description of the wire surface, and a finding is best expressed against the handler that populates or reads the message. `poolrpc/perms.go` and `poolrpc/format.go` are hand-written and are in scope, as is anything they do with a message field.
- `mock_interfaces.go` in the root, `order/mock_interfaces.go`, `account/mock_interfaces.go`, `sidecar/mock_interfaces.go` and `internal/test/mock_interfaces.go`. Generated gomock output, and test doubles. `internal/test/` as a whole — `internal/test/keys.go`, `internal/test/lightning_mock.go`, `internal/test/signer_mock.go`, `internal/test/walletkit_mock.go` and `internal/test/interfaces.go` — is test scaffolding.
- `tools/`, a separate Go module that builds the linters and mock generators. `gen/` holds the Docker wrapper for mockgen.
- `docs/`. `docs/batch_execution.md`, `docs/accounts.md`, `docs/orders.md`, `docs/sidecar_channels.md`, `docs/account_recovery.md`, `docs/channel_leases.md`, `docs/overview.md`, `docs/lightning_pool.md`, `docs/faq.md`, `docs/install.md`, `docs/quickstart.md`, `docs/SUMMARY.md`, `docs/README.md` and the release notes. Documentation, not behaviour, though `docs/batch_execution.md` is the clearest statement of what the verifier is meant to guarantee and is worth reading first.
- `cmd/pool/` and `cmd/poold/`. `cmd/pool/main.go` is the CLI, whose job is to build a request from flags and print a response. `cmd/poold/main.go` is a thin wrapper that parses configuration and calls `pool.Run`. Argument parsing and output formatting bugs are not protocol vulnerabilities.
- `scripts/release.sh`. Release tooling.
- `codec/` and `marshaler.go`. `codec/codec.go` is the small binary encoder that `clientdb/` and `sidecar/` use to write records; the values it encodes are the trader's own, so a decode of corrupt local state is a robustness question rather than an attack surface. `marshaler.go` builds the `poolrpc` response types from internal state for the REST gateway.
- `chaninfo/`. `chaninfo/channel_info.go` and `chaninfo/scb_keyring.go`, which assemble channel information and the static channel backup keyring for the backup path. It reads `lnd`'s own state.
- `gen.go` and the `//go:generate` directives. Tooling.
- Anything that needs the operator's own unauthenticated access to `poold`'s gRPC API. A caller who can reach that listener with a valid macaroon is the trader; there is no security boundary to cross.
- A finding that a trader's funds are at risk because a batch needs both parties to cooperate. Non-custodial, self-verified, two-of-two batches are the design; the interesting claim is that a party can act unilaterally or that verification can be bypassed, not that a stalling counterparty blocks progress.

## How to exercise it

The scanner builds this project from the Dockerfile enrolled for it, on the Go toolchain the module pins, with the checkout at `/src`. It fetches modules while the network is up, builds everything with `-gcflags='all=-N -l'`, and runs the audit with `GOPROXY=off`. There is no `lnd`, no auctioneer, no bitcoind and no network in the image. That shapes what is and is not demonstrable.

What runs without any of those:

- `go test ./...` runs the suite. There are no build tags to set for the root module: `make/testing_flags.mk` defines `DEV_TAGS` as empty and `UNIT` as `go list -deps ./...` piped through `xargs` into `go test -test.timeout=20m`. `make unit` is that, `make unit-race` adds `-race`, `make unit-cover` writes `coverage.txt`.
- `go test ./order/` is the highest-value target. `order/batch_verifier_test.go`, `order/rpc_parse_test.go`, `order/manager_test.go`, `order/batch_test.go`, `order/batch_storer_test.go`, `order/tradingfees_test.go`, `order/supplyunit_test.go` and `order/interfaces_test.go` are all pure Go and construct their inputs directly. `order/batch_verifier_test.go` is where a whole batch is constructed from `auctioneerrpc` values and run through the verifier, which makes it the fastest route to a reproducer for anything about the auctioneer's messages; `order/rpc_parse_test.go` covers the node-identity slice encoding and the error cases around it.
- `go test ./sidecar/` covers ticket codec and verification: `sidecar/codec_test.go` already includes `TestDecodeRandomInputs`, so random and malformed ticket strings are an established pattern here. `sidecar/tlv_test.go` and `sidecar/verification_test.go` cover the wire format and the signature checks.
- `go test ./account/` covers the state machine and recovery with mocks: `account/manager_test.go`, `account/recovery_test.go` and `account/auth_test.go`. `account/watcher/` has its own tests. The wallet, signer and chain-notifier seams are interfaces with mocks in `account/mock_interfaces.go` and `internal/test/`, so most account paths are reachable in-process.
- `go test ./poolscript/` covers the script construction and the witness classifiers. `make fuzz` is `go test -fuzztime 1m -fuzz FuzzWitnessSpendDetection ./poolscript`, and `FuzzWitnessSpendDetection` in `poolscript/script_test.go` is a ready-made harness for arbitrary witness bytes. Extending it is cheap.
- `go test ./clientdb/` covers the local store against an in-process database, including the batch snapshot and event paths.
- `go test ./auctioneer/` covers the client and the account subscription with mocks. `auctioneer/client_test.go` and `auctioneer/account_subscription_test.go` show how to drive message dispatch without a server.
- `go test -run TestName ./` for the root package, whose `rpcserver_test.go` and `sidecar_acceptor_test.go` cover the account renew and sidecar negotiation paths against mocks.
- Directly: `go test -run 'TestName' -v ./order/` while iterating on one case, and `make build` to produce the `pool` and `poold` binaries, which is useful mostly to confirm the tree still compiles.

What the image cannot do, and how to report it:

- Anything that needs a live `lnd` cannot be demonstrated. The `lndclient` seams in `account/interfaces.go`, `funding/manager.go`'s `BaseClient`, and `internal/test/` are the way through: a claim about a funding shim, a channel acceptance or an invoice should be expressed against the interface it actually calls, with a double in place of the node.
- Anything that needs a running auctioneer cannot be demonstrated end to end. The client side is still testable, because `auctioneer.Client` consumes a stream of `ServerAuctionMessage` values that a test can synthesize; `rpcserver.go`'s `handleServerMessage` takes such a message directly. Write the reproducer as "given this message from the auctioneer, the trader does X", not "the auctioneer can be made to send this message" unless you can show the trader itself constructs it.
- Anything needing on-chain confirmation needs the chain-notifier double.
- The integration test harness lives outside this repository and is not in the image. Do not assume it is available.

A reproducer that cannot be run in the image is still in scope. Say plainly which seam you stubbed, what a real deployment would have to be doing for the fault to fire, and how far the in-process test gets. We will read that as weaker evidence than a failing test and stronger than an argument.

## How we rate severity

Critical:

- Any path where a trader signs, or is made to sign, a batch transaction that spends its account into an output it did not choose, for an amount it did not agree to, or at a fee above its `MaxBatchFeeRate`. This is loss of funds, and it is the property the entire verifier exists to guarantee.
- Any path that breaks value conservation in a batch: a double-match of one account or one order, a clearing price that does not match the one the batch claims, an account ending balance that does not equal what the transaction's outputs actually pay, or a channel output that goes to a different node than the one matched.
- Any way for a hostile auctioneer to obtain a valid signature from a trader without passing verification, or to reuse a signature from one batch in another.
- Any account script or witness-handling fault that lets a party other than the trader spend an account output before its expiry, or lets the expiry path be taken early.

High:

- A remotely triggered panic or unbounded allocation in a message parser that a counterparty controls: `ParseRPCBatch`, `ParseRPCMatchedOrders`, `ParseRPCSign`, or the ticket decoder in `sidecar/codec.go`. Reachable from a peer, cheap for that peer to repeat, and it takes the trader offline for the duration of the batch window.
- Any way for a counterparty to permanently wedge a trader: a batch that leaves funding shims, pending channels or pending-batch state that cannot be cleared, so no subsequent batch can proceed. Persistent, remotely triggerable, and it costs the trader its participation. Medium if a restart or an operator command clears it.
- A state-machine fault that makes a trader's account unusable or its local records inconsistent with the chain, where recovery is possible but not automatic.
- A fault that lets a batch message be accepted for a different account or order than the one it names, without loss of funds but with a wrong-account side effect.

Medium:

- A DoS that needs the counterparty to be a real participant with funds at stake, or that needs many batches to accumulate. A hostile auctioneer is a serious threat model but it is a single, identifiable party, not an anonymous crowd.
- A panic in a path that only the operator's own CLI invocation reaches.
- A validation gap in an operator-supplied order parameter that produces an order behaving differently than its stated terms, where the operator had to ask for the odd value.
- Fee or unit arithmetic that leaks a small, bounded amount of value per batch, or that only misbehaves at amounts far outside realistic ranges, where the direction of the error is not clearly in an attacker's favour.

Low:

- Missing validation with no demonstrated effect on what gets signed or what gets spent. A parser that returns a clean error is the intended outcome.
- Imprecise error messages on a path the operator, not a counterparty, reaches.
- Local state that can be written into an odd but harmless shape by an operator command.

Out of scope for a rating, even when worth a sentence:

- That a trader needs both parties to cooperate to complete a batch. Non-custodial two-of-two is the design.
- That a batch can be rejected for any reason at all, including a peer connection failure. `docs/batch_execution.md` states this as intended behaviour.
- Dependency advisories with no demonstrated path through pool's own code.
- A trader-side disclosure of a value the auctioneer already knows: prices, node identities and match sizes all travel in the clear inside the encrypted channel by design.

The dividing question: does the fault let a counterparty change what the trader signs, spend, or is left holding? If yes, critical. If it lets a counterparty stop the trader operating, high when persistent and medium when transient. If it only affects what an operator sees or does, medium at most.

## Report and patch preferences

What we want, in order:

- A Go test in the package that owns the fault, using the existing mocks. `order/batch_verifier_test.go` and `order/rpc_parse_test.go` are the models: construct the batch or the message, run the verifier or the parser, assert on the outcome.
- For anything involving a signature or a spend, the exact bytes or values. Which account, which input, which output, which amount, which fee rate, and what the trader's own order said the limit was. A claim about a batch verifier flaw without the arithmetic spelled out is not reviewable.
- The counterparty's capability stated explicitly: is this a hostile auctioneer, a hostile trader on the other side of a match, or an operator mistake? The severity turns on that answer, so a report that does not answer it will be rated conservatively.
- The observable: did a signature come back, was a batch accepted, was a record written, did the store end up in a state that blocks the next batch.

A merge-ready patch is welcome and preferred when it is a check in the parser or the verifier: reject the entry, return the error, keep going. Please do not restructure the batch protocol or the account state machine in a patch. Do not change the exported interfaces in `order/interfaces.go` or `account/interfaces.go`, because the mocks and downstream integrations are built against them, and do not change `auctioneerrpc/auctioneer.proto` — the auctioneer is a separate service and a wire change is a coordinated release, not a pull request.

When the fault needs a live node or a live auctioneer, express it against the seam: name the interface, show the double you used, and state what the real counterparty would have to send. A report that says "with this `auctioneerrpc.OrderMatchPrepare` value, `ParseRPCBatch` followed by `OrderMatchValidate` accepts a batch whose ending balance does not match the transaction" is worth far more than one that says the auctioneer could misbehave.

## Anything to leave alone

The shapes that look wrong and are not:

- A batch being rejected at any point is always allowed. `OrderMatchValidate` returning an error, `PrepChannelFunding` failing, a peer connection timing out — all of these lead to a reject message, and that is the protocol working. A report that a trader can be made to reject a batch needs to show that the rejection is unrecoverable, not merely that it happened.
- `MismatchErr` and `ErrMismatchErr` in `order/batch_verifier.go` deliberately wrap the cause so callers can test the class of failure with `errors.Is` without parsing strings. The slightly redundant-looking error plumbing there is intentional.
- Deterministic randomness in test doubles. `internal/test/keys.go` and the mock signers produce fixed keys and fixed nonces; the carve-out in `sidecar/codec_test.go` for a fixed ticket is the same idea. Fixed values in tests are not a finding.
- `macDbDefaultPw` in `macaroons.go` is an empty password, and the comment says so and says why: the keys are encrypted on disk but the password is known. Changing it needs a create/unlock flow the API does not have. This is a documented, deliberate state of affairs, not an oversight to report.
- The auctioneer's key tweak and the trader's key tweak produce a per-batch key. A report that the account key changes between batches is describing the scheme.
- `sidecar` tickets carry a checksum and a human-readable prefix, and the checksum is not a signature. A ticket whose checksum validates but whose contents are otherwise arbitrary is expected: authenticity comes from `VerifyOffer` and `VerifyOrder`, not from the checksum. Do not report the checksum as an integrity failure.
- Rejecting an order whose `min_units_match` is zero or above the order's total units, in `order/rpc_parse.go`, is deliberate input validation, not an arbitrary restriction.
- The `batchVersion` negotiation in `order/batch.go` is versioned so a trader can refuse a batch using features it does not implement. A report that an old version skips a newer check needs to show the trader agreeing to the old version when it supports the new one.
- `MaxBatchIDHistoryLookup` in `order/batch.go` is a loop bound chosen to avoid an unbounded walk when iterating batch IDs from an invalid starting point. It is a guard, not a limit being hit in normal operation.
- `acctSubscription.authenticate` uses a fresh random nonce combined with the account's derived key to build the commitment hash. A report that the commitment hash is not secret is describing a value that is meant to be a public commitment.
- The trader's local database, its macaroon database and its order store are trusted inputs on the way in. A malformed record can come from a crash or a disk fault, and handling that is a robustness question at most; a report that requires the attacker to write the trader's database first has no attacker.
- `mock_interfaces.go` files and every `*_test.go`. Generated doubles and test code.
- `unsafe` does not appear in the hand-written code of this repository. If you find it, it is in generated protobuf output.
- The image builds with `-gcflags='all=-N -l'`, which disables inlining and optimisation so panic traces match the source. Do not report the reduced optimisation.
- Panics that a caller triggers by handing a function an already-inconsistent struct, such as a `order.Batch` with a nil `BatchTX` or an `account.Account` whose script version disagrees with its key. The code documents the contracts it expects its own packages to keep.

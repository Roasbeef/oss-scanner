# Threat model: lightning-node-connect

## What this project does and where untrusted input enters

Lightning Node Connect (LNC) is the transport that lets a browser or a mobile application talk gRPC to a Lightning node without the node exposing a listening port. The node dials out to a public mailbox relay and waits; the client dials the same relay; the relay matches the two halves by a stream identifier and forwards opaque frames in each direction. On top of that relayed byte stream the two peers run a Noise handshake, and everything after the handshake is an encrypted, authenticated session carrying HTTP/2, which is how a gRPC client reaches the node. The pairing secret is a ten-word passphrase, so the protocol has to be a password-authenticated key exchange rather than a plain key exchange, and the mailbox identifier is derived from that same passphrase entropy.

There are three distinct parties, and the security of the whole thing rests on being precise about what each of them can do.

- **The mailbox server** relays frames and nothing more. It sees stream identifiers, frame sizes and timing. It must not be able to read the session, must not be able to forge or reorder the application's operations, and must not be able to substitute itself for the node the client meant to reach. A hostile or colluding mailbox can at worst deny service. That is the central property.
- **The remote client** is untrusted by the node. After pairing it holds a macaroon scoped by the node operator, and it can send arbitrary gRPC frames within that scope. Its confinement is the macaroon, not this library.
- **A stranger who guesses or learns a stream identifier** is untrusted by both. Stream identifiers are the relay's only access control, so what that identifier does and does not protect is worth understanding before writing a report.

Untrusted bytes reach the code through these entry points:

- `mailbox/interface.go`. `MsgData.Deserialize` parses the framing every relayed message arrives in: a version byte, a four-byte big-endian length, then that many payload bytes. The length is attacker-chosen.
- `mailbox/noise.go`. The Noise state machine. `Machine.DoHandshake`, `handshakeState.readMsgPattern`, `handshakeState.readTokens`, `Machine.ReadHeader`, `Machine.ReadBody` and `Machine.ReadMessage` all consume bytes supplied by the peer, and the peer may be an imposter rather than the intended node. The handshake acts differ per version (`HandshakeVersion0`, `HandshakeVersion1`, `HandshakeVersion2`) and the payload sizes differ with them.
- `mailbox/noise_patterns.go`. `XXPattern` (the `XXeke+SPAKE2` pattern) and `KKPattern`, the two handshake shapes. `XX` masks the initiator's ephemeral key with the passphrase-derived SPAKE2 operation; `KK` is used once both sides know each other's static keys.
- `mailbox/grpc_noise_conn.go`, `mailbox/tcp_noise_conn.go` and `mailbox/tcp_noise_listner.go`. The `TransportCredentials` and `net.Conn` adapters. `NoiseGrpcConn.Read` buffers a partially consumed message in `nextMsg`, which is the seam where a framing mistake would show up.
- `mailbox/client_conn.go`, `mailbox/server_conn.go` and `mailbox/client_transport.go`. The mailbox streams themselves: `createReceiveMailBox`, `createSendMailBox`, `recv`, `send`, and the websocket and gRPC transports underneath. `stripJSONWrapper` parses the text wrapper the websocket transport delivers.
- `mailbox/conndata.go`. `ConnData.SID` derives the mailbox stream identifier from the passphrase entropy alone, or from an ECDH of the two static keys once the remote key is known. `SetRemote` and `SetAuthData` run the callbacks that decide whether the peer is acceptable.
- `gbn/messages.go` and `gbn/gbn_conn.go`. Go-Back-N provides reliability over a stream that can drop, reorder or duplicate. `Deserialize` parses a five-byte-or-less header plus payload from arbitrary bytes, and `GoBackNConn.Recv` reassembles chunks until `FinalChunk`. Sequence numbers are a single byte, so wraparound is normal rather than exceptional.
- `gbn/queue.go`, `gbn/syncer.go` and `gbn/timeout_manager.go`. The resend queue, the sync state machine and the adaptive timers. A hostile peer drives all three with ACK and NACK values it chooses.
- The `hashmailrpc/hashmail-lnd.proto` service, which is the relay's own API and is what an operator runs. It accepts a stream identifier and a bidirectional message stream from anyone.

The properties we care about: the noise session authenticates the specific node the client intended; a malicious mailbox cannot impersonate that node, downgrade the handshake, or splice two sessions together; the Go-Back-N layer cannot be made to deliver a duplicated or reordered application message; and any frame from any peer costs bounded work and bounded memory.

## Components that matter most

In order of damage if wrong.

1. `mailbox/noise.go`. The handshake and the record layer. `DoHandshake`, the `readMsgPattern`/`readTokens` pair, `cipherState.Encrypt`/`Decrypt`, `symmetricState.mixKey`/`mixHash`/`EncryptAndHash`/`DecryptAndHash`, `split`, `WriteMessage`, `Flush`, `ReadHeader` and `ReadBody`. A fault here is total: a session that can be read, forged, replayed or downgraded. Pay particular attention to the fact that `ReadHeader` treats the decrypted length as the amount to read next, and to the fact that `readMsgPattern` reads a peer-chosen version byte before any MAC protects it — both are places where the input says how much work to do.
2. `mailbox/noise_patterns.go` and the SPAKE2 masking in `mailbox/noise.go` (`ekeMask`, `ekeUnmask`, `hmac256`, `ecdh`). The masked ephemeral in the first act is what turns a guessed passphrase into a failed handshake rather than an observable one. A fault that lets an active attacker confirm a passphrase guess, or that lets the masking be stripped, defeats the pairing security model.
3. `mailbox/conndata.go`. `ConnData.SID`, `HandshakePattern`, `SetRemote`, `SetAuthData` and the `onRemoteStatic`/`onAuthData` callbacks. This is where the decision "is this peer the node I meant" is actually made, and where the stream identifier is derived. Confusing the two, or letting the identifier be derived from something the mailbox can choose, breaks the separation between relay and session.
4. `mailbox/interface.go`. `MsgData.Serialize`/`Deserialize`, `connKit.Read`/`Write`, and the `ControlMsg` contract. The outer framing of every relayed frame. A length that is trusted before it is bounded is the classic bug in this shape.
5. `gbn/messages.go`, `gbn/gbn_conn.go`, `gbn/queue.go` and `gbn/syncer.go`. Reliability over an unreliable stream. `Deserialize`, `Send`, `Recv`, `sendPacketsForever`, `receivePacketsForever`, `queue.addPacket`, `queue.processACK`, `queue.processNACK`, `syncer.processACK` and `syncer.processNACK`. Because the mailbox is not trusted, a duplicated, dropped or reordered frame is a normal input, and a single-byte sequence space means a hostile peer can always find a value that collides.
6. `mailbox/grpc_noise_conn.go`. `NoiseGrpcConn.Read`, `Write`, `ClientHandshake` and `ServerHandshake` (the two halves of the `credentials.TransportCredentials` interface), plus the `nextMsg` partial-read buffer and `proxyConnMtx`. This is the adapter between a byte-stream `net.Conn` and gRPC's expectations, and getting the buffering wrong splits a frame across two reads.
7. `mailbox/client_conn.go`, `mailbox/server_conn.go` and `mailbox/client_transport.go`. The stream lifecycle: Dials, retries, teardown, reconnection and `RefreshClientConn`/`RefreshServerConn`. A reconnect that reuses the wrong identifier, or that resumes a half-consumed state, is a session confusion.
8. `gbn/timeout_manager.go` and `gbn/backoff_wait.go`. Adaptive timers driven by measured response times. A hostile peer that stops responding, or that responds instantly, moves these numbers. An unbounded boost is a way to make a client hammer the relay.
9. `mailbox/tcp_noise_conn.go` and `mailbox/tcp_noise_listner.go`. The same noise session over a plain TCP listener, used for direct connections and by the test harness. Where the mailbox is absent, the peer supplies the bytes directly.
10. `mailbox/crypto.go`. `NewPassphraseEntropy`, `PassphraseEntropyToMnemonic`, `PassphraseMnemonicToEntropy` and the scrypt parameters. The passphrase is the whole security of the first pairing, so the entropy, the word encoding and the KDF parameters are load-bearing.

## Out of scope or low priority

- `mobile/`. This module does not build, and it is excluded from the image. The compiler reports unknown fields on the subserver config structs that `github.com/lightninglabs/lightning-terminal/perms` v1.0.5 populates, against the `lnrpc` stub versions the module pins; that mismatch is pre-existing in the dependency set and nothing in this repository changes it. Because the module cannot be compiled, nothing in `mobile/` can be exercised in the image, so a report about it cannot be demonstrated. Do not send one. The same applies to `mobile/go.mod` and `mobile/deps.go`.
- `cmd/wasm-client/`. Its own module, built only for `GOOS=js GOARCH=wasm`, and its files are behind a `js` build constraint, so it is not compiled by the image either. It is the reference browser client and is interesting for understanding how the pieces fit, not as a place to find memory-safety bugs. A finding that lives in shared code and is merely first noticed from here should be reported against the shared code.
- Generated code: `hashmailrpc/hashmail-lnd.pb.go`, `hashmailrpc/hashmail-lnd.pb.gw.go` and `hashmailrpc/hashmail-lnd_grpc.pb.go`. Protoc output. `hashmailrpc/hashmail-lnd.proto` is the readable description of the relay's API and is where a finding about the wire surface should be expressed.
- `itest/`. `itest/connection_test.go`, `itest/integration_test.go`, `itest/client_harness.go`, `itest/server_harness.go`, `itest/hashmailserver_harness.go`, `itest/test_harness.go`, `itest/test_list_on_test.go` and `itest/test_list_off_test.go`. Behind the `itest` build tag, and they need a live `lnd` node, a real mailbox and a regtest chain. Useful reading for how the protocol is driven end to end; not a place to find a vulnerability, and not runnable in the image.
- `itest/mockrpc/`. A trivial hello-world gRPC service and its Dockerfile, used by the integration harness.
- `example/` and `example-server.go`. `example/index.html`, `example/wasm_exec.js` and a static file server used to host the WASM client locally. Demo material.
- `doc/lnc.svg`. A diagram.
- `README.md`, `RELEASE.md` and the Dockerfiles other than the one the scanner builds. Documentation and packaging.
- `make/` and `scripts/`. Build plumbing, including `make/testing_flags.mk`.
- `mailbox/numsgen/`. Its own module: a small generator that derives the SPAKE2 group parameters for a given seed phrase. Tooling, run by a maintainer, not part of the runtime. `mailbox/crypto_rpctest.go` is a build-tagged helper in the same spirit.
- `logs/`. Log output.
- Randomness in tests and vectors. `mailbox/noise_test.go`, `mailbox/tcp_noise_test.go` and `gbn/rapid_test.go` use fixed passphrases and fixed keys, and that is what makes them reproducible.
- Anything that needs the caller to hand in an already-inconsistent value, such as a `ConnData` with no local key, or a `Machine` used after the handshake has been split. Those are documented contracts within the library.
- The claim that the mailbox itself is trusted to keep the two halves of a stream apart. It is not, and where that assumption is load-bearing the code says so; a report should show a consequence, not merely the assumption.

## How to exercise it

The scanner builds this project from the Dockerfile enrolled for it, with the checkout at `/src`. It fetches modules while the network is up, builds with `-gcflags='all=-N -l'`, and runs the audit with `GOPROXY=off`. It does not build `mobile/`, which is why that module is out of scope above.

This repository is a root module plus four more that build: `gbn/`, `mailbox/`, `hashmailrpc/` and `mailbox/numsgen/`. `cmd/wasm-client/` is a fifth that only builds for the WASM target. Every module carries its own `go.mod`, so a command run at the repository root does not cover the submodules; you have to enter each one. The build tags matter too: the root module and its tests need the RPC tag set the Makefile defines, otherwise the `lnrpc` subserver stubs the harness references are absent.

The RPC tags the Makefile sets as `RPC_TAGS`, needed for the root module's tests:

```
appengine autopilotrpc chainrpc invoicesrpc neutrinorpc peersrpc signrpc
wtclientrpc watchtowerrpc routerrpc walletrpc verrpc
```

The commands, all of them what the repository's own `Makefile` runs:

- `make unit` at the root is `go test -tags="$(RPC_TAGS)"` over `go list github.com/lightninglabs/lightning-node-connect/...`, with `-test.timeout=20m` from `make/testing_flags.mk`. `make unit-race` adds `-race`. `make build` is `go build -tags="$(RPC_TAGS)"` over the same package list.
- The three library submodules build and test on their own:
  `cd gbn && go test ./...`, `cd mailbox && go test ./...`, and `cd hashmailrpc && go build ./...`. These need no RPC tags, and they are where most of the interesting tests live.
- `mailbox/` is the richest target. `mailbox/noise_test.go` includes `TestSpake2Mask` and `TestXXHandshake`, which run a full handshake between two in-process machines and then exchange messages over the resulting connection — that is the harness to extend for anything about the handshake or the record layer. `mailbox/tcp_noise_test.go` does the same over a real loopback listener, using `testing/iotest` to interpose on the byte stream, which is exactly the tool for a partial-read or split-frame claim. `mailbox/interface_test.go` covers the `MsgData` framing (`TestControlMsgSerializeDeserialize`).
- `gbn/` is equally rich and entirely in-process. `gbn/gbn_conn_test.go` drives a client and server connection against each other with `sendBytesFunc`/`recvBytesFunc` closures standing in for the network, so any frame sequence can be injected without a relay. `gbn/message_test.go` covers `Serialize`/`Deserialize`. `gbn/queue_test.go`, `gbn/syncer_test.go` and `gbn/timeout_manager_test.go` cover the reliability machinery.
- `gbn/rapid_test.go` is a property-based suite already in the tree, using `pgregory.net/rapid`. `TestRapidMessageRoundTrip` and `TestRapidDeserializeNeverPanics` are directly relevant: deserialising arbitrary bytes must return an error rather than panic, and the existing test is the template for a reproducer.
- A single case: `cd mailbox && go test -run 'TestXXHandshake' -v .`, or `cd gbn && go test -run 'TestRapidDeserializeNeverPanics' -v .`.
- Fuzzing is available and cheap here. `cd mailbox && go test -run '^$' -fuzz '^FuzzName$' -fuzztime=60s .` after adding a `Fuzz` function, which is the shortest path from a suspicion about `MsgData.Deserialize`, `Machine.ReadHeader` or `gbn.Deserialize` to a concrete crashing input.

What the image cannot do:

- A reproducer that needs a live mailbox server can usually be rewritten without one. Both ends of the protocol are in this tree, and every constructor takes the connection it will use — `mailbox.NewServer` and `mailbox.NewGrpcClient` take `grpc.DialOption`s, and `mailbox.NewClient` accepts `mailbox.WithGrpcConn` — so a `bufconn`-backed `hashmailrpc.HashMailServer` implementation in a test stands in for the relay and lets you drop, duplicate, reorder or substitute frames at will. That is a better reproducer than one against a real relay, because you control the malice precisely. Writing a hostile relay is the expected way to demonstrate any claim about a malicious mailbox.
- A reproducer that needs a live `lnd` node cannot be demonstrated. The integration harness in `itest/` is the only code that knows how to drive one, and it is out of the image. Express such a claim against `mailbox` or `gbn` directly instead, since the node is above the transport.
- `mobile/` cannot be compiled at all, as described above.
- The WASM client cannot be run; there is no browser in the image.

A finding you can only reach with a real relay, a live node or a browser is still in scope. Say which of those it needs, show how far an in-process harness gets, and be explicit that the remaining step is untested. That is weaker than a failing test and much stronger than an untested assertion.

## How we rate severity

Critical:

- Any way for a party other than the intended node to complete a session with a client at the same security level, or for the mailbox to substitute itself for the node without the client noticing. Identity is the only thing the session provides; if it can be forged, the macaroon the client then sends is the attacker's.
- Any way to read or forge application data without the session keys: a plaintext leak, a MAC that can be bypassed or truncated, a nonce-reuse that allows recovery, or a downgrade to a handshake version without authentication.
- Anything that lets an attacker who does not know the passphrase distinguish a correct guess from an incorrect one, or that reduces the pairing search space below the passphrase entropy. The SPAKE2 masking exists for exactly this property.
- Any way to make the Go-Back-N layer deliver the same application message twice, deliver messages out of order to the layer above, or drop one silently while reporting success. Operations carried over LNC include things that are not idempotent, so duplication is a correctness and safety bug, not a throughput bug.

High:

- A remotely triggered panic in a parser reachable from a relayed frame: `MsgData.Deserialize`, `Machine.ReadHeader`, `Machine.ReadBody`, `handshakeState.readMsgPattern`, `handshakeState.readTokens` or `gbn.Deserialize`. The peer can be a stranger, the input is cheap to send, and a crash ends the session for a node that is trying to stay reachable.
- Work or allocation that scales with a length field rather than with the bytes actually delivered, in `MsgData.Deserialize`, in the handshake's act-two length read, or in `Machine.ReadBody`. High when the amplification is large or when it can be repeated to exhaust memory, medium when it is bounded by the frame size.
- Any way for a hostile mailbox to make a session permanently unusable, or to cause a reconnect loop that keeps the node off the relay, where the effect outlives the attack.
- A session-state confusion that lets a reconnected client resume another session, or an identifier derived for one peer be used for another.

Medium:

- A DoS that needs the attacker to hold the stream identifier, which is derived from the passphrase and therefore itself a secret. Someone who has the identifier already has a substantial capability, so the marginal gain matters less.
- A DoS that requires many frames or a long-lived connection rather than one.
- A panic in a path that needs a well-formed handshake first, so the attacker must already be a session peer.
- Resource growth in `gbn` driven by a peer's ACK/NACK behaviour that is self-limiting or cleared on reconnect.
- A timing or size observation that distinguishes protocol states without revealing a secret, where the observation requires many samples and produces no key material.

Low:

- Missing validation with no demonstrated effect: an implausible field accepted and then ignored, an error that is unhelpful rather than wrong.
- Behaviour differences between handshake versions that the version negotiation explicitly permits.
- Imprecise error messages or log lines.

Out of scope for a rating, even when worth a sentence:

- That the mailbox server learns stream identifiers, message sizes and timing, and could correlate two streams. It is a relay; that metadata is its function. The interesting claim is that it learns more than metadata.
- That a client which has already paired and cached the remote static key uses `KKPattern`, which does not need the passphrase. That is the design: pairing happens once and later sessions authenticate with the static keys.
- Dependency advisories with no demonstrated path through this code.
- That a party who obtains a valid macaroon can make gRPC calls. Confining the macaroon is the node's job, not this library's.

The dividing question: does the fault let someone who is not the intended peer read, forge, duplicate or reorder application data, or make the session indistinguishable from a legitimate one? If yes, critical. If it lets an unauthenticated stranger crash or exhaust the process, high. If it needs the identifier, the passphrase, or an established session first, medium. If nothing observable changes, low.

## Report and patch preferences

What helps, in order:

- A Go test in `mailbox` or `gbn` that fails. Both packages are self-contained and their existing tests already build both ends of a connection in process, so almost anything can be shown without a relay, a node or a browser. `TestXXHandshake` in `mailbox/noise_test.go` and the harness in `gbn/gbn_conn_test.go` are the shapes to copy.
- For anything about a hostile mailbox, the test should be an actual malicious relay: a `hashmailrpc.HashMailServer` implementation on a `bufconn` that drops, duplicates, reorders or substitutes frames. That both demonstrates the fault and shows precisely what the attacker does, which is what we need in order to judge severity.
- For anything about framing, the exact bytes. A hex literal for the frame, or the sequence of `Write` calls, is better than a description. `testing/iotest` and `OneByteReader` are the tools for a partial-read claim.
- The observable spelled out: a panic instead of an error, a duplicated message at the receiver, a silently dropped message, a handshake that completes when it should have failed, a number of bytes allocated.
- For anything claimed as a session-identity break, which handshake pattern and which version are in play, because `XX` and `KK` have different premises and a report that does not say which it breaks is not reviewable.

A merge-ready patch is welcome for a local fix: a bounds check in the parser at fault, a returned error instead of a panic, a bounded read. Please do not restructure the noise state machine or change the wire format in a patch; the format is versioned and both ends have to agree. Do not change the exported signatures of `mailbox` or `gbn`: `mailbox` is an imported library, and `aperture` and `lightning-terminal` both depend on it by version.

When the fault needs a real second party, express it against the sides that exist: a client machine, a server machine and a relay you wrote. Three in-process pieces are enough to say almost everything about this protocol, and a report built that way is easier to act on than one that says a real mailbox would have to be malicious.

## Anything to leave alone

The shapes that look wrong and are not:

- The length prefix in `MsgData.Serialize` is written before the payload and read back by `MsgData.Deserialize`. Reading a length and then reading that many bytes is the protocol; the question is only whether the read is bounded by what arrived, never whether a length prefix exists.
- `Machine.ReadHeader` decrypting the length and then reading that many bytes is the construction the package documents: the length is authenticated by the same AEAD that carries the body, and the encrypted length is used as associated data so the header is bound to the body. Do not report "the length is read from the wire".
- The all-zero associated data and nonces in the handshake's `EncryptAndHash` calls follow the Noise specification for that act. Each act uses fresh key material from the chaining key. A fixed nonce under a reused key would be a finding; this is Noise.
- `ekeMask` and `ekeUnmask` are SPAKE2-style masking, not encryption. The masked point is meant to be publishable; the security comes from the passphrase being needed to unmask it. Reporting that the first act's ephemeral key is not confidential is reporting the design.
- `scryptN`, `scryptR`, `scryptP` in `mailbox/crypto.go` are tied to protocol version 0 and documented as such. A report that different parameters would be stronger is a compatibility question, not a vulnerability, unless you can show the current cost is low enough to make an online guess feasible in the session's lifetime — in which case show the arithmetic.
- `NumPassphraseWords` being ten and `NumPassphraseEntropyBytes` being fourteen is a deliberate encoding of the same entropy into a human-typable phrase. The word count is not the entropy.
- `ConnData.SID` returning the same value for both sides, differing only in the last bit between the send and receive streams, is documented at the function. That symmetry is what makes the two one-way streams of a mailbox pair line up.
- The single-byte sequence numbers in `gbn/messages.go`. A one-byte space wraps constantly, and `gbn/queue.go` and `gbn/syncer.go` handle the wrap with their own comparison helpers rather than arithmetic. Reporting "the sequence number can wrap" is reporting the design; report it only if you can show the wrap logic delivering a duplicate or an out-of-order message.
- `gbn.Deserialize` returning `io.EOF` for every unrecognised or short input is intentional: a garbage frame on a relayed stream is an ordinary event, not an exceptional one. An unhelpful error here is not a finding, and `TestRapidDeserializeNeverPanics` already asserts it does not panic on arbitrary bytes.
- Recovery, retry and reconnection in `mailbox/client_conn.go` and `mailbox/server_conn.go` are long-lived loops by design: a mailbox stream that drops is expected, so `createReceiveMailBox`, `createSendMailBox`, `recv` and `send` retry until the caller's context is cancelled. A report that a client retries needs to show what an attacker gains, beyond the client doing what it is built to do.
- `gbn/backoff_wait.go` and the adaptive timers in `gbn/timeout_manager.go` deliberately move with measured response times. A report that a timeout can grow or shrink is describing the mechanism; report only if a peer can move it without bound in a way that causes harm.
- The `appengine` build tag in `RPC_TAGS` is there because of the flag-parsing library's OS-specific terminal code, as the `Makefile` comment says. It is not a deployment target.
- Fixed passphrases, fixed private keys and fixed nonces throughout the tests, including `mailbox/tcp_noise_test.go`'s package-level `pass` and `passHash`. Test fixtures.
- `mobile/` failing to build is a known, pre-existing dependency mismatch and is excluded from the image by design. Do not report the build failure itself, and do not report anything inside that module.
- The `-gcflags='all=-N -l'` build in the image disables inlining and optimisation so panic traces match the source. Do not report the reduced optimisation or the larger binary.
- `unsafe` does not appear in the hand-written code here. If you find it, it is in generated protobuf output.
- Panics that require the caller to misuse the library: constructing a `Machine` without a config, using a `NoiseGrpcConn` after `Close`, or calling `split` twice. Those are stated contracts between packages in this tree.

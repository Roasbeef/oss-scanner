# Threat model: lightning-onion

## What this project does and where untrusted input enters

lightning-onion implements the onion routing layer for the Lightning Network as
specified in BOLT 4. It is a single Go package, `sphinx`, that builds Sphinx
packets and peels them one hop at a time. It also implements the layered
surrounding the routing blob: the per-hop payload formats, the replay log the
receiver uses to reject duplicate packets, the error obfuscation used for
failure messages travelling backwards along a route, and the route-blinding
construction.

The library is consumed by lnd. Every payment lnd sends is constructed here, and
every onion lnd receives from a channel peer is parsed here. That second half is
where the hostile input is.

Untrusted bytes reach the package through these entry points:

- `Router.ProcessOnionPacket` in `sphinx.go` is the main one. The caller hands in
  an `*OnionPacket` that a remote peer authored, plus the associated data for the
  HTLC. Everything the packet contains is attacker chosen: the version byte, the
  33-byte compressed ephemeral key, the routing info blob and the 32-byte header
  MAC. The caller is expected to have bounded the total size by its own framing;
  in lnd an `update_add_htlc` onion is at most 1300 bytes and an onion message is
  at most 32768 bytes.
- `OnionPacket.Decode` in `sphinx.go` is the decoder for the serialized form: one
  version byte, one compressed public key, then the rest of the reader as routing
  info with the final 32 bytes taken as the MAC.
- `DecodeHopPayload` in `payload.go` parses the per-hop blob that is uncovered
  after a layer is decrypted. It decides between the legacy fixed-size format and
  the TLV format from the first byte, reads a varint length prefix through
  `ReadVarInt` in `varint.go`, then reads the payload and the next hop's HMAC.
- `Router.DecryptBlindedHopData` and `Router.NextEphemeral` in `sphinx.go`, with
  `blindedNodeID`, `encryptBlindedHopData` and `decryptBlindedHopData` in
  `path.go`, handle route-blinded routing. The encrypted hop data and the
  blinding point arrive from a remote peer.
- `OnionErrorDecrypter.DecryptError` in `crypto.go` parses a failure message that
  a hop further along the route sent back. The whole blob is attacker authored,
  and the decryption loop always runs the full `NumMaxHops` iterations so that
  timing does not reveal where in the route the failure came from.
- `ReplaySet.Decode` in `replay_set.go` reads sequence numbers back from storage.
  This is local data rather than remote, but it is parsed state.

A useful way to hold the whole thing: a sender picks a route, derives one shared
secret per hop, and lays down each hop's instructions under a stream cipher keyed
per layer, with an HMAC over the resulting blob chained backwards from the last
hop. A receiver is only supposed to learn its own instructions, and only after
proving it can compute the shared secret. Everything in the components below
serves that.

## Components that matter most

In order of damage if wrong.

1. `sphinx.go`, the unwrap path: `unwrapPacket`, `processOnionPacket`,
   `ProcessOnionPacket`, `ReconstructOnionPacket` and `Tx.ProcessOnionPacket`.
   This is where the header MAC is checked, the layer is decrypted, the
   ephemeral key is re-blinded for the next hop, and the next packet is built.
   A mistake here is a routing-integrity bug: a hop acting on instructions the
   sender never wrote, or two different packets verifying against the same MAC.
2. `payload.go` and `varint.go`: `DecodeHopPayload`, `HopData.Decode`,
   `decodeLegacyHopData`, `tlvPayloadSize`, `ReadVarInt`, `WriteVarInt`. Length
   prefixes and the legacy/TLV discrimination are read straight from decrypted
   attacker input. Off-by-one and truncation behaviour live here.
3. `crypto.go`: `calcMac`, `generateKey`, `generateCipherStream`,
   `computeBlindingFactor`, `blindGroupElement`, `sharedSecret`,
   `Router.generateSharedSecret` and `PrivKeyECDH.ECDH`. The composition is
   load-bearing: the MAC key, the stream key and the blinding factor must all be
   separated domains over the same shared secret, and the shared secret must be
   derived from a point that is actually on the curve.
4. `path.go`: `BuildBlindedPath`, `HopInfo.Encrypt`, `NextEphemeral`,
   `NextEphemeralPriv`. Route blinding is the newest surface and the one with the
   most composition: an AEAD-encrypted hop payload, a blinded node ID derived by
   HMAC, and a chain of ephemeral keys.
5. `replaylog.go`, `batch.go`, `replay_set.go`: `hashSharedSecret`, `Put`,
   `PutBatch`, `Batch.Put`, `ReplaySet`. Replay protection is what stops a
   captured packet from being accepted twice. The batch path also has to be
   idempotent, because the caller retries it.
6. `obfuscation.go` and `OnionErrorEncrypter`/`DecryptError` in `crypto.go`: the
   backwards failure path. A wrong answer here either leaks route position or
   makes a legitimate failure unattributable.
7. The construction side: `NewOnionPacket`, `generateHeaderPadding` and
   `rightShift` in `sphinx.go`. lnd is a sender for every payment it originates,
   so a fault here is not merely a receiver problem. It is also the part that
   decides how much padding a packet carries.

## Out of scope or low priority

- `hornet.go` contains unused draft types for a HORNET-style header. Nothing
  references them and no code path runs. Not part of the protocol this package
  implements.
- `cmd/main.go` and `cmd/example-data/`: the `sphinx-cli` developer utility and
  its sample JSON. The tool is handy for driving a packet by hand, but a fault in
  its argument parsing is not a library vulnerability.
- `testdata/`: BOLT 4 and route-blinding test vectors used by the test suite.
  These are inputs to tests, not code. Do not report the fixed keys, fixed
  session keys or absent randomness in these files; they are vectors.
- `tools/`: a separate Go module that builds the dockerised linters. Not part of
  the library, and not needed to build or test it.
- `bench_test.go` and the benchmark helpers: counters and allocation numbers, no
  security-relevant behaviour.
- The unexported test scaffolding in `sphinx_test.go`, `path_test.go`,
  `obfuscation_test.go` and `replaylog_test.go`.
- Anything that requires the caller to construct an already-inconsistent struct
  by hand rather than feeding bytes into a public entry point. The package takes
  pointers and slices; a caller that passes a nil `EphemeralKey` or a
  `RoutingInfo` shorter than an HMAC has broken a contract the code documents.

## How to exercise it

The image is built by the Dockerfile that sits next to this file, on
`golang:1.24.6-bookworm`, with the checkout at `/src` and `WORKDIR /src`. During
the build it runs `go mod download` and `go mod verify`, builds everything with
`go build -gcflags='all=-N -l' ./...`, compiles the test binaries with
`go test -count=1 -run '^$' ./...`, and then runs the full suite once. After that
the scan runs offline with `GOPROXY=off`. There are no build tags to set: this is
a pure-Go library with no cgo and no generated code.

The commands, all of which are what the repository's own Makefile runs:

- `go test ./...` runs everything in the single root module.
- `make unit` is `go test -v ./...`.
- `make unit-race` is
  `env CGO_ENABLED=1 GORACE="history_size=7 halt_on_errors=1" go test -race ./...`.
- `make unit-cover` writes `coverage.txt`.
- `make build` is `go build github.com/lightningnetwork/lightning-onion/...`.
- `make sphinx-cli` builds `./cmd/main.go` into `sphinx-cli`, which has
  `genkeys`, `nextephemeral`, `generate` and `peel` subcommands driven by JSON
  files under `cmd/example-data/`.

Everything you need to reach the parser is in-process. There is no network, no
second node and no daemon involved, so a reproducer for anything in this package
is fully demonstrable inside the image. A worked shape:

- Derive a router from a private key you generate, wrapped in `PrivKeyECDH`.
- Give it a `NewMemoryReplayLog()` after calling `Start`, or
  `NewNoOpReplayLog()` when you do not want replay rejection in the way.
- Build a legitimate packet with `NewOnionPacket` over a `PaymentPath` holding
  your `OnionHop` entries, a `sessionKey`, the associated data, and
  `BlankPacketFiller` so the bytes are deterministic.
- Mutate the packet or its bytes and feed them back through
  `Router.ProcessOnionPacket`, or through `Encode`/`Decode` first if you want the
  serialization path in the loop.

To produce the decrypted-then-parsed state directly, note that `unwrapPacket` and
`processOnionPacket` are unexported but reachable from a test in package `sphinx`.
A test in the package can therefore construct a packet whose plaintext hop
payload has a chosen varint length or a chosen first byte, without needing to
encrypt anything by hand. `TestUnwrapPacketBeyondRoutingInfoBoundary` in
`sphinx_test.go` is a worked example of exactly that technique.

There is no fuzz target in the tree. A new one, over `OnionPacket.Decode` or over
`ProcessOnionPacket`, is the cheapest way to turn a suspicion into a
reproducer:

```
go test -run '^$' -fuzz '^FuzzName$' -fuzztime=60s .
```

## How we rate severity

Critical:

- Any path where `ProcessOnionPacket` returns forwarding instructions derived
  from data the header MAC did not authenticate, or where a packet is accepted
  without a MAC that checks out over the routing info together with the
  associated data. The HMAC is the only thing standing between an arbitrary peer
  and an arbitrary instruction set for the next hop.
- Any confusion between hop layers: a packet whose next-hop payload, MAC or
  ephemeral key is taken from the wrong hop, so that the same onion yields
  different instructions at two positions, or one hop can act on another hop's
  instructions.
- Any defect that lets a third party forge or transplant a valid
  `(routing info, associated data, MAC)` triple without the shared secret.

High:

- A panic, index-out-of-range or nil dereference reachable from bytes a remote
  peer can put on the wire at the sizes the protocol permits: an onion of up to
  1300 bytes, an onion message of up to 32768 bytes, an error blob of the
  minimum length the failure path accepts. This is unauthenticated and cheap to
  repeat against a node whose caller does not recover panics, so it is not a
  medium.
- Work or allocation that scales with a value read out of the packet rather than
  with the bytes actually present. High when the amplification is large,
  medium when it is bounded by the input size.

Medium:

- Privacy and indistinguishability breaks: behaviour that tells an intermediate
  node its position in the route, how many hops remain, or whether a packet was
  meant for it, beyond what the protocol already implies. Rate high when a single
  probe on a single packet is enough, medium when it needs many observations.
  State the observation the attacker makes; "timing may vary" on its own is not
  a finding.
- A corrupted packet that makes the local replay log record a state that blocks a
  legitimate packet later, where the attacker gains only a denial of service
  against a caller that shares the log.

Low:

- Missing validation with no demonstrated path to any of the above. Input that
  produces a clean error is the intended outcome, so an error that is merely
  unhelpful is low at most.
- A panic that needs the caller to hand in a struct the package documents as the
  caller's responsibility, or an out-of-range sequence number on the batch path.
- Error strings or log lines that are imprecise.

Out of scope for a rating, though still worth a sentence in a report that
contains something else:

- DoS that requires the caller to feed an unbounded `io.Reader` into
  `OnionPacket.Decode`. That decoder reads to EOF by design; bounding the read is
  the framing layer's job.
- Anything reachable only with the node's private key, or only by a caller that
  has already decided to use `NoOpReplayLog` where replay protection was wanted.
- Behaviour that differs between the legacy and TLV payload formats when the
  caller passed `WithTLVPayloadOnly` to select one.

## Report and patch preferences

A minimal Go test in package `sphinx` is the best form, and it can live in
`sphinx_test.go` alongside the existing ones. It should:

- name the function and the line where the fault is,
- show the exact bytes or the exact construction that reaches it,
- state the observable before and after: accepted where it should be rejected,
  a panic instead of an error, a wrong payload returned, a timing or size
  difference an observer can measure,
- and for anything claimed to be a protocol break, state which property from
  BOLT 4 or the Sphinx paper is violated, in the terms the protocol uses.

A merge-ready patch is welcome and preferred when the fix is local: a bounds
check and a returned error in the decoder at fault, not a restructuring of the
package. Keep changes to exported signatures out of the patch. lnd pins this
module by version and a breaking change costs a coordinated release for a library
with a small surface. Do not fix a parser bug by making the error say more: see
the next section.

If you can only show the fault by reasoning about the code, say so plainly and
mark the report as unverified rather than constructing a reproducer that passes
for an unrelated reason. An honest "I could not make this reachable" is more
useful to us than a test that would need rewriting.

## Anything to leave alone

These are the shapes that look wrong and are not.

- `hmac.Equal` in `unwrapPacket` is the deliberate constant-time comparison, and
  it happens before anything derived from the packet is parsed. Reporting it as a
  timing side channel is a false positive.
- The MAC comparison failing returns `ErrInvalidOnionHMAC` and nothing else. The
  function does not tell the caller which of the checks failed and the protocol
  does not want it to. Flagging "the errors are not more descriptive" or "the
  failure paths differ in log wording" is not a finding on its own; a real
  finding would show that two distinguishable outcomes leak route position to an
  attacker, with the observation spelled out.
- The all-zero nonces. `generateCipherStream` builds a chacha20 cipher with a
  zero nonce, and `chacha20polyEncrypt`/`chacha20polyDecrypt` use
  `chaChaPolyZeroNonce`. That is the construction: a fresh key is derived per hop
  per layer from the shared secret, and a key is used for one stream. A fixed
  nonce under a reused key would be a finding; a fixed nonce under a per-layer
  key is the design.
- `generateCipherStream` panics if `chacha20.NewCipher` returns an error. The key
  is always `keyLen` bytes and the nonce is 8 bytes, so that branch is not
  reachable through the public API. Only report it if you can show a path with a
  different key length.
- `onionEncrypt` being its own inverse is what makes the error obfuscation work in
  both directions. It is documented and it is the point.
- `zeroHMAC` and the `bytes.Equal(zeroHMAC[:], outerHopPayload.HMAC[:])` test for
  the exit hop is the protocol's own marker for "this is the last hop". It is an
  equality test on a value the sender sets to zero, not an authentication check
  that was forgotten.
- `isLegacyPayloadByte` treats a leading `0x00` as a legacy payload, which is
  ambiguous with an empty TLV stream, because an empty TLV stream does not occur
  for a routable hop. `WithTLVPayloadOnly` exists to remove the ambiguity for
  onion messages. This is specified, not accidental.
- `BlankPacketFiller` writes nothing, leaving the unused part of the mix header
  zeroed. It is documented as being for test vectors only, and
  `NewOnionPacket` refuses a nil filler precisely so this cannot happen by
  accident. Do not report "the packet padding is not random" for a test using
  this filler. `DeterministicPacketFiller` deriving its padding from the session
  key is likewise deliberate.
- `NewMemoryReplayLog` and `NoOpReplayLog` are documented as being for testing and
  for callers that handle replay elsewhere. "A packet was accepted twice using
  `NoOpReplayLog`" is the documented behaviour of that choice.
- `BeginTxn` allocates `nels` slots and its comment states that using a sequence
  number at or above that value can panic. That is a stated caller contract.
- `Router.ReconstructOnionPacket` explicitly does no replay protection because its
  documented purpose is to re-derive a packet that was already accepted.
- The stream length is `numStreamBytes`, which asks for twice the routing info
  length so the last hop's filler can be decrypted. The doubled allocation is
  intended.
- `Circuit` and `OnionErrorEncrypter` encode and decode state that the *sending*
  side holds locally to deobfuscate a failure later. That reader is not fed by a
  remote peer, so treat length handling there as a robustness question at most,
  not as an attack surface.
- There is no `unsafe` in this package and no assembler. Any report that depends
  on either has misread the tree.
- The `testdata` JSON files contain fixed private keys and fixed session keys.
  They are published test vectors.

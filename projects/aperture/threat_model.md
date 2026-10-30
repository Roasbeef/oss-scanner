# Threat model: aperture

## What this project does and where untrusted input enters

Aperture is an internet-facing reverse proxy that gates access to backend HTTP and gRPC services with the L402 protocol, which is built from an HTTP 402 challenge, a macaroon, and a Lightning payment preimage. A client asks for a protected resource, is handed a challenge containing a freshly minted macaroon and a BOLT 11 invoice, pays the invoice, and returns the macaroon together with the preimage. Aperture verifies the macaroon's signature and its caveats, checks with the Lightning backend that the invoice is settled, and only then forwards the request to the configured upstream. The same proxy also speaks the Payment HTTP Authentication Scheme, which is a second payment protocol with a one-shot charge intent and a prepaid session intent.

This is the most directly remote-reachable code in our set. There is no trusted peer, no staking requirement, and no allowlist between the public internet and the request handler. Every byte of every request line, header field and body comes from an anonymous attacker, including:

- The request target and every header field. `proxy/proxy.go` reads them for routing, authentication, pricing, rate limiting and forwarding. The credential parsers in `l402/header.go` and `mpp/header.go` accept several header spellings for the same secret, and both parsers see attacker-chosen bytes.
- The macaroon itself: its identifier, its caveat list and its signature, all supplied base64 or hex encoded in a header. `mint/mint.go` and `l402/caveat.go` verify signature and then evaluate caveats through the satisfiers in `l402/satisfier.go`.
- The Payment challenge echo. A client pays by repeating the challenge back in a credential, and `auth/mpp_authenticator.go` re-derives the challenge HMAC over exactly the echoed fields to decide whether this deployment minted it.
- The request body, which is buffered and serialized for the price server by `pricer/grpcPricer.go` and forwarded upstream unchanged.
- The mailbox stream. `hashmail_server.go` implements the HashMail gRPC service, which is a relay that any client can open a stream against, and the LNC code in `lnc/lnc.go` connects out to such a server.
- The admin surface, when enabled: `admin/server.go` and the generated `adminrpc/admin.proto` service, plus the REST gateway and dashboard in front of it.

Naming, because it trips people up when reading issues and release notes: the daemon binary is `aperture`, built from `cmd/aperture/main.go` into the root package's `Main`. The command line client is `aperturecli`, built from `cmd/aperturecli/main.go`. There is no separate binary called `apertured` in this tree, and nothing in it refers to one; if a report or a piece of documentation uses that name it is describing a past layout. The root package is `github.com/lightninglabs/aperture` and lives in the files directly under the repository root, such as `aperture.go`, `config.go`, `services.go` and `hashmail_server.go`.

Two supporting processes share the repository. `cmd/aperture/main.go` builds the proxy daemon that serves traffic. `cmd/aperturecli/main.go` builds an operator command line client that talks to the daemon's admin gRPC API. `cmd/meterd/main.go` builds a reference price server that the proxy calls over `pricesrpc/prices.proto`. Only the daemon listens on a public address; the CLI and the price server are operator-side and are reached over a loopback or a private network. Treat a request arriving at the daemon's listener as hostile regardless of which component it claims to come from.

The properties we care about most, in plain terms: a macaroon's caveats must be enforced before a byte reaches an upstream; the challenge, receipt and session bookkeeping must not be replayable or confusable between users; the path Aperture authorised must be the path the upstream actually serves; and the work and memory a single unauthenticated request can cause must be bounded.

Two deployment shapes decide where the trust boundary sits, and a report should say which one it assumes. In the first, Aperture terminates TLS itself on `listenaddr`, using either a Let's Encrypt certificate obtained through `autocert` or a self-signed pair it generates under its base directory; everything the client sends after the handshake is attacker-controlled and Aperture is the only thing deciding who gets through. In the second, Aperture runs with `--insecure` behind a TLS-terminating load balancer, so the client address it sees may be a proxy's and the certificate is someone else's. The code reads the peer address from `r.RemoteAddr` for the freebie counter and for the unauthenticated rate limit key, and it never trusts a forwarding header for that address; keep that in mind before claiming a client can choose its own bucket. Whichever shape a deployment uses, the backend side is a separate trust boundary: the upstream is reached over HTTP or HTTPS with an optional pinned certificate per service, and the upstream's own response headers come back through the proxy to the client.

## Components that matter most

In order of damage if wrong.

1. `proxy/proxy.go`. The whole request lifecycle lives here: path canonicalisation, service matching, the authentication decision, the rate limit, the metered check, and the hand-off to `httputil.ReverseProxy` through the `director`. A fault at any of those points is an authentication bypass or a smuggling bug. Read `ServeHTTP`, `canonicalizeRequestPath`, `matchService`, `acceptForService`, `removeUnverifiedL402`, `publicResourceName` and `director` as one flow, because they are one flow.
2. `l402/header.go`, `l402/caveat.go` and `l402/satisfier.go`. The credential parser decides which header field is authoritative, rejects duplicates, and extracts the macaroon and preimage. `VerifyCaveats` in `l402/caveat.go` then walks every caveat against the satisfiers, which are the code that actually confines a token to a service, a capability set and an expiry. Anything that lets a caveat be skipped, satisfied by the wrong value, or read from the wrong part of the macaroon is a critical finding.
3. `mint/mint.go`. Minting and verification of the L402 itself: the root secret lookup, the signature check, the caveat set attached at mint time, and the price and expiry records written alongside. A fault here either mints something weaker than intended or accepts something we did not mint.
4. `auth/mpp_authenticator.go`, `auth/mpp_session_authenticator.go`, `auth/multi_authenticator.go`. The Payment scheme. `mpp/challenge.go` computes and verifies the challenge HMAC over fixed positional slots, `mpp/header.go` parses the credential and challenge header lists by the HTTP list grammar, and the two authenticators decide whether a charge is being presented for the first time and whether a session has the balance to pay for a request. The value-conservation property lives here: one settled invoice must buy one charge, one deposit must fund one session, and a top-up must credit exactly once.
5. `proxy/metering.go` and `pricer/grpcPricer.go`. Prepaid usage: reserving an estimate before the upstream call, observing the upstream response, and reporting actual usage afterwards. A fault lets a buyer draw more usage than the balance paid for, or leaks a reservation and shrinks a balance for nothing.
6. `aperturedb/interface.go`, `aperturedb/l402_transactions.go`, `aperturedb/mpp_sessions.go` and `aperturedb/secrets.go`. The durable state that makes replay detectable: consumed charges, sessions and their deposits, transaction records, and the macaroon root secrets. Every claim that a credential has not been spent before rests on these stores, and the atomicity of each claim rests on the SQL behind them.
7. `proxy/service.go` and `proxy/ratelimiter.go`. Service configuration parsing (`prepareServices`, `ValidateServiceName`, `prepareRewrite`) and the per-service limiter with its LRU cache. Service definitions may come from a config file or from the admin API, so a validation gap is a way to configure a service that behaves differently than its name and price suggest.
8. `admin/server.go` and `admin/auth.go`. The administrative API that creates, updates and deletes services and revokes tokens. It is macaroon-gated, and it is the only surface where a request can change routing for everyone else.
9. `aperture.go` and `config.go`. Process wiring: TLS setup, listener selection, the split between priority local services, fallback local services and proxied services, and which subsystems start at all. A default here decides whether a deployment is authenticated at all.
10. `challenger/lnd.go` and `challenger/wavelength.go`, behind the interfaces in `challenger/interface.go`. Creating an invoice for a challenge and confirming that an invoice reached the settled state are both done through a Lightning backend, and `VerifyInvoiceStatus` is what the L402 authenticator consults before it believes a preimage. A fault that accepts a preimage for an invoice the backend has not reported settled is an authentication bypass even though the macaroon signature is fine.
11. `hashmail_server.go` and `lnc/lnc.go`. The mailbox relay and the LNC client. Both handle attacker-supplied stream identifiers and framed messages, and both are reachable from a public listener when enabled.

## Out of scope or low priority

- Generated code: `adminrpc/admin.pb.go`, `adminrpc/admin.pb.gw.go`, `adminrpc/admin_grpc.pb.go` and the same three files under `pricesrpc/`. These are protoc output. A problem in the generated marshalling belongs upstream in the protobuf runtime, not here. The `.proto` files next to them are the readable statement of the surface, and a finding is better expressed against the handler that fills the message in.
- `aperturedb/sqlc/`: `aperturedb/sqlc/db.go`, `aperturedb/sqlc/models.go`, `aperturedb/sqlc/querier.go` and the per-table `*.sql.go` files, all marked "Code generated by sqlc. DO NOT EDIT." The queries they implement live in `aperturedb/sqlc/queries/` and the schema in `aperturedb/sqlc/migrations/`; those two are worth reading to understand what a store call actually does, but a defect is reported against the hand-written wrapper that calls them.
- `dashboard/`, the Next.js web console. It is a separate JavaScript application with its own dependency tree, and its build is not part of the Go image. Report a dashboard problem only if it demonstrates a flaw in the Go code it calls, such as the CSRF or CORS handling in `aperture.go`, and not a defect in a frontend library.
- `static/index.html`, the demo landing page served by the static file server.
- `docs/`, `README.md` and `skills/aperture/`. Documentation, not behaviour. That includes `docs/metering.md`, which is however the best short description of the prepaid flow if you need orientation before reading `proxy/metering.go`.
- `tools/`, a separate Go module that builds the linting and SQL code generation tooling. `scripts/gen_sqlc_docker.sh` regenerates the SQL layer and is not part of the runtime.
- `cli/`, `cmd/aperturecli/` and `cmd/meterd/`. Operator tooling. A bug in argument parsing or output formatting is not a proxy vulnerability. `cmd/meterd/` is a reference price server whose documented purpose is development use; treat `meterd/` as a real parser only if you can reach it as deployed.
- `internal/test/` and the `*_test.go` files throughout. Test scaffolding, including the Lightning client mock in `internal/test/lightning_client_mock.go`.
- `mpp/mppvectors/vectors.go` and `mpp/testdata/`. Fixed protocol vectors used by the conformance suites. Fixed keys and fixed nonces in vectors are expected.
- `proxy/testdata/hello.proto` and the stubs generated from it: a trivial Greeter used to exercise the gRPC proxying path in tests.
- Anything that requires the caller to hand in an already-inconsistent struct rather than send bytes. A caller that constructs a `proxy.Service` with a compiled regexp field unset, or invokes `proxy.UpdateServices` with a service whose name contains a slash, has broken a documented contract; the code validates its inputs in `prepareServices` for exactly this reason.

## How to exercise it

The scanner builds this project from the Dockerfile enrolled for it, on the Go toolchain the module pins, with the checkout at `/src`. It fetches modules while the network is up, builds everything with `-gcflags='all=-N -l'` so panic traces match the source, and lets the audit run with `GOPROXY=off`. There is no etcd, no postgres server and no Lightning node in the image, and no network.

Most of the surface needs none of that. A large fraction of the interesting paths are plain HTTP against an in-process upstream, which is why strong reproducers here are unusually cheap:

- `go test -tags=dev ./proxy/` runs the proxy suite. The `dev` tag is what the repository's own `make/testing_flags.mk` sets as `DEV_TAGS`, and `make unit` passes it. Several suites build a real `httptest.NewServer` upstream and drive requests at a configured `proxy.Proxy`, for example `proxy/path_test.go`, `proxy/public_auth_test.go` and `proxy/proxy_mpp_test.go`. Copying one of those tests is the fastest route to a reproducer for anything about routing, authentication or forwarding.
- `proxy/proxy_test.go` additionally starts a real gRPC backend and a TLS listener, and covers the gRPC-over-HTTP/2 path end to end.
- `go test -tags=dev ./l402/` covers credential parsing and caveat satisfaction, including `l402/satisfier_test.go`. `go test -tags=dev ./mpp/` covers header grammar, the challenge HMAC and the JSON canonicalisation, including `mpp/header_conformance_test.go` and `mpp/jcs_conformance_test.go`. Both are table-driven and take constructed strings, so they need no proxy and no node.
- `go test -tags=dev ./aperturedb/` runs against SQLite. `aperturedb/test_sqlite.go` provides `NewTestDB`, which builds a real SQLite database in `t.TempDir()` with the migrations applied. That is enough to test charge consumption, session crediting and secret storage without any external service. A Postgres variant exists behind the `test_db_postgres` build tag and needs Docker, so it will not run in the image; do not depend on it.
- `proxy/proxy_mpp_test.go` and `auth/mpp_authenticator_test.go` drive the Payment scheme end to end, including a settled-invoice double and an in-process SQLite charge store. `auth/mpp_session_authenticator_test.go` does the same for sessions, top-ups and closes. Those two suites are the reference for any claim about replay or value conservation, and `auth/mpp_service_binding_test.go` shows the property-driven style for a binding that must hold for arbitrary input.
- `make unit` is the full suite as the project runs it: `go list -tags=dev -deps ./...` piped through `xargs` into `go test -tags=dev -test.timeout=20m`. `make unit-race` adds `-race`. `make build` installs `cmd/aperture` and `cmd/aperturecli`.
- Directly: `go test -tags=dev -run 'TestName' ./proxy/` for one case, which is the loop you will want while iterating.

What needs more than the image provides, and what that means:

- A reproducer that needs a live Lightning node to mint and settle invoices cannot be demonstrated here. Mocks for the Lightning side exist at `internal/test/lightning_client_mock.go`, and the authenticator takes an `auth.InvoiceChecker` interface, so a test double that reports an invoice settled is usually enough to reach the code in question. Prefer that to claiming the finding is untestable.
- A reproducer that needs the MPP session or charge store needs a SQL backend, which SQLite supplies in-process. Use it.
- The mailbox relay in `hashmail_server.go` can be driven in-process over a `bufconn` or a loopback gRPC listener; nothing about it requires the public internet.

The mailbox relay deserves its own note on reachability. `hashmail_server.go` implements a service whose clients are anonymous by design: opening a stream needs only a 64-byte identifier, and the relay is expected to hand a stream to whoever presents the matching identifier. A test can start the server behind a `bufconn` and speak the generated client from the `hashmailrpc` package (a dependency module, not a file in this tree), so a claim about stream takeover, message injection between the two halves of a stream, or unbounded buffering is demonstrable without any external party.

A finding that you can only reach with a real second party, a live node or privileged networking is still in scope. Say plainly in the report that the image cannot demonstrate it and why, and show the in-process path as far as it goes. That is a weaker report than a test that fails, and we will treat it as such, but it is far better than a reproducer that passes for an unrelated reason.

## How we rate severity

Critical:

- Any way for a request to reach a configured upstream without the authentication the service configuration requires, or with a credential that was not verified: a caveat escape, a token accepted for a service it does not name, a signature check skipped, a Payment credential that re-establishes someone else's session.
- Any confusion of identity between users or tokens: one caller's preimage, session, receipt or rate-limit bucket being attributed to another, or a token spending a balance it did not pay for. This is a value-conservation break reachable from the network, and it is critical whether the loss is the operator's revenue or another buyer's deposit.
- Any way to make the upstream receive a request other than the one Aperture authorised: a path that routes to a different backend than the one matched, a rewrite that escapes the configured prefix, a request smuggled past the auth decision into the proxied handler, or a host/path combination that satisfies the matcher but not the upstream.
- Memory corruption or arbitrary code execution reachable from request bytes. We do not expect any in this codebase, and a report claiming one needs a demonstrated path, not a suspicion.
- Disclosure of the macaroon root secrets or the challenge HMAC secret to a remote caller.

High:

- A remotely triggerable denial of service that needs no credential and is cheap to repeat: an unbounded allocation driven by a header or body length, a goroutine or connection leak per request, a panic in the request path that a single request triggers.
- Replay of a settled payment or a completed challenge that yields more service than was paid for, where the amount is bounded and small rather than a full balance.
- An admin-API authorisation gap that needs only a valid admin macaroon the attacker already holds. High rather than critical because holding that macaroon is already a privileged position.

Medium:

- A DoS that requires an authenticated or staked counterparty, or that needs a large volume of traffic to matter. An authenticated attacker spending real money to degrade the service is a different problem from an anonymous one doing it for free.
- A panic that a single request triggers where the process recovers, or where the affected handler is one of several and the rest keep serving.
- A resource limit that is present but ineffective in a configuration the project documents, such as a cache that is bounded per service but unbounded in the number of services.
- A proxy-side information leak that reveals the existence of a service, a price, or the deployment's backend addresses, where no credential or session crosses.

Low:

- Missing validation with no demonstrated impact beyond a wrong error code or an unhelpful message. An input that produces a clean rejection is the intended outcome.
- A configuration value that is accepted where it should be rejected, when the resulting behaviour requires the operator to have set it deliberately.
- Log lines that include a value a careful reader would redact, where the value is not a secret and the log is not remotely readable.

Out of scope for a rating, even when worth a sentence:

- That Aperture trusts the TLS configuration it was given, or that the operator may run it with `--insecure` behind a load balancer. That is a deployment choice with a documented flag, not a bug.
- That a service has no rate limit configured, or that the default limit is generous. Rate limiting is per service and opt-in by configuration; "no limit set" is not a finding, though a limit that can be bypassed when it *is* set is.
- Behaviour that only differs when the operator sets an authentication level of `off`, or a whitelist pattern that matches everything. The configuration says what it wants.
- A dependency advisory with no demonstrated path through Aperture's own code.

Two readers should agree on all of the above. If a candidate finding sits between two levels, the deciding question is: does it cross a trust boundary an anonymous caller can reach, and does it cost money, credentials or data? Both yes is critical. One yes is high. Neither, but the process or the deployment suffers, is medium.

## Report and patch preferences

What helps most, in order:

- A Go test that fails. A test in the package that owns the fault, in the style of the existing ones: a `httptest` upstream, a `proxy.Proxy` built with `proxy.New`, and a request that shows the before and after. State the configuration the test sets up, because almost every property here is conditional on auth level and auth scheme.
- The exact entry point and the exact decision that went the wrong way. "`acceptForService` returned true for a header that `l402.FromHeader` rejects" is a good claim. "The proxy may be bypassable" is not.
- The observable difference spelled out: a status code, a forwarded header, a balance in the store, a log line, a number of allocations.
- For anything about value conservation, the arithmetic. What was paid, what was delivered, and where the two diverge.

A merge-ready patch is welcome when it is local: a check and a returned error where the decision is made. Please do not restructure the request path in a patch, and do not change exported signatures of `proxy`, `auth` or `l402`; downstream deployments embed these packages. If the fix needs a schema change in `aperturedb/`, describe it rather than generating migrations.

When the fault needs a second party, express it as an interface double rather than a live node: the authenticator, pricer and challenger seams are small interfaces with mocks already in the tree. A report that names the interface it stubbed is easier to reproduce than one that names the node it could not run.

## Anything to leave alone

The shapes that look wrong and are not, most of which we have been asked about before:

- `removeUnverifiedL402` and `removeHeaderValues` in `proxy/proxy.go` delete header fields on purpose. A client is allowed to send several credential spellings at once, and Aperture removes the ones nothing verified before the rate limiter, the metering check and the upstream see them. Reporting "the proxy strips a header the client sent" is reporting the mitigation.
- The deliberate deletion of `Grpc-Metadata-Authorization` before forwarding is the same class: the alias is not an authentication channel here, so it is always removed when auth is enabled.
- `hmac.Equal` in `mpp/challenge.go`, and the HMAC comparison inside `gopkg.in/macaroon.v2` that `macaroon.Macaroon.VerifySignature` relies on, are constant-time on purpose. A timing report over either needs a measurement, not a citation of the pattern.
- The challenge HMAC is over a pipe-joined string of fixed positional slots. Joining fields with a delimiter and then hashing looks like a canonicalisation bug and is not, provided every slot is either fixed-width or validated; check that before reporting, and report only if you can show two distinct challenges colliding.
- `mpp/jcs.go` round-trips values through `encoding/json` on the way to a canonical form, which loses integer precision above 2^53. The function's own doc comment states this as inherent to the RFC 8785 canonicalisation the protocol requires, and it is the only rendering a JavaScript peer can agree with. It is not a rounding bug in the pricing arithmetic.
- `mpp/problem.go` returning a fixed problem document for a 402 is the spec's shape. The body carries no attacker-chosen text, and a report that it should echo the request is a feature request.
- The `jcs` canonicaliser refusing to encode NaN and the infinities is a deliberate rejection of values with no JSON representation. A path that reaches that refusal through a price or an amount is worth checking for the amount's own sake, but the refusal itself is not the bug.
- `proxy.Service.AuthWhitelistPaths` and the `authwhitelistpaths` configuration are a documented way to let anonymous requests into a service. A path matching one of those patterns reaches the upstream without a credential. Reporting that a whitelisted path is reachable anonymously is reporting the configuration; the finding would be a path that matches a whitelist pattern it was not written to match.
- `auth.AuthSchemeL402MPP` allows both schemes on one service. A request carrying a Payment credential does not get L402 treatment, and `acceptForService` says so in its return values. Reading "a Payment request was refused L402-only logic" as a bug misreads the composition.
- The `defaultServicePrice` and `maxServicePrice` bounds in `proxy/service.go` are input validation on operator-supplied prices, not a security boundary. A report that a price above the maximum is rejected is reporting the check.
- `pricer/defaultPricer.go` returning a static price with no backend is the intended default. A report that it does not consult anything is describing the choice.
- `freebie.Count` being a `uint16` bounds the free-request counter by type. A report about wraparound there needs to show the counter reaching its maximum and what happens next, not merely that the type is small.
- Rejecting a credential whose challenge carries no expiry, in `auth/mpp_authenticator.go`, is a deliberate refusal of a shape this code does not mint.
- Credits, sessions and charges are all keyed by payment hash and claimed in a single atomic step. A re-presentation that returns "already applied" and is allowed to proceed is the intended idempotency for a client that lost a response. Only report it if you can show two distinct sessions or users being served from one payment.
- Errors are returned without detail on purpose in the credential paths: `FromHeader` says only that something failed. Do not report the absence of a diagnostic as a finding; report a case where two distinguishable outcomes leak something an attacker can observe.
- Duplicate `Authorization` values, an `LSAT` and an `L402` spelling of the same credential, and multiple macaroon headers are all explicitly rejected rather than resolved. That is stricter than lenient, and it is intentional.
- The `aperture.go` comments describing a gRPC header alias and the upstream-credential replacement in `director` state design decisions. They are not admissions.
- The static file server is a catch-all fallback for unmatched paths, and it returns 404 for anything absent. Serving `static/index.html` and the demo page is intended.
- `dashboard/out` is embedded only under the `dashboard` build tag, and `dashboard_stub.go` returns nil without it. A build that has no dashboard is a build without that tag, not a broken image.
- The test-only `--insecure` gRPC credentials Aperture uses to talk to its own REST gateway on loopback are deliberate, and documented at the call site.
- `freebie.NewMemIPMaskStore` and the masked-IP rate limit keys in `netutil/ip.go` group clients by subnet. A report that several addresses share a bucket is the design; `/24` and `/48` are the documented choices.
- Deliberate `unsafe` appears nowhere in hand-written code. If you find it, it is in generated protobuf output, which is where it belongs.
- The build flags in the image are `-gcflags='all=-N -l'`, which disables inlining and optimisation so stack traces line up. Do not report the reduced optimisation or the larger binary.
- Panics that only a caller can trigger by misusing `proxy.NewLocalService` or by mutating a `proxy.Service` after it has been prepared. `UpdateServices` takes the write lock precisely to make that safe for in-flight requests.

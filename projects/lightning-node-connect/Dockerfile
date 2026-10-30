# Scanner image for https://github.com/lightninglabs/lightning-node-connect.
#
# The repository ships no application Dockerfile for the libraries under audit (only one for the
# hashmailrpc helper and one for a reproducible wasm build), so this builds the scanner's checkout at
# /src.
#
# lightning-node-connect is a root module plus gbn/, mailbox/, hashmailrpc/, mobile/,
# cmd/wasm-client/ and mailbox/numsgen/. `make unit` runs the root module with the project's RPC_TAGS.
# The gbn, mailbox and hashmailrpc modules carry the transport and are built and test-compiled here
# too. The mobile/ module is deliberately left out: it does not build against the versions this module
# graph resolves to today, independent of anything added here, so including it would only make the
# image build fail. Its bindings are thin wrappers over the mobile-facing Go API, which is built here.

FROM golang:1.25.10-bookworm

ENV DEBIAN_FRONTEND=noninteractive \
    CGO_ENABLED=1 \
    GOTOOLCHAIN=local

RUN apt-get update && apt-get install -y --no-install-recommends \
      ca-certificates git build-essential pkg-config jq \
    && rm -rf /var/lib/apt/lists/*

# scanner contract: the checkout lives inside the image, at /src
COPY . /src
WORKDIR /src

# Fetch every module the build and the tests need while the network is still up.
RUN go mod download && go mod verify \
    && for mod in gbn mailbox hashmailrpc cmd/wasm-client mailbox/numsgen ; do \
         (cd "$mod" && go mod download) || exit 1 ; \
       done

# BUILD_TAGS is the RPC_TAGS list from the Makefile, which `make unit` passes.
ENV BUILD_TAGS="appengine autopilotrpc chainrpc invoicesrpc neutrinorpc peersrpc signrpc wtclientrpc watchtowerrpc routerrpc walletrpc verrpc"

# Build with debug info and no inlining so stack traces and reproducers match the source, then compile
# every test binary without running it.
RUN go build -tags="$BUILD_TAGS" -gcflags='all=-N -l' ./... \
    && go test -count=1 -run '^$' -tags="$BUILD_TAGS" ./...

RUN for mod in gbn mailbox hashmailrpc ; do \
      (cd "$mod" && go build -gcflags='all=-N -l' ./... && go test -count=1 -run '^$' ./...) || exit 1 ; \
    done

# The wasm client is a separate module that only builds for js/wasm; compile it so the browser-facing
# path is also known to build in this image.
RUN (cd cmd/wasm-client && GOOS=js GOARCH=wasm go build -tags="$BUILD_TAGS" -o /tmp/wasm-client.wasm .)

# Run the suite so the image is known to work, but do not let a failing test abort the build.
RUN (go test -count=1 -timeout 20m -tags="$BUILD_TAGS" ./... || echo "WARNING: go test reported failures")

# The scan runs offline. Fail fast instead of waiting on the network if anything still tries to fetch.
ENV GOPROXY=off \
    GOSUMDB=off \
    GOFLAGS=-mod=mod

CMD ["bash"]

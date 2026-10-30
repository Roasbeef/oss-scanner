# Scanner image for https://github.com/lightningnetwork/lightning-onion.
# lightning-onion is a pure-Go library, so this image only needs a Go toolchain matching go.mod
# (go 1.24.6). While the network is available it fetches every module the build and the tests
# need and compiles the test binaries; the audit that follows runs with no network at all.

FROM golang:1.24.6-bookworm
ENV DEBIAN_FRONTEND=noninteractive \
    GOTOOLCHAIN=local

RUN apt-get update && apt-get install -y --no-install-recommends \
      ca-certificates git build-essential \
    && rm -rf /var/lib/apt/lists/*

# scanner contract: the checkout lives inside the image, at /src
COPY . /src
WORKDIR /src

# Fetch every module the build and the tests need while the network is still up.
RUN go mod download && go mod verify

# Build everything with debug info and no inlining so stack traces and reproducers match the
# source, then compile every test binary without running it.
RUN go build -gcflags='all=-N -l' ./... \
    && go test -count=1 -run '^$' ./...

# Run the suite so the image is known to work, but do not let a failing test abort the build.
RUN (go test -count=1 -timeout 600s ./... || echo "WARNING: go test reported failures")

# The scan runs offline. Fail fast instead of waiting on the network if anything still tries to fetch.
ENV GOPROXY=off \
    GOFLAGS=-mod=mod

CMD ["bash"]

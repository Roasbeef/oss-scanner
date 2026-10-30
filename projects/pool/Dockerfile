# Scanner image for https://github.com/lightninglabs/pool.
#
# The repository's own Dockerfile builds release binaries; this file instead prepares the scanner's
# checkout at /src for an offline audit, with the test toolchain present.
#
# pool is a root module plus poolrpc/ and auctioneerrpc/. Its durable state is bbolt, which is pure
# Go, so no database headers are needed. CGO stays on for parity with the project's own builds.

FROM golang:1.23.6-bookworm

ENV DEBIAN_FRONTEND=noninteractive \
    CGO_ENABLED=1 \
    GOTOOLCHAIN=local

RUN apt-get update && apt-get install -y --no-install-recommends \
      ca-certificates git build-essential pkg-config jq procps \
    && rm -rf /var/lib/apt/lists/*

# scanner contract: the checkout lives inside the image, at /src
COPY . /src
WORKDIR /src

# Fetch every module the build and the tests need while the network is still up.
RUN go mod download && go mod verify \
    && for mod in poolrpc auctioneerrpc ; do (cd "$mod" && go mod download) || exit 1 ; done

# Build with debug info and no inlining so stack traces and reproducers match the source, then compile
# every test binary without running it.
RUN go build -gcflags='all=-N -l' ./... \
    && go test -count=1 -run '^$' ./...

RUN for mod in poolrpc auctioneerrpc ; do \
      (cd "$mod" && go build -gcflags='all=-N -l' ./... && go test -count=1 -run '^$' ./...) || exit 1 ; \
    done

# Run the suite so the image is known to work, but do not let a failing test abort the build.
RUN (go test -count=1 -timeout 20m ./... || echo "WARNING: go test reported failures")

# The scan runs offline. Fail fast instead of waiting on the network if anything still tries to fetch.
ENV GOPROXY=off \
    GOSUMDB=off \
    GOFLAGS=-mod=mod

CMD ["bash"]

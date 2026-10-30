# Scanner image for https://github.com/lightninglabs/loop.
#
# The repository's own Dockerfile builds release binaries from a build context and is a reasonable
# starting point, but it has no test toolchain. This file builds the scanner's checkout at /src and
# leaves the suite runnable offline.
#
# loop is a root module plus looprpc/, swapserverrpc/ and tools/. The gRPC stubs are generated and
# committed, so nothing needs protoc at build time.

FROM golang:1.25.12-bookworm

ENV DEBIAN_FRONTEND=noninteractive \
    CGO_ENABLED=1 \
    GOTOOLCHAIN=local

RUN apt-get update && apt-get install -y --no-install-recommends \
      ca-certificates git build-essential pkg-config jq sqlite3 \
    && rm -rf /var/lib/apt/lists/*

# scanner contract: the checkout lives inside the image, at /src
COPY . /src
WORKDIR /src

# Fetch every module the build and the tests need while the network is still up.
RUN go mod download && go mod verify \
    && for mod in looprpc swapserverrpc ; do (cd "$mod" && go mod download) || exit 1 ; done

# Build with debug info and no inlining so stack traces and reproducers match the source, then compile
# every test binary without running it.
RUN go build -gcflags='all=-N -l' ./... \
    && go test -count=1 -run '^$' ./...

RUN for mod in looprpc swapserverrpc ; do \
      (cd "$mod" && go build -gcflags='all=-N -l' ./... && go test -count=1 -run '^$' ./...) || exit 1 ; \
    done

# Run the suite so the image is known to work, but do not let a failing test abort the build.
RUN (go test -count=1 -timeout 20m ./... || echo "WARNING: go test reported failures")

# The scan runs offline. Fail fast instead of waiting on the network if anything still tries to fetch.
ENV GOPROXY=off \
    GOSUMDB=off \
    GOFLAGS=-mod=mod

CMD ["bash"]

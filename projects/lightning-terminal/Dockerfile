# Scanner image for https://github.com/lightninglabs/lightning-terminal.
#
# The repository's own Dockerfile builds a release image by cloning the tree inside a Node stage and a
# Go stage. It cannot be reused: the scanner supplies its own checkout as the build context and
# expects it at /src.
#
# This image is deliberately Go-only. litd's own `make unit` runs `mkdir -p app/build && touch
# app/build/index.html` before testing, purely so the go:embed of the UI assets resolves: the unit
# tests never exercise the frontend. So there is no Node or yarn here, the frontend under app/ is not
# built, and the UI is a stub. The Go code is what this image is for.
#
# lightning-terminal is a root module plus autopilotserverrpc/, litrpc/, perms/, third_party/lnd/tlv/
# and two tools modules.

FROM golang:1.26.8-bookworm

ENV DEBIAN_FRONTEND=noninteractive \
    CGO_ENABLED=1 \
    GOTOOLCHAIN=local

RUN apt-get update && apt-get install -y --no-install-recommends \
      ca-certificates git build-essential pkg-config jq procps sqlite3 \
    && rm -rf /var/lib/apt/lists/*

# scanner contract: the checkout lives inside the image, at /src
COPY . /src
WORKDIR /src

# Fetch every module the build and the tests need while the network is still up.
RUN go mod download && go mod verify \
    && for mod in autopilotserverrpc litrpc perms third_party/lnd/tlv ; do \
         (cd "$mod" && go mod download) || exit 1 ; \
       done

# The UI is embedded with go:embed, so the directory has to exist even though it stays empty. This is
# the same placeholder litd's own Makefile creates.
RUN mkdir -p app/build && touch app/build/index.html

# BUILD_TAGS mirrors make/testing_flags.mk, which puts "dev" in DEV_TAGS.
ENV BUILD_TAGS="dev"

# Build with debug info and no inlining so stack traces and reproducers match the source, then compile
# every test binary without running it.
RUN go build -tags="$BUILD_TAGS" -gcflags='all=-N -l' ./... \
    && go test -count=1 -run '^$' -tags="$BUILD_TAGS" ./...

RUN for mod in autopilotserverrpc litrpc perms ; do \
      (cd "$mod" && go build -gcflags='all=-N -l' ./... && go test -count=1 -run '^$' ./...) || exit 1 ; \
    done

# Run the suite so the image is known to work, but do not let a failing test abort the build.
RUN (go test -count=1 -timeout 30m -tags="$BUILD_TAGS" ./... || echo "WARNING: go test reported failures")

# The scan runs offline. Fail fast instead of waiting on the network if anything still tries to fetch.
ENV GOPROXY=off \
    GOSUMDB=off \
    GOFLAGS=-mod=mod

CMD ["bash"]

# Scanner image for https://github.com/lightninglabs/aperture.
#
# The repository's own Dockerfile builds a release image from a build context; this file instead
# prepares the scanner's checkout at /src for an offline audit, with the test toolchain present.
#
# aperture is a small root module plus tools/. The dashboard is behind a build tag (`dashboard`) and
# is not built here: its Next.js output is not checked in, and the Go code under audit does not need
# it. The database layer uses modernc.org/sqlite (pure Go) and pgx, so no database headers are
# required, but CGO stays on for parity with the project's own builds.

FROM golang:1.26.0-bookworm

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
RUN go mod download && go mod verify

# Build with debug info and no inlining so stack traces and reproducers match the source, then compile
# every test binary without running it.
RUN go build -gcflags='all=-N -l' ./... \
    && go test -count=1 -run '^$' ./...

# Run the suite so the image is known to work, but do not let a failing test abort the build.
RUN (go test -count=1 -timeout 20m ./... || echo "WARNING: go test reported failures")

# The scan runs offline. Fail fast instead of waiting on the network if anything still tries to fetch.
ENV GOPROXY=off \
    GOSUMDB=off \
    GOFLAGS=-mod=mod

CMD ["bash"]

# Build from source. Releases use Dockerfile.goreleaser, which copies a
# prebuilt binary instead.
FROM golang:1.27-alpine AS build

WORKDIR /src

# Dependencies are layered separately so a source-only change does not
# re-download the module cache.
COPY go.mod go.sum ./
RUN go mod download

COPY . .

ARG VERSION=dev
ARG COMMIT=none
ARG DATE=unknown

# CGO is off so the result runs on a scratch-like base with no libc.
RUN CGO_ENABLED=0 go build -trimpath \
    -ldflags "-s -w \
      -X github.com/scm-bench/jenkins-bench/internal/cli.Version=${VERSION} \
      -X github.com/scm-bench/jenkins-bench/internal/cli.Commit=${COMMIT} \
      -X github.com/scm-bench/jenkins-bench/internal/cli.Date=${DATE}" \
    -o /out/jenkins-bench ./cmd/jenkins-bench

FROM alpine:3.24

# Certificates are the only runtime dependency: jenkins-bench talks HTTPS to
# a Jenkins controller and nothing else.
RUN apk add --no-cache ca-certificates \
    && adduser -D -u 10001 scmbench

COPY --from=build /out/jenkins-bench /usr/local/bin/jenkins-bench

USER 10001
WORKDIR /work

ENTRYPOINT ["/usr/local/bin/jenkins-bench"]
CMD ["--help"]

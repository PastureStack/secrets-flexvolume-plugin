FROM golang:1.27.0-bookworm@sha256:484ef6066fa69acb059fdfeda7ba2b8f7391f2ef6abc6f9b8411e669ebd56466 AS build

ARG VERSION=dev
WORKDIR /src
COPY . .
RUN go test -count=1 ./...
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build \
    -trimpath \
    -ldflags="-s -w -X main.version=${VERSION}" \
    -o /out/secrets-flexvolume-plugin \
    ./cmd/secrets-flexvolume-plugin

FROM ubuntu:26.04

ARG VERSION=dev
ARG REVISION=unknown
LABEL org.opencontainers.image.title="PastureStack Secret Volume Driver" \
      org.opencontainers.image.description="Encrypted secret delivery to isolated in-memory Docker volumes" \
      org.opencontainers.image.source="https://github.com/PastureStack/secrets-flexvolume-plugin" \
      org.opencontainers.image.documentation="https://github.com/PastureStack/secrets-flexvolume-plugin/blob/main/README.md" \
      org.opencontainers.image.licenses="Apache-2.0" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.revision="${REVISION}"

RUN apt-get update \
    && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends ca-certificates \
    && rm -f /usr/bin/pebble \
    && rm -rf /var/lib/apt/lists/*

COPY --from=build /out/secrets-flexvolume-plugin /usr/local/bin/secrets-flexvolume-plugin

USER 0:0
ENTRYPOINT ["/usr/local/bin/secrets-flexvolume-plugin"]
CMD ["serve"]

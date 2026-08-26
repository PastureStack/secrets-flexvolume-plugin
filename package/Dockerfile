# syntax=docker/dockerfile:1.7
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

FROM ubuntu:26.04@sha256:2260313b31c8c011cd2eebe728008efac1b3982be73eb71348ea2648d2c0e09b

ARG VERSION=dev
ARG REVISION=unknown
ARG UBUNTU_SNAPSHOT=20260825T000000Z

ADD --checksum=sha256:6077d27c6b6f8b23590cb01ff877ed8c804a67a5442cc32b5a33da10d2bd0e90 \
    https://snapshot.ubuntu.com/ubuntu/20260825T000000Z/pool/main/c/ca-certificates/ca-certificates_20260601~26.04.1_all.deb \
    /tmp/ca-certificates.deb
LABEL org.opencontainers.image.title="PastureStack Secret Volume Driver" \
      org.opencontainers.image.description="Encrypted secret delivery to isolated in-memory Docker volumes" \
      org.opencontainers.image.source="https://github.com/PastureStack/secrets-flexvolume-plugin" \
      org.opencontainers.image.documentation="https://github.com/PastureStack/secrets-flexvolume-plugin/blob/main/README.md" \
      org.opencontainers.image.licenses="Apache-2.0" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.revision="${REVISION}"

RUN set -eux; \
    mkdir -p /tmp/ca-bootstrap /etc/ssl/certs; \
    dpkg-deb --extract /tmp/ca-certificates.deb /tmp/ca-bootstrap; \
    find /tmp/ca-bootstrap/usr/share/ca-certificates -type f -name '*.crt' | LC_ALL=C sort | while IFS= read -r certificate; do sed -e '$a\' "${certificate}"; done > /etc/ssl/certs/ca-certificates.crt; \
    rm -rf /tmp/ca-bootstrap /tmp/ca-certificates.deb; \
    rm -f /etc/apt/sources.list /etc/apt/sources.list.d/*.list /etc/apt/sources.list.d/*.sources; \
    printf 'Types: deb\nURIs: https://snapshot.ubuntu.com/ubuntu/%s\nSuites: resolute resolute-updates resolute-backports resolute-security\nComponents: main universe restricted multiverse\nSigned-By: /usr/share/keyrings/ubuntu-archive-keyring.gpg\nSnapshot: no\n' "${UBUNTU_SNAPSHOT}" > /etc/apt/sources.list.d/pasturestack-snapshot.sources; \
    printf 'Acquire::Retries "5";\nAcquire::https::CaInfo "/etc/ssl/certs/ca-certificates.crt";\nAcquire::https::Verify-Peer "true";\nAcquire::https::Verify-Host "true";\nAcquire::AllowInsecureRepositories "false";\nAPT::Get::AllowUnauthenticated "false";\n' > /etc/apt/apt.conf.d/80pasturestack-snapshot; \
    apt-get update \
    && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends ca-certificates \
    && rm -f /usr/bin/pebble \
    && rm -rf /var/lib/apt/lists/*

COPY --from=build /out/secrets-flexvolume-plugin /usr/local/bin/secrets-flexvolume-plugin

USER 0:0
ENTRYPOINT ["/usr/local/bin/secrets-flexvolume-plugin"]
CMD ["serve"]

# syntax=docker/dockerfile:1.7
ARG UBUNTU_SECURITY_BACKPORTS_IMAGE=ghcr.io/pasturestack/ubuntu-security-backports:v0.1.0@sha256:2742a3d429e4e14bc587f6dedc51ded4246cf90bbaedcd86c67d0885e32a6f2a

FROM golang:1.27.4-bookworm@sha256:4fa7c968ba93f1635670522dbb01a2c78150443e1385746924566079f36570ea AS build

ARG VERSION=dev
WORKDIR /src
COPY . .
RUN go test -count=1 ./...
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build \
    -trimpath \
    -ldflags="-s -w -X main.version=${VERSION}" \
    -o /out/secrets-flexvolume-plugin \
    ./cmd/secrets-flexvolume-plugin

FROM ${UBUNTU_SECURITY_BACKPORTS_IMAGE} AS ubuntu_security_backports

FROM ubuntu:26.04@sha256:2260313b31c8c011cd2eebe728008efac1b3982be73eb71348ea2648d2c0e09b AS qualified_backports
ARG UBUNTU_SECURITY_BACKPORTS_IMAGE

ARG VERSION=dev
ARG REVISION=unknown
ARG UBUNTU_SNAPSHOT=20260825T000000Z

ADD --checksum=sha256:a7e3bf769aec16ba21ca39cba180d6d311dafcbae68346a05f137c5cc26c9ca6 \
    https://security.ubuntu.com/ubuntu/pool/main/c/ca-certificates/ca-certificates_20260816ubuntu0.26.04.2_all.deb \
    /tmp/ca-certificates.deb
LABEL org.opencontainers.image.title="PastureStack Secret Volume Driver" \
      org.opencontainers.image.description="Encrypted secret delivery to isolated in-memory Docker volumes" \
      org.opencontainers.image.source="https://github.com/PastureStack/secrets-flexvolume-plugin" \
      org.opencontainers.image.documentation="https://github.com/PastureStack/secrets-flexvolume-plugin/blob/main/README.md" \
      org.opencontainers.image.licenses="Apache-2.0" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.revision="${REVISION}"

COPY ubuntu-security-packages.lock /licenses/ubuntu-security-packages.lock
COPY scripts/install-ubuntu-security-updates /usr/local/libexec/pasturestack/install-ubuntu-security-updates
ADD --checksum=sha256:a7e3bf769aec16ba21ca39cba180d6d311dafcbae68346a05f137c5cc26c9ca6 https://security.ubuntu.com/ubuntu/pool/main/c/ca-certificates/ca-certificates_20260816ubuntu0.26.04.2_all.deb /opt/pasturestack-ca-certificates.deb
ADD --checksum=sha256:0de729b8fe0e1c67c04e8e8d5bd6e0420dbd47f75b93f0b71c8e740edc2d5ffc \
    https://security.ubuntu.com/ubuntu/pool/main/a/apt/apt_3.2.1ubuntu0.1_amd64.deb \
    /tmp/apt.deb
ADD --checksum=sha256:94e5d41303265b66af0f8c70ade18bfb77260ad286edee6c8045faddef82b94c \
    https://security.ubuntu.com/ubuntu/pool/main/a/apt/libapt-pkg7.0_3.2.1ubuntu0.1_amd64.deb \
    /tmp/libapt-pkg7.0.deb
RUN set -eux; \
    mkdir -p /tmp/ca-bootstrap /etc/ssl/certs; \
    dpkg-deb --extract /tmp/ca-certificates.deb /tmp/ca-bootstrap; \
    find /tmp/ca-bootstrap/usr/share/ca-certificates -type f -name '*.crt' | LC_ALL=C sort | while IFS= read -r certificate; do sed -e '$a\' "${certificate}"; done > /etc/ssl/certs/ca-certificates.crt; \
    rm -rf /tmp/ca-bootstrap /tmp/ca-certificates.deb; \
    rm -f /etc/apt/sources.list /etc/apt/sources.list.d/*.list /etc/apt/sources.list.d/*.sources; \
    printf 'Types: deb\nURIs: https://snapshot.ubuntu.com/ubuntu/%s\nSuites: resolute resolute-updates resolute-backports resolute-security\nComponents: main universe restricted multiverse\nSigned-By: /usr/share/keyrings/ubuntu-archive-keyring.gpg\nSnapshot: no\n' "${UBUNTU_SNAPSHOT}" > /etc/apt/sources.list.d/pasturestack-snapshot.sources; \
    printf 'Acquire::Retries "5";\nAcquire::https::CaInfo "/etc/ssl/certs/ca-certificates.crt";\nAcquire::https::Verify-Peer "true";\nAcquire::https::Verify-Host "true";\nAcquire::AllowInsecureRepositories "false";\nAPT::Get::AllowUnauthenticated "false";\n' > /etc/apt/apt.conf.d/80pasturestack-snapshot; \
    dpkg -i /tmp/apt.deb /tmp/libapt-pkg7.0.deb; \
    for package in apt libapt-pkg7.0; do \
        test "$(dpkg-query -W -f='${Version}' "$package")" = '3.2.1ubuntu0.1'; \
    done; \
    rm -f /tmp/apt.deb /tmp/libapt-pkg7.0.deb; \
    apt-get update --error-on=any \
    && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends ca-certificates \
    && rm -f /usr/bin/pebble \
    && dpkg -i /opt/pasturestack-ca-certificates.deb \
    && update-ca-certificates --fresh \
    && test "$(dpkg-query -W -f='${Version}' ca-certificates)" = '20260816ubuntu0.26.04.2' \
    && test ! -e /usr/share/ca-certificates/mozilla/emSign_ECC_Root_CA_-_G3.crt \
    && rm -f /opt/pasturestack-ca-certificates.deb \
    && sh /usr/local/libexec/pasturestack/install-ubuntu-security-updates /licenses/ubuntu-security-packages.lock /etc/ssl/certs/ca-certificates.crt \
    && printf '%s\n' libperl5.40=5.40.1-7ubuntu0.4 perl=5.40.1-7ubuntu0.4 perl-base=5.40.1-7ubuntu0.4 perl-modules-5.40=5.40.1-7ubuntu0.4 > /tmp/ubuntu-perl-security.lock \
    && UBUNTU_SECURITY_ARCHIVE=https://archive.ubuntu.com/ubuntu sh /usr/local/libexec/pasturestack/install-ubuntu-security-updates /tmp/ubuntu-perl-security.lock /etc/ssl/certs/ca-certificates.crt \
    && rm -f /tmp/ubuntu-perl-security.lock \
    && rm -rf /var/lib/apt/lists/*

COPY --from=build /out/secrets-flexvolume-plugin /usr/local/bin/secrets-flexvolume-plugin

# Keep the build-only installer and package archives outside the final image.
RUN --mount=type=bind,from=ubuntu_security_backports,source=/out,target=/opt/pasturestack/ubuntu-security-backports,readonly \
    set -eux; \
    evidence=/usr/share/pasturestack/security/ubuntu-backports; \
    mkdir -p "$evidence"; \
    /opt/pasturestack/ubuntu-security-backports/install-existing-backports --install-in-docker-build > "$evidence/install.json"; \
    /opt/pasturestack/ubuntu-security-backports/install-existing-backports --verify-installed > "$evidence/verify.json"; \
    for file in manifest.json qualification.json source-inputs.lock.json openvex.json; do \
        cp "/opt/pasturestack/ubuntu-security-backports/$file" "$evidence/$file"; \
    done; \
    printf '%s\n' "$UBUNTU_SECURITY_BACKPORTS_IMAGE" > "$evidence/bundle-image.txt"; \
    (cd "$evidence" && sha256sum manifest.json qualification.json source-inputs.lock.json openvex.json install.json verify.json bundle-image.txt > SHA256SUMS)

FROM scratch AS official_glibc
ADD --checksum=sha256:be83aefc14597fba683031a520f303950a7338b95d74decbe625faa51c49933e https://security.ubuntu.com/ubuntu/pool/main/g/glibc/libc6_2.43-2ubuntu2.7_amd64.deb /tmp/official-glibc/libc6.deb
ADD --checksum=sha256:c0393ea4fa3c45cefe0351db369d3a4a459edc8045856f2e3612ca17e77b2797 https://security.ubuntu.com/ubuntu/pool/main/g/glibc/libc-bin_2.43-2ubuntu2.7_amd64.deb /tmp/official-glibc/libc-bin.deb
ADD --checksum=sha256:408ba056d39651c2489b59522a614276d7a96020c6a401e73cd0da7d771764b0 https://security.ubuntu.com/ubuntu/pool/main/g/glibc/libc-gconv-modules-extra_2.43-2ubuntu2.7_amd64.deb /tmp/official-glibc/libc-gconv-modules-extra.deb
FROM qualified_backports AS runtime
RUN --mount=from=official_glibc,source=/tmp/official-glibc,target=/tmp/official-glibc,ro \
    set -eux; \
    for package in libc6 libc-bin libc-gconv-modules-extra; do \
        archive="/tmp/official-glibc/$package.deb"; \
        test "$(dpkg-deb -f "$archive" Package)" = "$package"; \
        test "$(dpkg-deb -f "$archive" Source)" = glibc; \
        test "$(dpkg-deb -f "$archive" Architecture)" = amd64; \
        test "$(dpkg-deb -f "$archive" Version)" = 2.43-2ubuntu2.7; \
        dpkg --compare-versions "$(dpkg-query -W -f='${Version}' "$package")" lt 2.43-2ubuntu2.7; \
    done; \
    dpkg --path-include='/usr/share/doc/libc6/*' --path-include='/usr/share/man/man1/getconf.1.gz' \
        --path-include='/usr/share/man/man1/tzselect.1.gz' --install /tmp/official-glibc/*.deb; \
    audit="$(dpkg --audit)"; \
    test -z "$audit"; \
    for package in libc6 libc-bin libc-gconv-modules-extra; do \
        integrity="$(dpkg --verify "$package")"; \
        test -z "$integrity"; \
    done; \
    getent hosts localhost >/dev/null; \
    rm -f /var/cache/ldconfig/aux-cache /var/log/dpkg.log; \
    dpkg-query -W -f='${binary:Package}\t${Version}\n' | LC_ALL=C sort > /usr/share/pasturestack/ubuntu-security-packages.tsv

USER 0:0
ENTRYPOINT ["/usr/local/bin/secrets-flexvolume-plugin"]
CMD ["serve"]

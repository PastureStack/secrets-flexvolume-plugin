#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
if [[ -n "${VALIDATION_TEMP_BASE:-}" ]]; then
    [[ -d "$VALIDATION_TEMP_BASE" ]]
    validation_tmp="$(mktemp -d "$VALIDATION_TEMP_BASE/secrets-flexvolume-plugin-validation.XXXXXXXX")"
else
    validation_tmp="$(mktemp -d)"
fi

cleanup() {
    if [[ -n "${validation_tmp:-}" && -d "$validation_tmp" && "$validation_tmp" != "/" ]]; then
        rm -rf -- "$validation_tmp"
    fi
}
trap cleanup EXIT

cd "$repo_root"
command -v go >/dev/null
command -v gofmt >/dev/null

export GOTOOLCHAIN=local
export GOWORK=off
export GOPROXY=off
export GOSUMDB=off
export GOCACHE="$validation_tmp/go-build"
export GOMODCACHE="$validation_tmp/go-mod"

unformatted="$(gofmt -l cmd internal)"
if [[ -n "$unformatted" ]]; then
    printf 'gofmt check failed:\n%s\n' "$unformatted" >&2
    exit 1
fi

go test -mod=mod -count=3 ./...
go test -mod=mod -tags=publictree -count=1 ./internal/safety
go vet -mod=mod ./...
go mod verify

module_count="$(go list -mod=mod -m all | wc -l | tr -d '[:space:]')"
if [[ "$module_count" != "1" ]] || [[ "$(go list -mod=mod -m all)" != "github.com/PastureStack/secrets-flexvolume-plugin" ]]; then
    printf 'module dependency gate failed\n' >&2
    exit 1
fi

if command -v gcc >/dev/null 2>&1 && [[ "$(go env CGO_ENABLED)" == "1" ]]; then
    go test -mod=mod -race -count=1 ./...
else
    printf 'SKIP race test: CGO or gcc is unavailable.\n'
fi

build_target() {
    local goos="$1"
    local goarch="$2"
    local output="$3"
    CGO_ENABLED=0 GOOS="$goos" GOARCH="$goarch" \
        go build -mod=mod -trimpath -buildvcs=false '-ldflags=-s -w' \
        -o "$output" ./cmd/secrets-flexvolume-plugin
}

host_goos="$(go env GOOS)"
host_goarch="$(go env GOARCH)"
host_extension=""
if [[ "$host_goos" == "windows" ]]; then
    host_extension=".exe"
fi
host_a="$validation_tmp/host-a$host_extension"
host_b="$validation_tmp/host-b$host_extension"
windows_binary="$validation_tmp/secrets-flexvolume-plugin-windows-amd64.exe"
linux_binary="$validation_tmp/secrets-flexvolume-plugin-linux-amd64"

build_target "$host_goos" "$host_goarch" "$host_a"
build_target "$host_goos" "$host_goarch" "$host_b"
build_target windows amd64 "$windows_binary"
build_target linux amd64 "$linux_binary"
cmp -s "$host_a" "$host_b"

for binary in "$windows_binary" "$linux_binary"; do
    SECRETS_FLEXVOLUME_PLUGIN_BINARY="$binary" \
        go test -mod=mod -count=1 -run '^TestExternalBinaryGate$' ./internal/safety
done

digest='sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd'
request="$(cat <<JSON
{"apiVersion":"pasturestack.io/secrets-flexvolume-plugin/v1alpha1","operation":"stage","volumeRef":"$digest","ownerRef":"$digest","requestRef":"$digest","idempotencyRef":"$digest","sourceRef":"$digest","manifest":{"manifestRef":"$digest","version":1,"generation":1,"expectedGeneration":0,"notBefore":"2026-01-01T00:00:00Z","rotateAt":"2026-01-02T00:00:00Z","expiresAt":"2026-01-03T00:00:00Z","entries":[{"name":"validation/marker","type":"regular","claimedBytes":12,"claimedDigest":"$digest","uid":1000,"gid":1000,"mode":"0400"}]},"lifecycle":{"currentState":"absent","leaseCount":0},"assertions":{"redacted":true,"encrypted":true,"attested":true}}
JSON
)"

capabilities="$($host_a capabilities)"
validated="$(printf '%s' "$request" | "$host_a" validate)"
planned="$(printf '%s' "$request" | "$host_a" --locale zh-TW plan)"

for output in "$capabilities" "$validated" "$planned"; do
    if grep -Fq 'validation/marker' <<<"$output" || grep -Fq "$digest" <<<"$output"; then
        printf 'CLI output echoed request metadata\n' >&2
        exit 1
    fi
    grep -Fq '"network":false' <<<"$output"
    grep -Fq '"execution":false' <<<"$output"
done
grep -Fq 'asserted-unverified' <<<"$planned"

printf 'Validation passed.\n'

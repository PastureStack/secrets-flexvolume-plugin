#!/usr/bin/env bash
# Only read the exact consumer and immutable bundle; execute its guard on the runner.
set -euo pipefail
test "$#" -eq 3
image=$1
sbom=$2
evidence=$3
bundle_image='ghcr.io/pasturestack/ubuntu-security-backports:v0.1.0@sha256:2742a3d429e4e14bc587f6dedc51ded4246cf90bbaedcd86c67d0885e32a6f2a'
bundle_digest=${bundle_image##*@}
[[ "$bundle_digest" =~ ^sha256:[0-9a-f]{64}$ ]]
test -s "$sbom"
mkdir -p "$evidence"
scratch=$(mktemp -d)
consumer=
bundle=
cleanup() {
    if [[ -n "$consumer" ]]; then docker rm "$consumer" >/dev/null 2>&1 || true; fi
    if [[ -n "$bundle" ]]; then docker rm "$bundle" >/dev/null 2>&1 || true; fi
    rm -rf -- "$scratch"
}
trap cleanup EXIT
consumer=$(docker create --entrypoint /bin/true "$image")
docker cp "$consumer:/usr/share/pasturestack/security/ubuntu-backports/." "$evidence/"
docker rm "$consumer" >/dev/null
consumer=
bundle=$(docker create "$bundle_image" /artifact-export-only)
docker cp "$bundle:/out/verify-consumer-evidence.py" "$scratch/verify-consumer-evidence.py"
docker cp "$bundle:/out/SHA256SUMS" "$scratch/bundle-SHA256SUMS"
docker rm "$bundle" >/dev/null
bundle=
python3 -B "$scratch/verify-consumer-evidence.py" \
    --evidence-dir "$evidence" --sbom "$sbom" \
    --expected-bundle-digest "$bundle_digest" \
    --bundle-checksums "$scratch/bundle-SHA256SUMS"

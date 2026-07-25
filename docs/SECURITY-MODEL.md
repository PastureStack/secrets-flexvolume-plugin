# Security model

## Trust boundary

The driver is a host component. It requires:

- a compatible control-plane URL and scoped environment-service credentials;
- the host RSA identity key mounted read-only;
- write and mount access only to the shared PastureStack volume root; and
- `CAP_SYS_ADMIN` for creating and removing `tmpfs` mounts.

It does not require the Docker socket, host PID namespace, host network, unrestricted root filesystem writes, or privileged-container mode.

The control plane decides which encrypted records an opaque volume token may retrieve. The driver validates cryptography and filesystem safety; it does not expand authorization beyond that token.

With `--provider vault`, the trusted bridge decides whether the requested sorted policy set is allowlisted. The driver obtains its host UUID from the link-local metadata API and signs the exact bounded JSON request with RSA-PSS/SHA-256 using the same host identity key. The bridge resolves the active host public key independently; the driver never sends a public key.

## Transport

- HTTPS requires TLS 1.2 or newer.
- Plain HTTP is restricted to private, loopback, or link-local IP destinations.
- URL user information, query strings, and fragments are rejected.
- Redirects may not change scheme or authority and are limited to two hops.
- Environment proxy configuration is ignored so credentials and tokens cannot be diverted through a proxy.
- Requests use bounded deadlines, headers, response bodies, and connection pools.
- Vault-provider redirects are rejected completely, signed requests use a fresh 192-bit nonce and UTC timestamp, and the bridge enforces its own replay cache.

## Envelope validation

The encrypted response is decoded with unknown-field rejection and a single-document requirement. Each record must contain a safe relative file name and a rewrapped envelope with:

- RSA OAEP using SHA-256 for the 256-bit data key;
- HMAC-SHA256 authentication over the encrypted payload;
- AES-256-GCM with a 96-bit nonce; and
- strict base64 decoding for the final file content.

The HMAC is verified before authenticated decryption. Unsupported algorithms, malformed keys, invalid signatures, modified ciphertext, invalid final content encoding, duplicate file names, invalid ownership, unsafe modes, path traversal, excess nesting, and over-limit payloads fail closed. Sensitive byte slices are overwritten after use where Go ownership permits.

## Filesystem controls

The host-side volume root uses mode `0700`. Each mounted volume root and nested directory uses mode `0755` so a workload's configured non-root UID can traverse it; only workloads receiving the volume mount can reach that path. Secret files are created exclusively through an atomic temporary file, synchronized, renamed, re-opened without following symlinks, assigned numeric ownership, and limited to the read-only modes `0400`, `0440`, or `0444`. Directory components reject absolute paths, dot segments, backslashes, control characters, and excessive depth or length.

Each volume uses a size-bounded `tmpfs` with `nodev`, `nosuid`, and `noexec`. If fetching, decryption, or materialization fails, the mount is removed and the directory is erased. Normal unmount removes the filesystem after the last consumer. Driver shutdown intentionally leaves active mounts in place to avoid breaking running workloads.

Vault-provider volumes also hold a response-wrapped token rather than an issuing or unwrapped child token. A failed materialization triggers immediate best-effort revocation. Normal final unmount must receive a successful idempotent revoke response; otherwise the local data is still erased and Docker may retry the revoke. After driver restart, a recovered active Vault mount is marked for revocation without persisting token material or an accessor locally.

## Limits

Defaults are:

| Control | Default | Maximum accepted configuration |
| --- | ---: | ---: |
| encrypted response | 10 MiB | 32 MiB |
| decoded file | 1 MiB | 4 MiB |
| decoded volume total | 8 MiB | 16 MiB |
| files per volume | 128 | 512 |
| control-plane request | 10 seconds | 60 seconds |

## Observability

`/healthz` reports only status and version. `/readyz` reports status, version, and the number of locally tracked volumes. Logs and protocol errors use fixed diagnostic text and do not include tokens, credentials, key material, secret values, encrypted envelopes, file names, or workload identifiers.

## Residual risks

Root on the host can inspect process memory and mounted files. A compromised control plane or host identity key defeats the intended confidentiality boundary. Active mounts intentionally survive a driver restart and require the workload lifecycle or an operator to release them. Operators must protect host backups, restrict access to the identity key and plugin socket, monitor failed mount requests, and rotate scoped environment-service credentials.

A compromised Vault bridge, issuing token, token role, or allowlist defeats the Vault-provider authorization boundary. Operators must restrict the bridge network, use the narrowest renewable issuing token and role, and keep wrapping and child-token TTLs short.

# Compatibility boundary

The production driver implements Docker Volume Plugin API v1 over a Unix socket. It supports:

- `Plugin.Activate`
- `VolumeDriver.Create`
- `VolumeDriver.Remove`
- `VolumeDriver.Mount`
- `VolumeDriver.Unmount`
- `VolumeDriver.Path`
- `VolumeDriver.Get`
- `VolumeDriver.List`
- `VolumeDriver.Capabilities`

The scope is `local`. A catalog installation schedules one instance per host, so each Docker daemon talks only to its host-local socket and memory-backed volume paths.

## Control-plane bridge

The driver uses the compatible control-plane `/secrets` endpoint with HTTP Basic authentication supplied by the environment service. HTTPS requires TLS 1.2 or newer. Plain HTTP is accepted only for loopback, link-local, or private IP addresses. Redirects are limited to the original scheme and authority, and environment proxy settings are intentionally ignored.

The request body is an opaque authorization token. The response must be a bounded JSON collection of encrypted records. The driver does not expose the token, credentials, identity key, file names, or decrypted values in health responses or logs.

The current option is `io.pasturestack.secrets.token`. A compatibility option is accepted for workloads created by the preserved control-plane protocol, but it is not a public PastureStack identifier.

## Vault bridge

With `--provider vault`, control-plane secret credentials are not required by the host driver. The driver requires a bridge URL, the host metadata URL, and its read-only RSA identity key. It sends signed requests to:

- `POST /v1/leases`
- `POST /v1/leases/revoke`

The current options are:

- `io.pasturestack.vault.policies`
- `io.pasturestack.vault.file`
- `io.pasturestack.vault.uid`
- `io.pasturestack.vault.gid`
- `io.pasturestack.vault.mode`

Neutral aliases (`policies`, `file`, `uid`, `gid`, and `mode`) are accepted. Conflicting aliases, unknown policy syntax, unsafe paths, writable modes, and invalid ownership values are rejected before a signed network request is made.

## Filesystem behavior

Each active volume is a host-visible shared `tmpfs` under `/var/lib/pasturestack/volumes/secret-volume`. The driver:

1. creates a private volume directory;
2. mounts `tmpfs` with `nodev`, `nosuid`, and `noexec`;
3. fetches and authenticates encrypted records;
4. writes each regular file atomically without following symlinks;
5. applies the requested numeric ownership and a read-only mode of `0400`, `0440`, or `0444`;
6. returns the host-visible mount path to Docker; and
7. unmounts and removes the directory after the final consumer releases it.

Multiple consumers of the same local volume share one mount. A live volume token cannot be replaced. Graceful driver shutdown preserves active mounts so running workloads are not disrupted; the next driver process discovers those mounts without recovering token material.

## Deliberate differences

The current implementation does not retain historical exec-based volume commands, vendored dependencies, Docker socket access, unrestricted host paths, permissive file modes, or plaintext diagnostics. It uses only the Go standard library and the Docker plugin protocol.

`storage-plugins`, `secret-delivery-api`, and `vault-secrets-bridge` remain separate projects. The Vault provider shares this driver's audited envelope validation and memory-volume lifecycle, while the bridge remains a separately released, unprivileged environment service.

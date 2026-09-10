PastureStack is an independent community effort to preserve, audit, and modernize the Rancher 1.6 ecosystem. It is not affiliated with or endorsed by Rancher Labs or SUSE.

**Upstream:** [`rancher/secrets-flexvol`](https://github.com/rancher/secrets-flexvol). This GitHub fork retains the upstream Git history, authorship, dates, and license notices unchanged; PastureStack maintenance is consolidated into one commit after the preserved upstream boundary.

# Secret Volume Driver

`secrets-flexvolume-plugin` is the PastureStack Docker volume driver for delivering encrypted control-plane secrets to workloads. The driver exposes a Docker Volume Plugin API v1 socket, requests only the encrypted records authorized by an opaque volume token, authenticates every envelope, decrypts it with the host identity key, and materializes the result inside an isolated in-memory filesystem.

The production entry point is:

```text
secrets-flexvolume-plugin serve
```

The release image starts that entry point automatically:

```text
ghcr.io/pasturestack/secrets-flexvolume-plugin:v0.2.0
```

Catalog deployment is the supported installation path. It runs one driver instance on each eligible host and supplies the compatible control-plane identity through the environment service. Operators do not pass plaintext secret values, private keys, or API credentials on the command line.

## Runtime contract

- Docker driver name: `pasturestack-secret-volume`
- Plugin socket: `/run/docker/plugins/pasturestack-secret-volume.sock`
- Private volume root: `/var/lib/pasturestack/volumes/secret-volume`
- Host identity key inside the container: `/var/lib/pasturestack/etc/ssl/host.key`
- Health endpoints: `GET /healthz` and `GET /readyz` on port `8093`
- Current volume option: `io.pasturestack.secrets.token`
- Providers: `control-plane` (default) and `vault`

The driver accepts the control plane's compatibility token name during migration, but the current source, user interface, driver name, socket, and volume paths use PastureStack naming.

The separate Vault deployment uses:

- driver name `pasturestack-vault-volume`;
- socket `/run/docker/plugins/pasturestack-vault-volume.sock`;
- volume root `/var/lib/pasturestack/volumes/vault-volume`;
- health port `8094`;
- `--provider vault`; and
- a private `--vault-bridge-url`.

Vault volume options are `io.pasturestack.vault.policies` (required), `io.pasturestack.vault.file`, `io.pasturestack.vault.uid`, `io.pasturestack.vault.gid`, and `io.pasturestack.vault.mode`. Neutral aliases are accepted for compose compatibility. The driver discovers its immutable host UUID through metadata, signs every issue and revoke request with the host identity key, rejects redirects, and revokes the lease after the final consumer unmounts.

Every secret file must use a safe relative path, a numeric UID and GID, and a read-only mode of `0400`, `0440`, or `0444`. The driver rejects path traversal, symlinks, duplicate names, unsupported algorithms, invalid signatures, unauthenticated ciphertext, writable or executable modes, oversized responses, oversized files, and excessive file counts. Secret contents live in a `tmpfs` mounted with `nodev`, `nosuid`, and `noexec`, and are erased when the final consumer unmounts the volume.

See [the security model](docs/SECURITY-MODEL.md), [the compatibility boundary](docs/COMPATIBILITY.md), [origin and attribution](ORIGIN.md), and [preserved legal artifacts](LICENSES/HISTORICAL-MANIFEST.json).

## Audit planner

The repository also retains a metadata-only audit interface:

```text
secrets-flexvolume-plugin [--locale en-US|zh-TW] capabilities
secrets-flexvolume-plugin [--locale en-US|zh-TW] validate
secrets-flexvolume-plugin [--locale en-US|zh-TW] plan
```

These commands validate bounded lifecycle metadata and never retrieve or print secret material. They do not execute the resulting plan; runtime delivery is available only through `serve`.

## Validation

Go 1.26 or newer is required:

```text
./scripts/validate.sh
./scripts/validate.ps1
```

The validation scripts check formatting, repeated unit tests, race safety, vet, module integrity, the public-tree policy, deterministic builds, binary content, and audit-CLI behavior. The container build repeats the complete Go test suite before producing the static Linux binary.

The repository-integrity workflow runs for pull requests, `main` pushes, and
manual dispatch. It validates repository policy but does not publish or deploy
runtime artifacts.

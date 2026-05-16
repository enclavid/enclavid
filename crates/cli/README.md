# enclavid-cli

CLI for managing Enclavid policies — encrypt your wasm, push to the registry, authenticate to the platform. Single static binary, no runtime dependencies.

## Install

```bash
cargo install --git https://github.com/enclavid/enclavid
```

Prebuilt binaries for Linux / macOS / Windows will be published via GitHub Releases. Homebrew formula and `enclavid/setup-cli@v1` GitHub Action are on the roadmap.

## Quickstart

```bash
# 1. One-time setup: generate your encryption key (K_client)
enclavid keygen --output client.key
#    Store client.key in your secrets manager (HSM / Vault / equivalent).
#    If you lose it, your encrypted policies become unrecoverable.

# 2. Encrypt your built policy
enclavid encrypt path/to/policy.wasm --key client.key -o policy.wasm.age

# 3. Authenticate (interactive — opens browser)
enclavid login

# 4. Push to your registry using a full OCI ref
enclavid push policy.wasm.age registry.enclavid.com/<org>/policies/kyc-standard:v1.0.0 \
  --key client.key
```

The CLI no longer tracks an "active workspace" — every push takes a full OCI reference (`<registry>/<repository>[:tag]`). Your organization id appears in the path because Enclavid's registry namespaces policies as `<org>/policies/<name>`; external registries (ghcr, ECR, ...) use whatever path layout you prefer.

## CI usage

In CI, set credentials as environment variables — no `enclavid login` needed:

```yaml
env:
  ENCLAVID_CLIENT_ID:     ${{ secrets.ENCLAVID_CLIENT_ID }}
  ENCLAVID_CLIENT_SECRET: ${{ secrets.ENCLAVID_CLIENT_SECRET }}

steps:
  - run: |
      enclavid encrypt policy.wasm --key client.key -o policy.wasm.age
      enclavid push policy.wasm.age \
        registry.enclavid.com/${{ vars.ENCLAVID_ORG }}/policies/kyc-standard:v${{ github.sha }} \
        --key client.key
```

Machine-to-machine credentials are issued from your Enclavid console (API Keys → Create key) and are bound to a specific organization at creation time.

## Using raw `oras` instead of `enclavid push`

The CLI plays nicely with the standard tooling. To push with `oras`:

```bash
echo "$(enclavid token)" | oras login registry.enclavid.com --username "" --password-stdin
oras push registry.enclavid.com/<org>/policies/kyc-standard:v1.0.0 \
  policy.wasm.age:application/vnd.enclavid.policy.wasm.v1.encrypted
```

`enclavid token` prints a fresh access token (refreshes if expired).

## Configuration

The CLI fetches its endpoints (issuer, OAuth client id, scopes) from a discovery endpoint at startup and caches the result for 1 hour under your user cache directory. Per-field env vars override what discovery returns.

| Env var | Purpose |
| --- | --- |
| `ENCLAVID_CLIENT_ID` | M2M client_id (CI flow) |
| `ENCLAVID_CLIENT_SECRET` | M2M client_secret (CI flow) |
| `ENCLAVID_DISCOVERY` | Override the discovery URL (default: `https://console.enclavid.com/api/cli-config`) |
| `ENCLAVID_ISSUER` | Override the OIDC issuer URL |
| `ENCLAVID_CLI_CLIENT_ID` | Override the OAuth client id used for the device flow |
| `ENCLAVID_REGISTRY_RESOURCE` | Override the OAuth resource indicator for the registry |
| `ENCLAVID_REGISTRY_SCOPES` | Comma-separated registry scopes (e.g. `registry:read,registry:push`) |

If the discovery endpoint is unreachable, set `ENCLAVID_ISSUER` / `ENCLAVID_CLI_CLIENT_ID` / `ENCLAVID_REGISTRY_RESOURCE` together to bypass discovery entirely.

## Files written

| Path | Contents |
| --- | --- |
| `~/.config/enclavid/auth.json` (or platform equivalent), mode `0600` | access_token, refresh_token, id_token |
| `~/.cache/enclavid/cli-config.json` (or platform equivalent) | Cached discovery response (TTL 1h) |

`enclavid logout` removes the auth file.

## License

Apache-2.0

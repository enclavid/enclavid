# enclavid-cli

CLI for managing Enclavid policy (encrypted OCI artifacts that carry your verification logic). Single static binary, no runtime dependencies.

## Install

```bash
cargo install --git https://github.com/enclavid/enclavid
```

Installs two binaries: `enclavid` (the CLI) and `docker-credential-enclavid` (a docker credential helper auto-invoked by `docker push` / `oras push` / `enclavid policy push` to keep your Enclavid registry token fresh — see [Authentication](#authentication)).

Prebuilt binaries for Linux / macOS / Windows will be published via GitHub Releases. Homebrew formula and `enclavid/setup-cli@v1` GitHub Action are on the roadmap.

## Command structure

```text
enclavid
├── cloud                          ← Enclavid SaaS: auth + workspace selection
│   ├── login [--workspace <id>]
│   ├── logout
│   ├── token
│   └── workspace
│       ├── (bare)                 ← show active
│       ├── list
│       └── use <id-or-name>
├── policy                         ← OCI artifact tooling (registry-agnostic)
│   ├── keygen
│   ├── seal --manifest manifest.json
│   ├── push [--auth ...]
│   └── validate
└── session                        ← verification session lifecycle
    ├── create --policy ... --policy-key ...
    ├── get <id>
    └── disclosures <id>
```

`cloud` and `policy` are intentionally separate groups. `cloud login` writes to `~/.docker/config.json` so subsequent pushes (including `docker push` and `oras push`, not just our own) refresh tokens automatically. `policy push` itself is **registry-agnostic** — pushing to ghcr/ECR/Docker Hub uses the same code path, with credentials resolved from the standard docker config chain.

## Quickstart

```bash
# 1. Generate your encryption key (client_policy_key). Store in HSM /
#    Vault — if you lose it, your encrypted policies become unrecoverable.
enclavid policy keygen --output client.key

# 2. Seal the policy: bundles the wasm component with `manifest.json`
#    (as a wasm custom section) and age-encrypts the whole thing.
enclavid policy seal path/to/policy.wasm \
    --key client.key --manifest path/to/manifest.json -o policy.wasm.age

# 3. Authenticate to Enclavid + auto-wire docker credentials. Prompts
#    for workspace selection if you're a member of multiple workspaces.
enclavid cloud login

# 4. Push using a full OCI ref. Auth comes from the docker credHelper
#    enclavid cloud login just registered — no extra flags needed.
enclavid policy push policy.wasm.age \
    registry.enclavid.com/enclavid/<workspace-id>/policies/kyc:v1.0.0
# → prints Pinned ref: registry.enclavid.com/.../kyc@sha256:<hex>

# 5. Smoke-test by creating a session against your running API.
enclavid session create \
    --policy registry.enclavid.com/enclavid/<workspace-id>/policies/kyc@sha256:<hex> \
    --policy-key client.key
# → prints session_id + applicant URL to open in a browser
```

Every push takes a **full** OCI reference (`<registry>/<repository>[:tag]`). For the Enclavid registry, the path layout is `enclavid/<workspace_id>/policies/<name>` — this is enforced by the registry's access policy. After `enclavid cloud login` the exact prefix is printed; you can also get it later via `enclavid cloud workspace`.

## Authentication

`enclavid policy push` resolves registry credentials via the standard chain — same one docker, oras, podman, and skopeo follow — with two enclavid-specific overrides on top for CI:

1. `--auth "Bearer <token>"` — explicit per-invocation.
2. `$ENCLAVID_REGISTRY_AUTH` — same shape, for single-registry CI.
3. `~/.docker/config.json` — `auths`, `credHelpers`, `credsStore` (in that order).

There's no Enclavid-specific carve-out for our own registry. `enclavid cloud login` registers a credential helper entry in `~/.docker/config.json` for the Enclavid registry host, so step 3 resolves it via the same path that resolves ECR or `osxkeychain` creds. The helper (the second binary, `docker-credential-enclavid`) is what mints fresh JWTs on demand — including for `docker push` and `oras push`, not just `enclavid policy push`.

The cred helper scopes minted JWTs to your **active workspace** (Logto `organization_id` claim). Switch workspaces with `enclavid cloud workspace use <id-or-name>` — the cached access token is invalidated, the next push gets a fresh token scoped to the new workspace, and your `enclavid/<workspace-id>/policies/...` path matches the registry's access policy.

### Pushing to external registries

`enclavid cloud login` only touches the Enclavid registry. For ghcr/ECR/Docker Hub, use whatever you'd use anyway:

```bash
# ghcr.io
docker login ghcr.io -u <gh-user> -p $GH_PAT

# ECR
aws ecr get-login-password | docker login --username AWS --password-stdin <acct>.dkr.ecr....

# Docker Hub
docker login -u <user>

# After ANY of the above:
enclavid policy push policy.wasm.age ghcr.io/me/policies/kyc:v1
```

### CI

For CI runners that don't want to write `~/.docker/config.json`:

```yaml
- run: |
    enclavid policy seal policy.wasm --key client.key --manifest manifest.json -o policy.wasm.age
    enclavid policy push policy.wasm.age \
        ghcr.io/${{ github.repository }}/kyc:v${{ github.sha }} \
        --auth "Bearer ${{ secrets.GHCR_PAT }}"
```

Or via env var:

```yaml
- run: enclavid policy push policy.wasm.age <ref>
  env:
    ENCLAVID_REGISTRY_AUTH: Bearer ${{ secrets.GHCR_PAT }}
```

> `enclavid policy push` no longer needs `--key` or `--manifest` — both are consumed at `enclavid policy seal`. Push uploads a single self-contained `.wasm.age` blob plus a `com.enclavid.policy.age-header` annotation that `POST /api/v1/sessions` uses for the cheap key-match check.

### Manifest is mandatory

Every `enclavid policy seal` requires a `manifest.json` (default: `./manifest.json`, override with `--manifest <path>`). The manifest is embedded into the wasm as a component-level custom section before age-encryption, so the resulting `.wasm.age` is a self-contained artifact — `manifest.json` doesn't need to travel alongside the encrypted file at any point after seal.

Policies that don't use text-refs (decision-only stubs) still ship a minimal manifest:

```bash
echo '{"version": 1, "kind": "policy"}' > manifest.json
```

`disclosure_fields` and `localized` are both optional within the manifest (default to empty). Seal refuses without a manifest file. If somehow an artifact reaches `POST /connect` without an embedded manifest section (e.g. produced by a non-enclavid age tool), the TEE returns `NoPolicyManifestLayer` → 422.

## Using raw `oras` / `docker push`

Both work transparently after `enclavid cloud login` (which writes the credential helper):

```bash
oras push registry.enclavid.com/enclavid/<workspace-id>/policies/kyc:v1 \
    policy.wasm.age:application/vnd.enclavid.policy.wasm.v1.encrypted

# or:
docker push registry.enclavid.com/enclavid/<workspace-id>/policies/kyc:v1
```

Both invoke `docker-credential-enclavid get` per push to fetch a current JWT.

> ⚠ Raw `oras push` / `docker push` doesn't add the `com.enclavid.policy.age-header` manifest annotation that `POST /api/v1/sessions` reads to do cheap client_policy_key validation. Policy pushed without that annotation will fail at /sessions create with `MissingAgeHeader`. If you need a non-enclavid push tool, you can compute the annotation manually (first ~200 bytes of the .age file, base64'd) — see [crates/cli/src/commands/push.rs::extract_age_header](src/commands/push.rs).

## Configuration

The CLI fetches its endpoints (issuer, OAuth client id, scopes) from a discovery endpoint at startup and caches the result for 1 hour. Per-field env vars override what discovery returns.

| Env var | Purpose |
| --- | --- |
| `ENCLAVID_REGISTRY_AUTH` | Registry credentials override (`Bearer ...` / `Basic <base64>`) |
| `ENCLAVID_API_TOKEN` | Raw Bearer for API calls (sessions). Bypasses Logto entirely — for lightweight dev stacks or pre-minted tokens |
| `ENCLAVID_API_URL` | Enclavid API base URL (sessions). Default: `http://localhost:8001` |
| `ENCLAVID_APPLICANT_URL` | Applicant SPA origin printed after `session create`. Default: `http://localhost:5173` |
| `ENCLAVID_WORKSPACE_ID` | Active workspace override (CI: avoids the interactive picker in `cloud login`) |
| `ENCLAVID_CLIENT_ID` | M2M client_id (Logto client_credentials grant for non-interactive auth) |
| `ENCLAVID_CLIENT_SECRET` | M2M client_secret |
| `ENCLAVID_DISCOVERY` | Override the discovery URL (default: `https://console.enclavid.com/api/cli-config`) |
| `ENCLAVID_ISSUER` | Override the OIDC issuer URL |
| `ENCLAVID_CLI_CLIENT_ID` | Override the OAuth client id used for the device flow |
| `ENCLAVID_REGISTRY_RESOURCE` | Override the OAuth resource indicator for the Enclavid registry |
| `ENCLAVID_REGISTRY_SCOPES` | Comma-separated registry scopes (e.g. `registry:read,registry:push`) |

If the discovery endpoint is unreachable, set `ENCLAVID_ISSUER` / `ENCLAVID_CLI_CLIENT_ID` / `ENCLAVID_REGISTRY_RESOURCE` together to bypass discovery entirely.

## Files written

| Path | Contents |
| --- | --- |
| `~/.config/enclavid/auth.json` (or platform equivalent), mode `0600` | access_token, refresh_token, id_token, workspaces list, active_workspace_id |
| `~/.cache/enclavid/cli-config.json` (or platform equivalent) | Cached discovery response (TTL 1h) |
| `~/.docker/config.json` `credHelpers` entry | Maps Enclavid registry host → `enclavid` helper |
| `~/.config/enclavid/sessions/<id>/token`, mode `0600` | Per-session `X-Session-Token` (returned by `session create`) |
| `~/.config/enclavid/sessions/<id>/disclosure.key`, mode `0600` | Per-session age secret-key (auto-generated, or copy of `--disclosure-key`) |

`enclavid cloud logout` removes the auth file AND the credHelper entry.

## License

Apache-2.0

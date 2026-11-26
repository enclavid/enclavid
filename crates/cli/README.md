# enclavid-cli

CLI for enclavid policies and plugins: embed a component's catalogs, validate them, push it to an OCI registry, and run it as a verification session. Single static binary, no runtime dependencies.

## Install

```bash
npm install -g @enclavid/cli
```

`@enclavid/cli` carries the binary built for macOS (Apple silicon and Intel) and for Linux (x64 and arm64, linked statically). A project made with `npm create enclavid` has it as a dev dependency, which `npx enclavid` runs. Each release's binaries are on its GitHub release as well, attested with Sigstore: `gh attestation verify enclavid-<platform> --repo enclavid/enclavid`.

Anywhere else, from source:

```bash
cargo install --git https://github.com/enclavid/enclavid enclavid-cli
```

## Command structure

```text
enclavid
├── policy                         ← author a policy artifact
│   ├── embed <wasm> [--wit wit] [--i18n i18n] [-o out]
│   └── validate [dir] [--i18n i18n] [--models models]
├── plugin                         ← author a plugin artifact
│   ├── embed <wasm> [--wit wit] [--i18n i18n] [-o out]
│   └── validate [dir] [--i18n i18n] [--models models]
├── oci                            ← registry operations, role-agnostic
│   └── push <artifact> <ref> [--auth ...] [--encrypt inline|kbs --key-out <file|->] [--models dir] [--quiet]
└── session                        ← verification session lifecycle
    ├── create --policy <ref|-> [--props <json|@file>] --api <origin> --applicants <origin>
    ├── get <id>
    └── disclosures <id>
```

`policy embed` asserts the component exports `enclavid:policy/policy`; `plugin embed` asserts it does not. `oci push` is **registry-agnostic**: a policy and a plugin are the same kind of artifact on the wire, and pushing to ghcr, ECR or Docker Hub uses the same code path, with credentials resolved from the standard docker config chain. With `--encrypt`, the layer key goes only where `--key-out` says: a new file only its owner may read, or stdout for `-`, and then everything else the push says goes to stderr.

## Quickstart: the playground

The playground runs a policy with no account: it takes a push with no credentials, and creates a session of it as enclavid's API does, pinning its own plugins.

```bash
# 1. Embed the policy's catalogs into the wasm component: its texts
#    (`i18n/`, one JSON file per language — or `--i18n i18n.json`, every
#    language in one file) and its disclosure fields, checked against the
#    keys its slot, `enclavid-ext:policy` in its WIT (`wit/`), declares.
enclavid policy embed path/to/policy.component.wasm -o policy.wasm

# 2. Push it to the playground, and start a session of it there.
enclavid oci push policy.wasm playground.enclavid.com/policies --quiet \
  | enclavid session create --policy - --props '{"min-age": 18}' \
      --api https://playground.enclavid.com --applicants https://verify.enclavid.com
# → prints session_id + applicant URL to open in a browser

# 3. Read it back once the applicant is done.
enclavid session get <session_id>
enclavid session disclosures <session_id>
```

`--quiet` prints the pinned reference alone, and `--policy -` reads it from stdin. Without them, `oci push` prints `Pinned ref: <registry>/<repository>@sha256:<hex>`, which `--policy` takes as it is. The pinned reference is the digest of the manifest the CLI pushed, never what the tag names when read back, which someone else's push may have moved by then.

`--props '{...}'` is quoted for a POSIX shell; anywhere, `--props @props.json` reads them from a file.

What is pushed to the playground is public: anyone may read it. The playground takes a policy of 4 MiB at most, and runs it with its own plugins: those of enclavid's templates.

## Sessions

`session create` takes the API's origin from `--api` / `$ENCLAVID_API_URL`, and the origin of the site applicants take a session at from `--applicants` / `$ENCLAVID_APPLICANT_URL`. Both are bare origins (`https://<name>[:port]`, no path). The API is reached over https, or over plain http on this machine alone (`localhost`, `127.0.0.1`, `[::1]`) and then through no proxy; `oci push` holds a registry to the same.

`$ENCLAVID_API_TOKEN` is the bearer for the API `$ENCLAVID_API_URL` names, and goes to that origin alone: a request to any other — `--api` naming another, as the playground — goes without it. So a token set for one API never reaches another:

```bash
export ENCLAVID_API_URL=https://api.enclavid.com ENCLAVID_API_TOKEN=<token>
enclavid session create --policy <pinned-ref> --applicants https://verify.enclavid.com
```

`create` caches the API, the session's token, the group it was placed on and the disclosure secret, so `session get` and `session disclosures` name the session alone.

A session takes its applicant's requests until its `expires_at`: `--expires-in <secs>` from now, else the one `--from-file` gives, else an hour.

### Through a gateway

When a gateway sits in front of api, it places a session on a group of api instances and answers with that group, `x-enclavid-group`, which the CLI caches. From then on `session get` and `session disclosures` put the group in front of the path (`<api>/-<label>.<build>/api/v1/sessions/<id>/...`), and the printed applicant link goes under it too (`<applicant>/-<label>.<build>/<id>`), because the gateway routes a request by that marker alone. Do not write the marker into either origin by hand — the CLI adds it.

A creating request may name the api build it requires:

```bash
enclavid session create --policy <pinned-ref> --measurement <96 lowercase hex> \
    --api https://<api name> --applicants https://<applicant name>
# or: ENCLAVID_API_MEASUREMENT=<96 lowercase hex> in place of --measurement
```

The CLI sends the build as `x-enclavid-measurement`, and refuses a group on another build. If a build is named and no group comes back, `session create` says so in a note, and the session is on no group.

## Registry credentials

`enclavid oci push` resolves registry credentials via the standard chain — same one docker, oras, podman, and skopeo follow — with two enclavid-specific overrides on top for CI:

1. `--auth "Bearer <token>"` — explicit per-invocation.
2. `$ENCLAVID_REGISTRY_AUTH` — `<registry> Bearer <token>` (or `<registry> Basic <base64>`), for CI: used for the registry it names, and no other.
3. `~/.docker/config.json` — `auths`, `credHelpers`, `credsStore` (in that order), each for its own registry.
4. None: the push goes anonymously, as to the playground. A registry that wants credentials refuses it, and the CLI says how to give some.

```bash
# ghcr.io
docker login ghcr.io -u <gh-user> -p $GH_PAT

# ECR
aws ecr get-login-password | docker login --username AWS --password-stdin <acct>.dkr.ecr....

# After either:
enclavid oci push policy.wasm ghcr.io/me/policies/kyc:v1
```

### CI

```yaml
- run: |
    enclavid policy embed policy.component.wasm -o policy.wasm
    enclavid oci push policy.wasm \
        ghcr.io/${{ github.repository }}/kyc:v${{ github.sha }} \
        --auth "Bearer ${{ secrets.GHCR_PAT }}"
```

## Configuration

| Env var | Purpose |
| --- | --- |
| `ENCLAVID_REGISTRY_AUTH` | Registry credentials for the registry named first: `<registry> Bearer <token>` / `<registry> Basic <base64>` |
| `ENCLAVID_API_TOKEN` | Bearer for API calls (sessions) to the API `ENCLAVID_API_URL` names, and to no other |
| `ENCLAVID_API_URL` | The API's origin for `session create`, in place of `--api` |
| `ENCLAVID_APPLICANT_URL` | The applicants' site's origin for `session create`, in place of `--applicants` |
| `ENCLAVID_API_MEASUREMENT` | The api build `session create` requires, as 96 lowercase hex characters; `--measurement` wins over it |

## Files written

`<config>` is the platform config directory: `$XDG_CONFIG_HOME` or `~/.config` on Linux, `~/Library/Application Support` on macOS, `%APPDATA%` on Windows.

| Path | Contents |
| --- | --- |
| `<config>/enclavid/sessions/<id>/api`, mode `0600` | The origin of the API the session was created at |
| `<config>/enclavid/sessions/<id>/token`, mode `0600` | Per-session `X-Session-Token` (returned by `session create`) |
| `<config>/enclavid/sessions/<id>/disclosure.key`, mode `0600` | Per-session disclosure secret, an X25519 secret key as hex (auto-generated, or copy of `--disclosure-key`); absent when `--from-file` brought its own `disclosure_pubkey` |
| `<config>/enclavid/sessions/<id>/group`, mode `0600` | Per-session group `<label>.<build>` a gateway placed the session on, checked again whenever it is read; absent when the API answered with none |

## License

Apache-2.0

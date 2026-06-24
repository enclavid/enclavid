use anyhow::Result;
use clap::{Parser, Subcommand};
use std::path::PathBuf;

mod auth;
mod commands;
mod config;
mod declarations;
mod discovery;
mod docker_config;
mod embed;
mod registry_auth;
mod wit_role;

#[derive(Parser)]
#[command(name = "enclavid")]
#[command(about = "Manage Enclavid policies — embed, push, authenticate", long_about = None)]
#[command(version)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Operations against the Enclavid SaaS: authentication and
    /// workspace selection. All commands that talk to Logto / our
    /// platform live here, kept separate from the registry-agnostic
    /// artifact tooling (`enclavid policy` / `plugin` / `oci`).
    Cloud {
        #[command(subcommand)]
        command: CloudCommand,
    },

    /// Author a **policy** artifact: embed its `enclavid:embedded.*`
    /// declarations (disclosure-fields / i18n / icons) and validate them.
    /// `embed` asserts the component exports the `enclavid:policy/policy`
    /// world. Registry push is role-agnostic — see `enclavid oci push`.
    Policy {
        #[command(subcommand)]
        command: PolicyCommand,
    },

    /// Author a **plugin** artifact: embed its `enclavid:embedded.{i18n,
    /// icons}` declarations. No disclosure-fields (policy is the single
    /// bandwidth gate, Option C). `embed` asserts the component is NOT a
    /// policy. Registry push is role-agnostic — see `enclavid oci push`.
    Plugin {
        #[command(subcommand)]
        command: PluginCommand,
    },

    /// Registry operations on Enclavid artifacts — role-agnostic. A
    /// policy and a plugin are the same wasm component on the wire
    /// (single `application/wasm` layer, digest-pinned), so push/pull
    /// live here once rather than duplicated per role.
    Oci {
        #[command(subcommand)]
        command: OciCommand,
    },

    /// Lifecycle of verification sessions against an Enclavid API
    /// instance. Useful for smoke-testing, dev iteration on policy,
    /// and inspecting consented data after applicants finish their
    /// flow. Talks to `$ENCLAVID_API_URL` (default `http://localhost:8001`).
    Session {
        #[command(subcommand)]
        command: SessionCommand,
    },
}

#[derive(Subcommand)]
enum CloudCommand {
    /// Authenticate to Enclavid (interactive, opens browser). After
    /// the device flow completes, prompts for workspace selection
    /// (auto-confirms when the user is a member of exactly one).
    /// Also wires the Enclavid registry into `~/.docker/config.json`
    /// as a credential helper, so subsequent `docker push` / `oras
    /// push` / `enclavid oci push` against that registry get
    /// fresh tokens automatically — no relogin every hour.
    Login {
        /// Skip the interactive workspace picker by selecting a
        /// specific workspace up-front. Accepts either a full id
        /// (`ord_...`) or a unique substring of the workspace name.
        /// Required when the user is a member of multiple workspaces
        /// and stdin isn't a TTY (CI).
        #[arg(long)]
        workspace: Option<String>,
    },

    /// Remove locally-stored credentials and drop the credHelper
    /// entry from `~/.docker/config.json`.
    Logout,

    /// Print a fresh access token to stdout. Useful for piping into
    /// custom flows (`curl -H "Authorization: Bearer $(enclavid cloud
    /// token)" ...`). For pushing artifacts prefer the credential-
    /// helper path set up by `enclavid cloud login` — no manual token
    /// plumbing.
    Token,

    /// Manage the active workspace (Logto organization). The active
    /// workspace determines which `enclavid/<workspace-id>/policies/...`
    /// namespace `enclavid oci push` writes to.
    Workspace {
        #[command(subcommand)]
        command: Option<WorkspaceCommand>,
    },
}

#[derive(Subcommand)]
enum WorkspaceCommand {
    /// Print the currently-active workspace and its push-path prefix.
    /// Same as bare `enclavid cloud workspace`.
    Show,

    /// List all workspaces the authenticated user is a member of.
    /// The active one is marked with `*`.
    List,

    /// Switch the active workspace. Arg can be either a full id
    /// (`ord_...`) or a unique case-insensitive substring of the
    /// workspace name.
    Use {
        /// Workspace id (`ord_...`) or substring of its name.
        id_or_name: String,
    },
}

#[derive(Subcommand)]
enum PolicyCommand {
    /// Embed the policy's `enclavid:embedded.*.v1` declarations
    /// (disclosure-fields, i18n, icons) into a wasm component as
    /// custom sections. Pure metadata embedding — the output is a
    /// wasm component ready for `enclavid oci push`.
    Embed {
        /// Path to the wasm component file (output of
        /// `cargo build --target wasm32-…` + `wasm-tools component
        /// new`).
        wasm: PathBuf,

        /// Path to the disclosure-fields declarations file (flat JSON
        /// list of identifier keys). Embedded into the wasm as the
        /// `enclavid:embedded.disclosure-fields.v1` custom section.
        /// Optional — components without `prompt-disclosure` calls
        /// can omit it. Defaults to `disclosure-fields.json` in the
        /// current directory; an absent file is silently treated as
        /// "no declarations".
        #[arg(long = "disclosure-fields", default_value = "disclosure-fields.json")]
        disclosure_fields: PathBuf,

        /// Path to the i18n translations catalog (JSON map of
        /// `key → { locale → text }`). Embedded as the
        /// `enclavid:embedded.i18n.v1` custom section. Optional —
        /// components without UI text refs can omit it. Defaults to
        /// `i18n.json`; an absent file is silently treated as "no
        /// translations".
        #[arg(long = "i18n", default_value = "i18n.json")]
        i18n: PathBuf,

        /// Path to the icons declarations file (flat JSON list of
        /// machine identifiers). Embedded as the
        /// `enclavid:embedded.icons.v1` custom section. Optional —
        /// components that never set `CaptureStep.icon` can omit it.
        /// Defaults to `icons.json`; an absent file is silently
        /// treated as "no icons".
        #[arg(long = "icons", default_value = "icons.json")]
        icons: PathBuf,

        /// Output path for the embedded wasm. Defaults to
        /// `<input-stem>.embedded.wasm` next to the input.
        #[arg(short, long)]
        output: Option<PathBuf>,
    },

    /// Validate a policy manifest against the same rules the TEE
    /// engine enforces at load time. Run before `push` to catch
    /// issues at author time with clean error messages.
    Validate {
        /// Path to the policy project directory containing the
        /// embedded declarations files (`disclosure-fields.json`,
        /// `i18n.json`). Both files are optional — missing files are
        /// silently treated as "no declarations of that kind".
        /// Defaults to the current directory.
        #[arg(default_value = ".")]
        dir: PathBuf,
    },
}

#[derive(Subcommand)]
enum PluginCommand {
    /// Embed the plugin's `enclavid:embedded.{i18n,icons}.v1`
    /// declarations into a wasm component as custom sections. Pure
    /// metadata embedding — no encryption. Plugins don't carry a
    /// `disclosure-fields` section under Option C (policy is the
    /// single bandwidth gate for DF refs).
    Embed {
        /// Path to the wasm component file (output of
        /// `cargo build --target wasm32-…` + `wasm-tools component
        /// new`).
        wasm: PathBuf,

        /// Path to the i18n translations catalog. Embedded as the
        /// `enclavid:embedded.i18n.v1` custom section. Optional —
        /// defaults to `i18n.json`; absent file is treated as "no
        /// translations".
        #[arg(long = "i18n", default_value = "i18n.json")]
        i18n: PathBuf,

        /// Path to the icons declarations file. Embedded as the
        /// `enclavid:embedded.icons.v1` custom section. Optional —
        /// defaults to `icons.json`; absent file is treated as "no
        /// icons".
        #[arg(long = "icons", default_value = "icons.json")]
        icons: PathBuf,

        /// Output path for the embedded wasm. Defaults to
        /// `<input-stem>.embedded.wasm` next to the input.
        #[arg(short, long)]
        output: Option<PathBuf>,
    },

    /// Validate a plugin project's embedded declarations (i18n, icons)
    /// against the same rules the TEE engine enforces at load. No
    /// disclosure-fields (policy is the single bandwidth gate, Option
    /// C). Run before `enclavid oci push`.
    Validate {
        /// Path to the plugin project directory containing `i18n.json`
        /// and `icons.json` (both optional — missing files are treated
        /// as "no declarations of that kind"). Defaults to the current
        /// directory.
        #[arg(default_value = ".")]
        dir: PathBuf,
    },
}

#[derive(Subcommand)]
enum OciCommand {
    /// Push an Enclavid artifact (a policy OR a plugin wasm component)
    /// to an OCI registry as a single `application/wasm` layer. Role-
    /// agnostic: the bytes are self-contained (the `policy` / `plugin
    /// embed` step welded the embedded declarations in), push just ships
    /// them; the TEE re-verifies the layer digest on pull.
    ///
    /// Registry auth resolution (first match wins):
    ///   1. `--auth "<scheme> <token>"` flag.
    ///   2. `ENCLAVID_REGISTRY_AUTH` env var.
    ///   3. `~/.docker/config.json` (static auths, credHelpers, credsStore).
    Push {
        /// Path to the (embedded) wasm component file.
        artifact: PathBuf,

        /// Full OCI reference: `<registry>/<repository>[:tag]`. Examples:
        /// `registry.enclavid.com/acme/kyc:v1`,
        /// `ghcr.io/acme/plugins/well-known:0.1.0`. Tag defaults to a
        /// timestamp if omitted; the artifact is also re-tagged as
        /// `:latest` unless that's already the supplied tag.
        reference: String,

        /// Explicit registry credential: a full Authorization-header
        /// value (e.g. `"Bearer ghp_xxxxx"` or `"Basic <base64>"`).
        /// Takes precedence over env / docker config.
        #[arg(long)]
        auth: Option<String>,

        /// Encrypt the artifact (ocicrypt `AES_256_CTR_HMAC_SHA256`).
        /// Omit for a plaintext push (today's default).
        ///   `inline` — prints the layer key for the client to pass as
        ///     `"key": "<base64>"` in POST /sessions (owner == the
        ///     session creator).
        ///   `kbs` — writes the `--kbs-resource` URI into the artifact's
        ///     `enc.keys.*` annotation and prints the layer key to register
        ///     as that KBS resource; the client passes `"key": { "kbs":
        ///     { endpoint } }` and the TEE fetches it under attestation.
        #[arg(long, value_enum)]
        encrypt: Option<EncryptMode>,

        /// KBS resource URI the layer key will be registered under, e.g.
        /// `kbs:///myrepo/key/1`. Required with `--encrypt kbs`; written
        /// into the artifact's digest-pinned `enc.keys.*` annotation.
        #[arg(long)]
        kbs_resource: Option<String>,
    },
}

#[derive(Clone, Copy, Debug, clap::ValueEnum)]
enum EncryptMode {
    Inline,
    Kbs,
}

#[derive(Subcommand)]
enum SessionCommand {
    /// Create a new verification session.
    ///
    /// Two ways to specify the request body: `--policy <ref>` for the
    /// trivial plaintext case, or `--from-file <spec.json>` for the full
    /// `POST /sessions` payload (plugin pins, per-artifact keys,
    /// registry_auth). Either way the CLI generates an ephemeral
    /// disclosure keypair (unless one is supplied), caches the secret
    /// locally so subsequent `session disclosures` can decrypt, and caches
    /// the returned `client_session_token` for `session get` /
    /// `session disclosures`.
    Create {
        /// Pinned OCI ref of the policy, `<registry>/<repo>@sha256:<hex>`.
        /// Use the value printed by `enclavid oci push` as
        /// `Pinned ref:`. Mutually exclusive with `--from-file`.
        #[arg(long, conflicts_with = "from_file")]
        policy: Option<String>,

        /// Path to a JSON file holding the **entire** `POST /sessions`
        /// body — `policy`, `plugins: [{package, impl_ref, key?}]`,
        /// `policy_key`, `registry_auth`, etc. (the same shape a consumer
        /// backend would send). If it omits `client_disclosure_pubkey`,
        /// the CLI injects an auto-generated one and caches its secret.
        /// Mutually exclusive with `--policy`.
        #[arg(short = 'f', long = "from-file", conflicts_with = "policy")]
        from_file: Option<PathBuf>,

        /// Path to an age identity used as the disclosure recipient.
        /// Wins over a `client_disclosure_pubkey` in `--from-file`. When
        /// absent (and the file supplies none), generate an ephemeral
        /// keypair and stash the secret under
        /// `~/.config/enclavid/sessions/<id>/`.
        #[arg(long)]
        disclosure_key: Option<PathBuf>,

        /// Opaque client-side identifier — echoed back in
        /// `session get` and webhook payloads. Use for reconciling
        /// session_id → your-side record on your dashboard.
        #[arg(long)]
        client_ref: Option<String>,
    },

    /// Fetch and print the session record (status, policy, disclosure
    /// count, ...). Uses the cached `client_session_token`.
    Get {
        /// Session id (the `ses_...` value from `session create`).
        id: String,
    },

    /// Pull disclosure entries, decrypt each with the cached
    /// disclosure secret, and pretty-print the resulting JSON.
    Disclosures {
        /// Session id.
        id: String,

        /// Override the disclosure secret path. When absent, look in
        /// `~/.config/enclavid/sessions/<id>/disclosure.key` (populated
        /// by the matching `session create`).
        #[arg(long)]
        disclosure_key: Option<PathBuf>,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "enclavid=info".into()),
        )
        .init();

    let cli = Cli::parse();

    // Discovery is needed strictly for the Logto-talking commands
    // (login / logout / token need OIDC endpoints). Workspace
    // subcommands operate on cached local state — they only consult
    // discovery (best-effort) to enrich output with the push-prefix
    // hint. Pure-policy commands skip discovery entirely so they
    // work offline.
    let needs_discovery_strict = matches!(
        cli.command,
        Commands::Cloud {
            command: CloudCommand::Login { .. }
                | CloudCommand::Logout
                | CloudCommand::Token,
        },
    );
    let needs_discovery_best_effort = matches!(
        cli.command,
        Commands::Cloud {
            command: CloudCommand::Workspace { .. },
        } | Commands::Session { .. },
    );
    if needs_discovery_strict {
        discovery::load().await?;
    } else if needs_discovery_best_effort {
        let _ = discovery::load().await;
    }

    match cli.command {
        Commands::Cloud { command } => match command {
            CloudCommand::Login { workspace } => {
                commands::cloud::login::run(workspace).await
            }
            CloudCommand::Logout => commands::cloud::logout::run().await,
            CloudCommand::Token => commands::cloud::token::run().await,
            CloudCommand::Workspace { command } => match command {
                None | Some(WorkspaceCommand::Show) => {
                    commands::cloud::workspace::show().await
                }
                Some(WorkspaceCommand::List) => commands::cloud::workspace::list().await,
                Some(WorkspaceCommand::Use { id_or_name }) => {
                    commands::cloud::workspace::use_workspace(&id_or_name).await
                }
            },
        },
        Commands::Policy { command } => match command {
            PolicyCommand::Embed {
                wasm,
                disclosure_fields,
                i18n,
                icons,
                output,
            } => commands::policy::embed::run(wasm, disclosure_fields, i18n, icons, output),
            PolicyCommand::Validate { dir } => commands::policy::validate::run(dir).await,
        },
        Commands::Plugin { command } => match command {
            PluginCommand::Embed {
                wasm,
                i18n,
                icons,
                output,
            } => commands::plugin::embed::run(wasm, i18n, icons, output),
            PluginCommand::Validate { dir } => commands::plugin::validate::run(dir).await,
        },
        Commands::Oci { command } => match command {
            OciCommand::Push {
                artifact,
                reference,
                auth,
                encrypt,
                kbs_resource,
            } => commands::oci::push::run(artifact, reference, auth, encrypt, kbs_resource).await,
        },
        Commands::Session { command } => match command {
            SessionCommand::Create {
                policy,
                from_file,
                disclosure_key,
                client_ref,
            } => {
                commands::session::create::run(policy, from_file, disclosure_key, client_ref).await
            }
            SessionCommand::Get { id } => commands::session::get::run(&id).await,
            SessionCommand::Disclosures {
                id,
                disclosure_key,
            } => commands::session::disclosures::run(&id, disclosure_key).await,
        },
    }
}

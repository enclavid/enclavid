use anyhow::Result;
use clap::{Parser, Subcommand};
use std::path::PathBuf;

mod auth;
mod commands;
mod config;
mod discovery;
mod docker_config;
mod embed;
mod registry_auth;

#[derive(Parser)]
#[command(name = "enclavid")]
#[command(about = "Manage Enclavid policies — encrypt, push, authenticate", long_about = None)]
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
    /// policy tooling under `enclavid policy ...`.
    Cloud {
        #[command(subcommand)]
        command: CloudCommand,
    },

    /// OCI artifact operations on enclavid policy bundles.
    Policy {
        #[command(subcommand)]
        command: PolicyCommand,
    },

    /// OCI artifact operations on enclavid plugin components. Symmetric
    /// with `enclavid policy ...` minus DF section (plugins don't
    /// declare disclosure-fields under Option C — policy is the single
    /// authority) and minus whole-component encryption (plugin
    /// encryption is code-section-only with a KBS-released key, Phase
    /// 6, not yet implemented).
    Plugin {
        #[command(subcommand)]
        command: PluginCommand,
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
    /// push` / `enclavid policy push` against that registry get
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
    /// namespace `enclavid policy push` writes to.
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
    /// Generate a new client_policy_key encryption key.
    Keygen {
        /// Output path for the key file.
        #[arg(short, long, default_value = "client.key")]
        output: PathBuf,
    },

    /// Embed the policy's `enclavid:embedded.*.v1` declarations
    /// (disclosure-fields, i18n, icons) into a wasm component as
    /// custom sections. Pure metadata embedding — no encryption. The
    /// output is a wasm component ready for `enclavid policy encrypt`
    /// (the next step in the production pipeline) or pushable as-is
    /// for unencrypted/dev artifacts.
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

    /// Age-encrypt a wasm policy component under the
    /// `client_policy_key`. Typical input is the output of
    /// `enclavid policy embed`. Output is `<input>.age`. The TEE
    /// decrypts the whole envelope before instantiation.
    Encrypt {
        /// Path to the wasm component file. If you have embedded
        /// declarations, run `enclavid policy embed` first; this
        /// command encrypts whatever wasm bytes it's handed.
        wasm: PathBuf,

        /// Path to client_policy_key file (generated by `enclavid
        /// policy keygen`).
        #[arg(short, long)]
        key: PathBuf,

        /// Output path for the encrypted artifact. Defaults to the
        /// wasm path with `.age` appended.
        #[arg(short, long)]
        output: Option<PathBuf>,
    },

    /// Push an encrypted policy artifact to an OCI registry.
    ///
    /// The artifact is self-contained — `enclavid policy embed` then
    /// `enclavid policy encrypt` already welded the manifest into the
    /// wasm component and age-encrypted the result. Push uploads it
    /// as a single OCI layer; no manifest flag here.
    ///
    /// Registry auth resolution (first match wins):
    ///   1. `--auth "<scheme> <token>"` flag.
    ///   2. `ENCLAVID_REGISTRY_AUTH` env var.
    ///   3. `~/.docker/config.json` (static auths, credHelpers, credsStore).
    Push {
        /// Path to the encrypted artifact (typically `.wasm.age`).
        artifact: PathBuf,

        /// Full OCI reference: `<registry>/<repository>[:tag]`. Examples:
        /// `registry.enclavid.com/acme/kyc:v1`,
        /// `ghcr.io/acme/policies/kyc:latest`. Tag defaults to a
        /// timestamp if omitted; the artifact is also re-tagged as
        /// `:latest` unless that's already the supplied tag.
        reference: String,

        /// Explicit registry credential: a full Authorization-header
        /// value (e.g. `"Bearer ghp_xxxxx"` or `"Basic <base64>"`).
        /// Takes precedence over env / docker config.
        #[arg(long)]
        auth: Option<String>,
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
}

#[derive(Subcommand)]
enum SessionCommand {
    /// Create a new verification session.
    ///
    /// Generates an ephemeral disclosure keypair (unless `--disclosure-key`
    /// is given), caches the secret half locally so subsequent
    /// `session disclosures` can decrypt. Caches the returned
    /// `client_session_token` so `session get` / `session disclosures`
    /// work without you re-passing it.
    Create {
        /// Pinned OCI ref of the policy, `<registry>/<repo>@sha256:<hex>`.
        /// Use the value printed by `enclavid policy push` as
        /// `Pinned ref:`.
        #[arg(long)]
        policy: String,

        /// Path to the client_policy_key file (`enclavid policy keygen`
        /// output). Used to age-encrypt the policy on push; the API
        /// re-validates against the manifest's age-header annotation.
        #[arg(long)]
        policy_key: PathBuf,

        /// Path to an age identity used as the disclosure recipient.
        /// When absent, generate an ephemeral keypair and stash the
        /// secret under `~/.config/enclavid/sessions/<id>/`.
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
            PolicyCommand::Keygen { output } => commands::policy::keygen::run(output),
            PolicyCommand::Embed {
                wasm,
                disclosure_fields,
                i18n,
                icons,
                output,
            } => commands::policy::embed::run(wasm, disclosure_fields, i18n, icons, output),
            PolicyCommand::Encrypt { wasm, key, output } => {
                commands::policy::encrypt::run(wasm, key, output)
            }
            PolicyCommand::Push {
                artifact,
                reference,
                auth,
            } => commands::policy::push::run(artifact, reference, auth).await,
            PolicyCommand::Validate { dir } => commands::policy::validate::run(dir).await,
        },
        Commands::Plugin { command } => match command {
            PluginCommand::Embed {
                wasm,
                i18n,
                icons,
                output,
            } => commands::plugin::embed::run(wasm, i18n, icons, output),
        },
        Commands::Session { command } => match command {
            SessionCommand::Create {
                policy,
                policy_key,
                disclosure_key,
                client_ref,
            } => {
                commands::session::create::run(policy, policy_key, disclosure_key, client_ref)
                    .await
            }
            SessionCommand::Get { id } => commands::session::get::run(&id).await,
            SessionCommand::Disclosures {
                id,
                disclosure_key,
            } => commands::session::disclosures::run(&id, disclosure_key).await,
        },
    }
}

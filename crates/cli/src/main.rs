use anyhow::Result;
use clap::{Parser, Subcommand};
use std::path::PathBuf;

mod auth;
mod commands;
mod declarations;
mod docker_config;
mod models;
mod plain_http;
mod registry_auth;
mod wit_role;

#[derive(Parser)]
#[command(name = "enclavid")]
#[command(about = "Manage enclavid policies — embed, push, run", long_about = None)]
// The version of the npm package the CLI is released as (build.rs).
#[command(version = env!("ENCLAVID_CLI_VERSION"))]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Author a **policy** artifact: embed its catalogs (texts and
    /// disclosure fields) and validate them. `embed` asserts the
    /// component exports the `enclavid:policy/policy` world. Registry
    /// push is role-agnostic — see `enclavid oci push`.
    Policy {
        #[command(subcommand)]
        command: PolicyCommand,
    },

    /// Author a **plugin** artifact: embed its texts and validate them.
    /// No disclosure fields (a plugin's helpers take the fields the policy
    /// mints). `embed` asserts the component is NOT a policy.
    /// Registry push is role-agnostic — see `enclavid oci push`.
    Plugin {
        #[command(subcommand)]
        command: PluginCommand,
    },

    /// Registry operations on enclavid artifacts — role-agnostic. A
    /// policy and a plugin are the same wasm component on the wire
    /// (single `application/wasm` layer, digest-pinned), so push/pull
    /// live here once rather than duplicated per role.
    Oci {
        #[command(subcommand)]
        command: OciCommand,
    },

    /// Lifecycle of verification sessions against an enclavid API:
    /// enclavid's own, or the playground's, which answers as it does and
    /// asks no credentials. Useful for smoke-testing, dev iteration on a
    /// policy, and inspecting consented data after applicants finish
    /// their flow.
    Session {
        #[command(subcommand)]
        command: SessionCommand,
    },
}

#[derive(Subcommand)]
enum PolicyCommand {
    /// Embed the policy's catalogs into its wasm component: its texts
    /// and its disclosure fields, checked against the keys its slot,
    /// `enclavid-ext:policy`, declares. Pure metadata embedding — the
    /// output is a wasm component ready for `enclavid oci push`.
    Embed {
        /// Path to the wasm component file (output of
        /// `cargo build --target wasm32-…` + `wasm-tools component
        /// new`).
        wasm: PathBuf,

        /// The WIT the component was built from. The cases of `key` in
        /// `enclavid-ext:policy/i18n` are the texts' keys, and those in
        /// `enclavid-ext:policy/disclosure-fields` the policy's
        /// disclosure fields.
        #[arg(long = "wit", default_value = "wit")]
        wit: PathBuf,

        /// The texts: a directory of `<language>.json` files, each a
        /// language's texts by key, or one JSON file of every language's
        /// texts, by language (`i18n.json`). Absent for a policy with no
        /// texts of its own.
        #[arg(long = "i18n", default_value = "i18n")]
        i18n: PathBuf,

        /// Output path for the embedded wasm. Defaults to
        /// `<input-stem>.embedded.wasm` next to the input.
        #[arg(short, long)]
        output: Option<PathBuf>,
    },

    /// Validate a policy project's catalogs against the same rules the
    /// TEE engine enforces at load time, and the files of the models its
    /// slot declares (`enclavid-ext:policy/models`): each graph as the
    /// process that runs it checks it, against the `run` the slot declares.
    /// Run before `push` to catch issues at author time with clean error
    /// messages.
    Validate {
        /// Path to the policy project directory, holding its `wit/` and
        /// its texts. Defaults to the current directory.
        #[arg(default_value = ".")]
        dir: PathBuf,

        /// The texts, in the project directory: a directory of
        /// `<language>.json` files, or one JSON file of every language's
        /// texts (`i18n.json`).
        #[arg(long = "i18n", default_value = "i18n")]
        i18n: PathBuf,

        /// The models' files, in the project directory or anywhere else: a
        /// directory holding `<function>.onnx` for each model the slot
        /// declares, and `<function>.onnx.data` where its graph points into
        /// one, and nothing besides — as they are pushed beside the
        /// component.
        #[arg(long = "models", default_value = "models")]
        models: PathBuf,
    },
}

#[derive(Subcommand)]
enum PluginCommand {
    /// Embed the plugin's texts into its wasm component, checked against
    /// the keys its slot declares: `enclavid-ext:<name>`, named for its
    /// package. Pure metadata embedding — no encryption. Plugins declare
    /// no disclosure fields: their helpers take the fields the policy
    /// mints.
    Embed {
        /// Path to the wasm component file (output of
        /// `cargo build --target wasm32-…` + `wasm-tools component
        /// new`).
        wasm: PathBuf,

        /// The WIT the component was built from; the cases of `key` in
        /// its slot's `i18n`, `enclavid-ext:<name>/i18n`, are the texts'
        /// keys.
        #[arg(long = "wit", default_value = "wit")]
        wit: PathBuf,

        /// The texts: a directory of `<language>.json` files, each a
        /// language's texts by key, or one JSON file of every language's
        /// texts, by language (`i18n.json`). Absent for a plugin with no
        /// texts.
        #[arg(long = "i18n", default_value = "i18n")]
        i18n: PathBuf,

        /// Output path for the embedded wasm. Defaults to
        /// `<input-stem>.embedded.wasm` next to the input.
        #[arg(short, long)]
        output: Option<PathBuf>,
    },

    /// Validate a plugin project's texts against the same rules the TEE
    /// engine enforces at load, and the files of the models its slot
    /// declares (`enclavid-ext:<name>/models`): each graph as the process
    /// that runs it checks it, against the `run` the slot declares. Run
    /// before `enclavid oci push`.
    Validate {
        /// Path to the plugin project directory, holding its `wit/` and
        /// its texts. Defaults to the current directory.
        #[arg(default_value = ".")]
        dir: PathBuf,

        /// The texts, in the project directory: a directory of
        /// `<language>.json` files, or one JSON file of every language's
        /// texts (`i18n.json`).
        #[arg(long = "i18n", default_value = "i18n")]
        i18n: PathBuf,

        /// The models' files, in the project directory or anywhere else: a
        /// directory holding `<function>.onnx` for each model the slot
        /// declares, and `<function>.onnx.data` where its graph points into
        /// one, and nothing besides — as they are pushed beside the
        /// component.
        #[arg(long = "models", default_value = "models")]
        models: PathBuf,
    },
}

#[derive(Subcommand)]
enum OciCommand {
    /// Push an enclavid artifact (a policy OR a plugin wasm component)
    /// to an OCI registry as an `application/wasm` layer, and the files of
    /// its models beside it. Role-agnostic: the bytes are self-contained
    /// (the `policy` / `plugin embed` step welded the embedded declarations
    /// in), push just ships them; the TEE re-verifies every layer digest on
    /// pull.
    ///
    /// Registry auth resolution (first match wins):
    ///   1. `--auth "<scheme> <token>"` flag.
    ///   2. `ENCLAVID_REGISTRY_AUTH` env var, `<registry> <scheme> <token>`,
    ///      for the registry it names alone.
    ///   3. `~/.docker/config.json` (static auths, credHelpers, credsStore).
    ///   4. None: anonymous, as to the playground,
    ///      `playground.enclavid.com/policies`, which asks for none.
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

        /// Encrypt the artifact (ocicrypt `AES_256_CTR_HMAC_SHA256`) under a
        /// new layer key, written to `--key-out`. Omit for a plaintext push
        /// (today's default).
        ///   `inline` — the client passes the key, base64, as
        ///     `"key": "<base64>"` in POST /sessions (owner == the
        ///     session creator).
        ///   `kbs` — writes the `--kbs-resource` URI into the artifact's
        ///     `enc.keys.*` annotation; the key is registered as that KBS
        ///     resource, the client passes `"key": { "kbs": { endpoint } }`
        ///     and the TEE fetches it under attestation.
        #[arg(long, value_enum, requires = "key_out")]
        encrypt: Option<EncryptMode>,

        /// Where the layer key of `--encrypt` goes: a new file, which only
        /// its owner may read, or `-` for stdout — then everything else the
        /// push says goes to stderr. Never printed otherwise: a key in a CI
        /// log is anyone's who reads it. The key is in the form its mode
        /// takes: base64 for `inline`, the JSON the resource holds for `kbs`.
        #[arg(long, requires = "encrypt")]
        key_out: Option<PathBuf>,

        /// KBS resource URI the layer key will be registered under, e.g.
        /// `kbs:///myrepo/key/1`. Required with `--encrypt kbs`; written
        /// into the artifact's digest-pinned `enc.keys.*` annotation.
        #[arg(long)]
        kbs_resource: Option<String>,

        /// The models' files to push beside the component: every
        /// `<function>.onnx` and `<function>.onnx.data` in this directory,
        /// each a layer of its own named for its file — as `validate
        /// --models` checks them. Pushed in the clear, so not with
        /// `--encrypt`. Omit for an artifact with no models.
        #[arg(long)]
        models: Option<PathBuf>,

        /// Print the pinned reference alone, for another command to read:
        /// `enclavid oci push ... --quiet | enclavid session create
        /// --policy -`. Not with `--key-out -`, which writes the key there.
        #[arg(long)]
        quiet: bool,
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
    /// Two ways to specify the request body: `--policy <ref>`, with its
    /// `--props`, for the plaintext case, or `--from-file <spec.json>` for
    /// the full `POST /sessions` payload (plugin pins, per-artifact keys,
    /// registry_auth). Either way the CLI generates an ephemeral
    /// disclosure keypair (unless one is supplied), caches the secret
    /// locally so subsequent `session disclosures` can decrypt, and caches
    /// the API and the returned `client_session_token` for `session get` /
    /// `session disclosures`.
    ///
    /// The playground runs a policy pushed to it with no credentials,
    /// pinning its own plugins: `--api https://playground.enclavid.com
    /// --applicants https://verify.enclavid.com`.
    Create {
        /// Pinned OCI ref of the policy, `<registry>/<repo>@sha256:<hex>`:
        /// the value printed by `enclavid oci push` as `Pinned ref:`, or
        /// `-` to read it from stdin, as `enclavid oci push --quiet`
        /// writes it. Mutually exclusive with `--from-file`.
        #[arg(long, conflicts_with = "from_file")]
        policy: Option<String>,

        /// The props the policy reads: a JSON object, `{"min-age": 18}`,
        /// or `@<path>` of a file holding one. Mutually exclusive with
        /// `--from-file`, whose body carries its own.
        #[arg(long, conflicts_with = "from_file")]
        props: Option<String>,

        /// Path to a JSON file holding the **entire** `POST /sessions`
        /// body — `policy`, `plugins: [{package, impl_ref, key?}]`,
        /// `policy_key`, `registry_auth`, `props`, etc. (the same shape a
        /// consumer backend would send). If it omits `client_disclosure_pubkey`,
        /// the CLI injects an auto-generated one and caches its secret.
        /// Mutually exclusive with `--policy`.
        #[arg(short = 'f', long = "from-file", conflicts_with = "policy")]
        from_file: Option<PathBuf>,

        /// Path to a file holding the disclosure secret (an X25519 secret
        /// as hex) whose public key is the disclosure recipient.
        /// Wins over a `client_disclosure_pubkey` in `--from-file`. When
        /// absent (and the file supplies none), generate an ephemeral
        /// keypair and stash the secret under `enclavid/sessions/<id>/`
        /// in the platform config directory (`~/.config` on Linux,
        /// `~/Library/Application Support` on macOS).
        #[arg(long)]
        disclosure_key: Option<PathBuf>,

        /// Opaque client-side identifier — echoed back in
        /// `session get` and webhook payloads. Use for reconciling
        /// session_id → your-side record on your dashboard.
        #[arg(long)]
        client_ref: Option<String>,

        /// The api build the session must run on, as 96 lowercase hex
        /// characters (the launch measurement). Sent to a gateway in
        /// front of api, which places the session on a group running
        /// that build. Falls back to `$ENCLAVID_API_MEASUREMENT`; omit
        /// both against api directly, or against the playground, which
        /// names its own.
        #[arg(long)]
        measurement: Option<String>,

        /// The API's origin, `scheme://host[:port]`: where the session is
        /// created, and every later `session` command about it goes. The
        /// bearer in `$ENCLAVID_API_TOKEN` goes with these requests when
        /// they go to the API `$ENCLAVID_API_URL` names, the one it is for.
        #[arg(long, env = "ENCLAVID_API_URL")]
        api: String,

        /// The origin of the site applicants take a session at, which
        /// the printed applicant link goes to.
        #[arg(long, env = "ENCLAVID_APPLICANT_URL")]
        applicants: String,
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
        /// `enclavid/sessions/<id>/disclosure.key` in the platform config
        /// directory (`~/.config` on Linux, `~/Library/Application
        /// Support` on macOS; populated by the matching `session create`).
        #[arg(long)]
        disclosure_key: Option<PathBuf>,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    // Logs go to stderr: stdout is what a command answers, which another
    // may read, as `session create --policy -` reads `oci push --quiet`.
    tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "enclavid=info".into()),
        )
        .init();

    let cli = Cli::parse();

    match cli.command {
        Commands::Policy { command } => match command {
            PolicyCommand::Embed {
                wasm,
                wit,
                i18n,
                output,
            } => commands::policy::embed::run(wasm, wit, i18n, output),
            PolicyCommand::Validate { dir, i18n, models } => {
                commands::policy::validate::run(dir, i18n, models).await
            }
        },
        Commands::Plugin { command } => match command {
            PluginCommand::Embed {
                wasm,
                wit,
                i18n,
                output,
            } => commands::plugin::embed::run(wasm, wit, i18n, output),
            PluginCommand::Validate { dir, i18n, models } => {
                commands::plugin::validate::run(dir, i18n, models).await
            }
        },
        Commands::Oci { command } => match command {
            OciCommand::Push {
                artifact,
                reference,
                auth,
                encrypt,
                key_out,
                kbs_resource,
                models,
                quiet,
            } => {
                commands::oci::push::run(commands::oci::push::Asked {
                    artifact,
                    reference,
                    auth,
                    encrypt,
                    key_out,
                    kbs_resource,
                    models,
                    quiet,
                })
                .await
            }
        },
        Commands::Session { command } => match command {
            SessionCommand::Create {
                policy,
                from_file,
                props,
                disclosure_key,
                client_ref,
                measurement,
                api,
                applicants,
            } => {
                commands::session::create::run(commands::session::create::Asked {
                    policy,
                    from_file,
                    props,
                    disclosure_key,
                    client_ref,
                    measurement,
                    api,
                    applicants,
                })
                .await
            }
            SessionCommand::Get { id } => commands::session::get::run(&id).await,
            SessionCommand::Disclosures { id, disclosure_key } => {
                commands::session::disclosures::run(&id, disclosure_key).await
            }
        },
    }
}

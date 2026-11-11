use clap::{Args, Subcommand};
use hysteria_cli::{
    CliError, Result,
    ech::{self, Aead},
};
use std::{
    io::{self, Write as _},
    path::PathBuf,
};

/// Generates keys offline; stdout contains only public metadata/configuration.
#[derive(Debug, Args)]
#[command(subcommand_negates_reqs = true, args_conflicts_with_subcommands = true)]
pub(crate) struct EchOptions {
    #[command(subcommand)]
    command: Option<KeyCommand>,
    /// Plaintext outer SNI, such as public.example.com (not the real server name).
    #[arg(long, required = true)]
    public_name: Option<String>,
    /// Private PEM file. Never use it as a publicly served website file.
    #[arg(short = 'o', long, default_value = "ech.pem")]
    output: PathBuf,
    /// Config identifier, 0-255; -1 selects a random unused ID.
    #[arg(long, default_value_t = -1, allow_hyphen_values = true, value_parser = clap::value_parser!(i16).range(-1..=255))]
    config_id: i16,
    /// Inner-name padding hint, 0-255; zero means unknown.
    #[arg(long, default_value_t = 0)]
    max_name_length: u8,
    /// HPKE AEADs in preference order, separated by commas.
    #[arg(long, value_enum, value_delimiter = ',', default_value = "aes-128-gcm")]
    aead: Vec<Aead>,
    /// Atomically replace an existing regular key file.
    #[arg(long)]
    overwrite: bool,
    /// Retain keys from this private PEM during rotation; the new key is preferred.
    #[arg(long)]
    retain_keys: Option<PathBuf>,
}

#[derive(Debug, Subcommand)]
enum KeyCommand {
    /// Retire unselected keys after clients have migrated; never generates a key.
    Prune {
        /// Existing private PEM containing all active keys.
        #[arg(short = 'i', long)]
        input: PathBuf,
        /// IDs to retain, comma-separated or repeated. All others are retired.
        #[arg(long, required = true, value_delimiter = ',')]
        keep_id: Vec<u8>,
        /// New private PEM file.
        #[arg(short = 'o', long)]
        output: PathBuf,
        /// Atomically replace an existing regular output file.
        #[arg(long)]
        overwrite: bool,
    },
}

impl EchOptions {
    pub(crate) fn run(self) -> Result<()> {
        if let Some(KeyCommand::Prune {
            input,
            keep_id,
            output,
            overwrite,
        }) = self.command
        {
            let pruned = ech::prune(&input, &output, &keep_id, overwrite)?;
            let mut stdout = io::stdout().lock();
            writeln!(
                stdout,
                "ECH KEYS PRUNED\n  Retained IDs    {}\n\n# server.yaml\nech:\n  keyPath: {}\n\n# Public client configuration\ntls:\n  ech: {}\n\nThe key file remains private. Restart the server after pointing it to this file.\nClients using only retired keys will fail; migrate them before restarting.",
                pruned
                    .retained_ids
                    .iter()
                    .map(u8::to_string)
                    .collect::<Vec<_>>()
                    .join(", "),
                serde_json::Value::String(pruned.output.to_string_lossy().into_owned()),
                pruned.client_config
            )?;
            return Ok(());
        }
        let generated = ech::generate(&ech::Options {
            public_name: self
                .public_name
                .ok_or_else(|| CliError::new("--public-name is required for key generation"))?,
            output: self.output,
            config_id: u8::try_from(self.config_id).ok(),
            max_name_length: self.max_name_length,
            aeads: self.aead,
            overwrite: self.overwrite,
            retain_keys: self.retain_keys,
        })?;
        let mut output = io::stdout().lock();
        writeln!(
            output,
            "ECH KEYS GENERATED\n  Public name     {}\n  New config ID   {}\n  Active keys     {}\n\nKeep the key file private. Share only the public client configuration below.\n\n# server.yaml\nech:\n  keyPath: {}\n\n# client.yaml: retain your real tls.sni and certificate verification settings\ntls:\n  ech: {}\n\nRestart the server to load this file. For rotation, distribute the new public\nconfiguration before removing old keys; restart again to retire those keys.",
            generated.public_name,
            generated.config_id,
            generated.key_count,
            serde_json::Value::String(generated.output.to_string_lossy().into_owned()),
            generated.client_config
        )?;
        Ok(())
    }
}

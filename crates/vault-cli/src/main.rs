//! `vault` — the no-JavaScript client.
//!
//! ```text
//! vault signup                       # account number + 24 words, printed once
//! vault login 4827 3910 5649 0182    # stores a session token only
//! vault gate                         # 18+ confirmation
//! vault put clip.mp4 --public        # encrypts with a fresh FEK, uploads ciphertext
//! vault ls
//! vault cat f_… | mpv -              # decrypt to stdout and play
//! vault get f_… out.mp4              # decrypt to a file
//! ```
//!
//! The passphrase is read from a TTY (no echo), `$VAULT_PASSPHRASE`, or
//! `--passphrase-file`. It is never written to disk; only the session token is.
//!
//! `vault cat` is the point of this binary: a complete viewer with zero
//! JavaScript, no browser, no Electron.

use std::io::Write;
use std::path::PathBuf;

use clap::{Parser, Subcommand, ValueEnum};
use vault_cli::{Api, Session};
use vault_core::wire::Visibility;

#[derive(Parser)]
#[command(
    name = "vault",
    about = "Zero-JS client for a zero-knowledge vault",
    version
)]
struct Cli {
    /// API base URL (default: $VAULT_API or http://127.0.0.1:8080)
    #[arg(long, global = true, env = "VAULT_API")]
    api: Option<String>,

    #[command(subcommand)]
    command: Command,
}

#[derive(Clone, Copy, ValueEnum)]
enum Vis {
    Private,
    Public,
    Passphrase,
}

impl From<Vis> for Visibility {
    fn from(v: Vis) -> Self {
        match v {
            Vis::Private => Visibility::Private,
            Vis::Public => Visibility::Public,
            Vis::Passphrase => Visibility::Passphrase,
        }
    }
}

#[derive(Subcommand)]
enum Command {
    /// Create an account. Prints the number and the 24-word recovery phrase once.
    Signup {
        #[arg(long)]
        passphrase_file: Option<PathBuf>,
    },
    /// Log in and store a session token (no keys are stored).
    Login {
        /// Account number, e.g. "4827 3910 5649 0182" (spaces are fine).
        account: Vec<String>,
        #[arg(long)]
        passphrase_file: Option<PathBuf>,
    },
    /// Forget the stored session token.
    Logout,
    /// Confirm 18+ and fetch the portal key.
    Gate,
    /// Show the account behind the current session.
    Whoami,
    /// List files.
    Ls,
    /// Encrypt and upload a file.
    Put {
        file: PathBuf,
        #[arg(long, value_enum, default_value_t = Vis::Private)]
        visibility: Vis,
        #[arg(long)]
        mime: Option<String>,
        #[arg(long)]
        passphrase_file: Option<PathBuf>,
    },
    /// Decrypt a file to stdout (pipe into mpv/ffplay).
    Cat {
        file_id: String,
        #[arg(long)]
        passphrase_file: Option<PathBuf>,
    },
    /// Decrypt a file to a path.
    Get {
        file_id: String,
        out: PathBuf,
        #[arg(long)]
        passphrase_file: Option<PathBuf>,
    },
}

fn base(cli: &Cli) -> String {
    cli.api
        .clone()
        .or_else(|| std::env::var("VAULT_API").ok())
        .unwrap_or_else(|| "http://127.0.0.1:8080".to_string())
}

fn passphrase(file: Option<&std::path::Path>) -> String {
    if let Some(path) = file {
        return std::fs::read_to_string(path)
            .unwrap_or_else(|e| die(&format!("reading {}: {e}", path.display())))
            .trim_end_matches(['\n', '\r'])
            .to_string();
    }
    if let Ok(p) = std::env::var("VAULT_PASSPHRASE") {
        return p;
    }
    rpassword::prompt_password("passphrase: ")
        .unwrap_or_else(|e| die(&format!("reading passphrase: {e}")))
}

fn die(msg: &str) -> ! {
    eprintln!("error: {msg}");
    std::process::exit(1);
}

fn main() {
    let cli = Cli::parse();
    let api_base = base(&cli);

    let outcome: Result<(), String> = match &cli.command {
        Command::Signup { passphrase_file } => {
            let pass = passphrase(passphrase_file.as_deref());
            vault_cli::signup(&api_base, &pass)
                .map(|created| print_created(&created))
                .map_err(|e| e.to_string())
        }
        Command::Login {
            account,
            passphrase_file,
        } => {
            let digits = match vault_core::account::AccountNumber::parse(&account.join(" ")) {
                Ok(a) => a.digits(),
                Err(e) => die(&e.to_string()),
            };
            let pass = passphrase(passphrase_file.as_deref());
            vault_cli::login(&api_base, &digits, &pass)
                .map(|s| {
                    println!(
                        "logged in as {}",
                        vault_core::account::AccountNumber::parse(&s.digits)
                            .map(|a| a.formatted())
                            .unwrap_or(s.digits.clone())
                    );
                    println!(
                        "session stored at {} (token only, no keys)",
                        Session::path().display()
                    );
                })
                .map_err(|e| e.to_string())
        }
        Command::Logout => Session::clear()
            .map(|_| println!("session cleared"))
            .map_err(|e| e.to_string()),
        Command::Gate => with_session(|s| {
            let g = Api::from_session(s).gate().map_err(|e| e.to_string())?;
            println!("18+ confirmed at {}", g.gate_at);
            if g.portal_key.is_some() {
                println!("portal key received (held in memory only)");
            }
            Ok(())
        }),
        Command::Whoami => with_session(|s| {
            let me = Api::from_session(s).me().map_err(|e| e.to_string())?;
            println!("account     {}", me.account_number);
            println!("fingerprint {}", me.fingerprint);
            println!("tier        {:?}", me.tier);
            println!(
                "storage     {} / {} bytes",
                me.storage_used, me.storage_quota
            );
            println!("gate        {}", me.gate_passed);
            println!("strikes     {}  banned {}", me.strikes, me.ban_flag);
            Ok(())
        }),
        Command::Ls => with_session(|s| {
            let list = Api::from_session(s).list().map_err(|e| e.to_string())?;
            if list.files.is_empty() {
                println!("no files");
            }
            for f in list.files {
                println!(
                    "{:34} {:24} {:>12}  {:?} {:?}",
                    f.file_id, f.mime, f.size, f.visibility, f.status
                );
            }
            Ok(())
        }),
        Command::Put {
            file,
            visibility,
            mime,
            passphrase_file,
        } => with_session(|s| {
            let pass = passphrase(passphrase_file.as_deref());
            let api = Api::from_session(s);
            let mime = mime.clone().unwrap_or_else(|| vault_cli::guess_mime(file));
            let up = vault_cli::upload(&api, s, file, (*visibility).into(), mime, &pass)
                .map_err(|e| e.to_string())?;
            println!(
                "stored {} ({} bytes plaintext, {} bytes ciphertext)",
                up.file_id, up.plaintext_len, up.ciphertext_len
            );
            Ok(())
        }),
        Command::Cat {
            file_id,
            passphrase_file,
        } => with_session(|s| {
            let pass = passphrase(passphrase_file.as_deref());
            let api = Api::from_session(s);
            let mut out = std::io::stdout().lock();
            let n =
                vault_cli::fetch(&api, s, file_id, &pass, &mut out).map_err(|e| e.to_string())?;
            out.flush().ok();
            eprintln!("decrypted {n} bytes");
            Ok(())
        }),
        Command::Get {
            file_id,
            out,
            passphrase_file,
        } => with_session(|s| {
            let pass = passphrase(passphrase_file.as_deref());
            let api = Api::from_session(s);
            let mut f = std::fs::File::create(out).map_err(|e| e.to_string())?;
            let n = vault_cli::fetch(&api, s, file_id, &pass, &mut f).map_err(|e| e.to_string())?;
            println!("wrote {n} bytes to {}", out.display());
            Ok(())
        }),
    };

    if let Err(e) = outcome {
        die(&e);
    }
}

fn with_session<F>(f: F) -> Result<(), String>
where
    F: FnOnce(&Session) -> Result<(), String>,
{
    let session = Session::load().map_err(|e| e.to_string())?;
    f(&session)
}

fn print_created(created: &vault_cli::Created) {
    println!();
    println!("  account number   {}", created.formatted);
    println!("  fingerprint      {}", created.fingerprint);
    println!();
    println!("  recovery phrase (write this down, it is the only way back in):");
    for row in created.words.chunks(4) {
        println!("    {}", row.join(" "));
    }
    println!();
    println!("  Nobody can recover this for you. Losing both = losing the vault.");
}

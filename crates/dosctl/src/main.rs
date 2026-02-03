use clap::{Parser, Subcommand};
use dos_client::{ConfigFile, DosClient, ShareConfig};
use dos_core::ClientInfo;
use std::path::PathBuf;

#[derive(Parser)]
#[command(name="dosctl", version="0.1.0", about="DOS command-line client")]
struct Cli {
    /// Config file path
    #[arg(long, default_value = "dos_shares.json")]
    config: PathBuf,

    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    Join {
        #[arg(long)]
        base_url: String,
        #[arg(long)]
        share: String,
        #[arg(long)]
        password: String,
        #[arg(long, default_value="dosctl")]
        device: String,
    },
    Shares,
    Ls {
        #[arg(long)]
        base_url: String,
        #[arg(long)]
        token: String,
        #[arg(long, default_value="/")]
        path: String,
    },
    Cat {
        #[arg(long)]
        base_url: String,
        #[arg(long)]
        token: String,
        #[arg(long)]
        path: String,
    },
    Put {
        #[arg(long)]
        base_url: String,
        #[arg(long)]
        token: String,
        #[arg(long)]
        local: PathBuf,
        #[arg(long)]
        remote: String,
    },
    Get {
        #[arg(long)]
        base_url: String,
        #[arg(long)]
        token: String,
        #[arg(long)]
        remote: String,
        #[arg(long)]
        local: PathBuf,
    },
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    match cli.cmd {
        Cmd::Join { base_url, share, password, device } => {
            let client = DosClient::new(&base_url);
            let resp = client
                .join(
                    &share,
                    &password,
                    ClientInfo {
                        name: "dosctl".into(),
                        version: "0.1.0".into(),
                        device,
                    },
                )
                .await?;

            println!("token={}", resp.token);
            println!("share_id={}", resp.share_id);

            // Persist
            let mut cfg = load_cfg(&cli.config).unwrap_or_default();
            cfg.shares.push(ShareConfig {
                base_url,
                share,
                token: resp.token,
            });
            save_cfg(&cli.config, &cfg)?;
        }
        Cmd::Shares => {
            let cfg = load_cfg(&cli.config).unwrap_or_default();
            if cfg.shares.is_empty() {
                println!("(no shares saved)");
            } else {
                for (i, s) in cfg.shares.iter().enumerate() {
                    println!("[{}] {} {} token={}", i, s.base_url, s.share, s.token);
                }
            }
        }
        Cmd::Ls { base_url, token, path } => {
            let client = DosClient::new(&base_url).with_token(token);
            let resp = client.list(&path).await?;
            for e in resp.entries {
                let k = match e.kind { dos_core::NodeKind::Dir => "DIR ", dos_core::NodeKind::File => "FILE" };
                let sz = e.size.unwrap_or(0);
                println!("{k} {:>10} {}", sz, e.name);
            }
        }
        Cmd::Cat { base_url, token, path } => {
            let client = DosClient::new(&base_url).with_token(token);
            let st = client.stat(&path).await?;
            let size = st.size.unwrap_or(0);
            let data = client.read_range(&path, 0, size).await?;
            print!("{}", String::from_utf8_lossy(&data));
        }
        Cmd::Put { base_url, token, local, remote } => {
            let client = DosClient::new(&base_url).with_token(token);
            let data = tokio::fs::read(&local).await?;
            client.upload_put_all(&remote, &data).await?;
            println!("ok");
        }
        Cmd::Get { base_url, token, remote, local } => {
            let client = DosClient::new(&base_url).with_token(token);
            let st = client.stat(&remote).await?;
            let size = st.size.unwrap_or(0);
            let data = client.read_range(&remote, 0, size).await?;
            tokio::fs::write(&local, &data).await?;
            println!("ok");
        }
    }

    Ok(())
}

fn load_cfg(path: &PathBuf) -> Option<ConfigFile> {
    let s = std::fs::read_to_string(path).ok()?;
    serde_json::from_str(&s).ok()
}

fn save_cfg(path: &PathBuf, cfg: &ConfigFile) -> anyhow::Result<()> {
    let s = serde_json::to_string_pretty(cfg)?;
    std::fs::write(path, s)?;
    Ok(())
}

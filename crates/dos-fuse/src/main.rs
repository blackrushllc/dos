#[cfg(not(windows))]
mod fuse_fs;

#[cfg(not(windows))]
use fuse_fs::DosFuse;

#[cfg(not(windows))]
use dos_client::DosClient;

#[cfg(not(windows))]
use clap::Parser;

#[cfg(not(windows))]
use std::path::PathBuf;

#[cfg(not(windows))]
#[derive(Parser)]
#[command(name="dos-fuse", about="DOS FUSE mount (Linux)")]
struct Args {
    #[arg(long)]
    base_url: String,
    #[arg(long)]
    token: String,
    #[arg(long, default_value="/")]
    remote_root: String,
    #[arg(long)]
    mountpoint: PathBuf,
}

#[cfg(not(windows))]
fn main() -> anyhow::Result<()> {
    let args = Args::parse();
    let client = DosClient::new(args.base_url).with_token(args.token);

    let fs = DosFuse::new(client, args.remote_root);
    let options = vec![
        fuser::MountOption::RO,
        fuser::MountOption::FSName("dos".to_string()),
        fuser::MountOption::DefaultPermissions,
    ];

    fuser::mount2(fs, &args.mountpoint, &options)?;
    Ok(())
}

#[cfg(windows)]
fn main() {
    eprintln!("Error: dos-fuse is only supported on Linux/macOS.");
    eprintln!("On Windows, please use the REST API or the native Windows client (to be implemented).");
    std::process::exit(1);
}

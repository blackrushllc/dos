mod fuse_fs;

use clap::Parser;
use dos_client::DosClient;
use fuse_fs::DosFuse;
use std::path::PathBuf;

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

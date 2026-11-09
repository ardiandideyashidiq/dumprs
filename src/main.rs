use anyhow::Result;
use clap::Parser;
use std::env;
use std::path::PathBuf;

use ::dumprs::utils::progress::init_logging;
use ::dumprs::{dumprs, DumpOptions};

#[derive(Parser, Debug)]
#[command(name = "dumprs", about = "Dumprs - High-performance Android firmware extractor")]
struct Args {
    /// Path to a device OTA or firmware archive
    #[arg(value_name = "FILE")]
    file: PathBuf,

    /// Custom output folder
    #[arg(short, long, value_name = "OUTPUT")]
    output: Option<PathBuf>,

    /// Retain temporary directories for debugging
    #[arg(short, long)]
    debug: bool,

    /// Skip Step 1 (reuse existing temp_extracted_archive)
    #[arg(long)]
    skip_extract: bool,

    /// Skip Step 2 (reuse existing temp_raw_images)
    #[arg(long)]
    skip_prepare: bool,

    /// Resume from existing temporary directories without re-extracting
    #[arg(short, long)]
    resume: bool,

    /// Extract only specified partition(s) (e.g. -p system -p vendor)
    #[arg(short, long, value_name = "PARTITION")]
    partition: Vec<String>,
}

fn main() -> Result<()> {
    let args = Args::parse();

    init_logging();

    let output = match args.output {
        Some(out) => out,
        None => {
            let stem = args
                .file
                .file_stem()
                .and_then(|s| s.to_str())
                .unwrap_or("dump");
            env::current_dir()?.join(stem)
        }
    };

    let options = DumpOptions {
        debug: args.debug,
        skip_extract: args.skip_extract,
        skip_prepare: args.skip_prepare,
        resume: args.resume,
        partitions: args.partition,
    };

    let _output_path = dumprs(&args.file, &output, &options)?;

    Ok(())
}

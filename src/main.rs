use anyhow::Result;
use clap::Parser;
use std::env;
use std::path::PathBuf;
use tracing_indicatif::IndicatifWriter;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;
use tracing_subscriber::EnvFilter;

use ::dumprs::utils::progress::get_multi_progress;
use ::dumprs::{dumprs, DumpOptions};

#[derive(Parser, Debug)]
#[command(name = "dumprs", about = "Dumprs - Android firmware extractor")]
struct Args {
    /// Path to a device OTA
    #[arg(value_name = "FILE")]
    file: PathBuf,

    /// Custom output folder
    #[arg(short, long, value_name = "OUTPUT")]
    output: Option<PathBuf>,

    /// Enable verbose output
    #[arg(short, long)]
    verbose: bool,

    /// Enable debugging features (retains temporary directories)
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

fn setup_logging(verbose: bool) {
    let filter = if let Ok(rust_log) = env::var("RUST_LOG") {
        EnvFilter::new(rust_log)
    } else if verbose {
        EnvFilter::new("dumprs=debug,info")
    } else {
        EnvFilter::new("dumprs=info,warn")
    };

    let mp = get_multi_progress().clone();
    let writer = IndicatifWriter::<tracing_indicatif::writer::Stderr>::new(mp);

    tracing_subscriber::registry()
        .with(
            tracing_subscriber::fmt::layer()
                .with_writer(writer)
                .with_target(false)
                .without_time(),
        )
        .with(filter)
        .init();
}

fn main() -> Result<()> {
    let args = Args::parse();

    setup_logging(args.verbose || args.debug);

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

    let output_path = dumprs(&args.file, &output, &options)?;

    println!("\nDone! You can find the dump in {}", output_path.display());

    Ok(())
}

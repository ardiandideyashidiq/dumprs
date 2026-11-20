use anyhow::{Result, anyhow};
use clap::{Args as ClapArgs, Parser, Subcommand};
use std::env;
use std::path::PathBuf;

use ::dumprs::formats::erofs_writer::{ErofsRepackOptions, repack_erofs};
use ::dumprs::utils::fs_metadata::{FilesystemType, FsMetadataOptions, GenerationMode};
use ::dumprs::utils::progress::init_logging;
use ::dumprs::{DumpOptions, dumprs};

#[derive(Parser, Debug)]
#[command(
    name = "dumprs",
    about = "Dumprs - High-performance Android firmware extractor and repacker"
)]
struct Args {
    #[command(subcommand)]
    command: Option<Commands>,

    /// Path to a device OTA or firmware archive
    #[arg(value_name = "FILE")]
    file: Option<PathBuf>,

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

    /// Do not generate boot/kernel artifacts (AVB, IKconfig, DTB/DTS)
    #[arg(long)]
    skip_boot_artifacts: bool,

    /// Extract only specified partition(s) (e.g. -p system -p vendor)
    #[arg(short, long, value_name = "PARTITION")]
    partition: Vec<String>,

    /// Emit fs_config and file_contexts sidecars for extracted partitions
    #[arg(long)]
    emit_fs_metadata: bool,

    /// Filesystem conventions for sidecar generation [ext4, erofs, f2fs]
    #[arg(
        long,
        value_name = "FSTYPE",
        default_value = "ext4",
        requires = "emit_fs_metadata"
    )]
    fs_metadata_fstype: String,

    /// Restrict sidecar generation to bin/ entries
    #[arg(long, requires = "emit_fs_metadata")]
    fs_metadata_bin_only: bool,

    /// Override vendor/odm bin/ SELinux context
    #[arg(long, value_name = "CONTEXT", requires = "emit_fs_metadata")]
    fs_metadata_vbin: Option<String>,

    /// Override system bin/ SELinux context
    #[arg(long, value_name = "CONTEXT", requires = "emit_fs_metadata")]
    fs_metadata_sbin: Option<String>,

    /// Root directory for generated config files
    #[arg(long, value_name = "DIR", requires = "emit_fs_metadata")]
    fs_metadata_dir: Option<PathBuf>,

    /// Count sidecar entries without writing files
    #[arg(long, requires = "emit_fs_metadata")]
    fs_metadata_dry_run: bool,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Repack an extracted partition directory into a filesystem image
    Repack(RepackArgs),
}

#[derive(ClapArgs, Debug)]
struct RepackArgs {
    /// Directory containing the extracted partition tree
    #[arg(short, long, value_name = "DIR")]
    input: PathBuf,

    /// Image file to write
    #[arg(short, long, value_name = "IMAGE")]
    output: PathBuf,

    /// Partition name used to interpret sidecar paths
    #[arg(long, default_value = "system")]
    partition: String,

    /// fs_config sidecar from extraction
    #[arg(long, value_name = "FILE")]
    fs_config: Option<PathBuf>,

    /// file_contexts sidecar from extraction
    #[arg(long, value_name = "FILE")]
    file_contexts: Option<PathBuf>,

    /// Block size as power of two (12 = 4096 bytes)
    #[arg(long, default_value_t = 12)]
    blkszbits: u8,
}

fn main() -> Result<()> {
    let args = Args::parse();
    init_logging();

    if let Some(Commands::Repack(repack)) = args.command {
        return run_repack(repack);
    }

    let file = args.file.ok_or_else(|| anyhow!("missing FILE argument"))?;
    let output = match args.output {
        Some(out) => out,
        None => {
            let stem = file.file_stem().and_then(|s| s.to_str()).unwrap_or("dump");
            env::current_dir()?.join(stem)
        }
    };

    let fs_metadata = args
        .emit_fs_metadata
        .then(|| -> Result<FsMetadataOptions> {
            Ok(FsMetadataOptions {
                fstype: FilesystemType::parse(&args.fs_metadata_fstype)?,
                mode: if args.fs_metadata_bin_only {
                    GenerationMode::BinOnly
                } else {
                    GenerationMode::All
                },
                vendor_bin_context: args.fs_metadata_vbin.clone(),
                system_bin_context: args.fs_metadata_sbin.clone(),
                dry_run: args.fs_metadata_dry_run,
                config_root: args.fs_metadata_dir.clone(),
            })
        })
        .transpose()?;

    let options = DumpOptions {
        debug: args.debug,
        skip_extract: args.skip_extract,
        skip_prepare: args.skip_prepare,
        resume: args.resume,
        skip_boot_artifacts: args.skip_boot_artifacts,
        partitions: args.partition,
        fs_metadata,
    };

    let _output_path = dumprs(&file, &output, &options)?;
    Ok(())
}

fn run_repack(args: RepackArgs) -> Result<()> {
    let options = ErofsRepackOptions {
        input: args.input,
        output: args.output.clone(),
        partition: args.partition,
        fs_config: args.fs_config,
        file_contexts: args.file_contexts,
        blkszbits: args.blkszbits,
    };
    let size = repack_erofs(&options)?;
    println!("Repacked {} ({} bytes)", args.output.display(), size);
    Ok(())
}

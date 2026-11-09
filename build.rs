use prost_build::Config;
use prost_types::FileDescriptorSet;
use std::fs;
use std::path::Path;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("cargo:rerun-if-changed=update_metadata.desc");
    let desc_path = Path::new("update_metadata.desc");
    if desc_path.exists() {
        let bytes = fs::read(desc_path)?;
        let fds = <FileDescriptorSet as prost::Message>::decode(&bytes[..])?;
        let mut config = Config::new();
        config.compile_fds(fds)?;
    }
    Ok(())
}

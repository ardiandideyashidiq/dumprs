use flate2::read::GzDecoder;
use std::collections::HashMap;
use std::fs::{self, File};
use std::io::{Read, Seek};
use std::path::{Path, PathBuf};
use walkdir::WalkDir;

#[derive(Debug, Clone, Default)]
pub struct DeviceInfo {
    pub description: Option<String>,
    pub brand: Option<String>,
    pub model: Option<String>,
    pub platform: Option<String>,
    pub cpu_abilist: Option<String>,
    pub is_ab: Option<bool>,
    pub treble_support: Option<bool>,
    pub screen_density: Option<String>,
    pub android_version: Option<String>,
    pub android_build: Option<String>,
    pub tran_os_build: Option<String>,
    pub tran_os_version: Option<String>,
    pub custom_os_name: Option<String>,
    pub custom_os_version: Option<String>,
    pub security_patch: Option<String>,
    pub kernel_version: Option<String>,
    pub fingerprint: Option<String>,
    // Android device tree / makefile configuration properties
    pub device_codename: Option<String>,
    pub product_brand: Option<String>,
    pub product_model: Option<String>,
    pub manufacturer: Option<String>,
    pub gms_clientid_base: Option<String>,
}

#[derive(Default)]
struct PropStore {
    // prop_name -> list of (partition_context, value)
    props: HashMap<String, Vec<(String, String)>>,
}

impl PropStore {
    fn insert(&mut self, partition: &str, key: &str, value: &str) {
        self.props
            .entry(key.to_string())
            .or_default()
            .push((partition.to_string(), value.to_string()));
    }

    fn get(&self, prop_name: &str) -> Option<&str> {
        self.props
            .get(prop_name)
            .and_then(|list| list.first().map(|(_, v)| v.as_str()))
    }

    fn get_any(&self, prop_names: &[&str]) -> Option<&str> {
        for &name in prop_names {
            if let Some(val) = self.get(name).filter(|v| !v.is_empty()) {
                return Some(val);
            }
        }
        None
    }

    fn get_in_partition(&self, partition_pattern: &str, prop_name: &str) -> Option<&str> {
        if let Some(list) = self.props.get(prop_name) {
            for (part, val) in list {
                if (part == partition_pattern || part.contains(partition_pattern))
                    && !val.is_empty()
                {
                    return Some(val.as_str());
                }
            }
        }
        None
    }

    fn load_file(&mut self, path: &Path, partition: &str) {
        if let Ok(content) = fs::read_to_string(path) {
            for line in content.lines() {
                let trimmed = line.trim();
                if trimmed.is_empty() || trimmed.starts_with('#') {
                    continue;
                }
                if let Some((k, v)) = trimmed.split_once('=') {
                    let key = k.trim();
                    let val = v.trim();
                    if !key.is_empty() && !val.is_empty() {
                        self.insert(partition, key, val);
                    }
                }
            }
        }
    }
}

impl DeviceInfo {
    pub fn from_dump_dir(dump_dir: &Path) -> Self {
        let mut store = PropStore::default();

        // 1. Check known build.prop locations in priority order
        let known_locations = [
            ("system", "system/system/build.prop"),
            ("system", "system/build.prop"),
            ("system", "system/etc/build.prop"),
            ("vendor", "vendor/build.prop"),
            ("vendor", "vendor/etc/build.prop"),
            ("product", "product/build.prop"),
            ("product", "product/etc/build.prop"),
            ("system_ext", "system_ext/build.prop"),
            ("system_ext", "system_ext/etc/build.prop"),
            ("odm", "odm/build.prop"),
            ("odm", "odm/etc/build.prop"),
            ("tr_manifest", "tr_manifest/build.prop"),
            ("tr_product", "tr_product/build.prop"),
            ("tr_region", "tr_region/build.prop"),
            ("my_manifest", "my_manifest/build.prop"),
            ("my_product", "my_product/build.prop"),
        ];

        let mut checked_paths = Vec::new();
        for (part, rel_path) in &known_locations {
            let full_path = dump_dir.join(rel_path);
            if full_path.is_file() {
                store.load_file(&full_path, part);
                checked_paths.push(full_path);
            }
        }

        // 2. Discover any additional *.prop files (up to depth 4, skipping temp directories)
        let walker = WalkDir::new(dump_dir)
            .max_depth(4)
            .into_iter()
            .filter_entry(|e| {
                if e.depth() == 1 && e.file_type().is_dir() {
                    let name = e.file_name();
                    name != "temp_extracted_archive" && name != "temp_raw_images"
                } else {
                    true
                }
            });

        for entry in walker.filter_map(|e| e.ok()) {
            if entry.file_type().is_file() {
                let p = entry.path();
                if p.extension().map(|ext| ext == "prop").unwrap_or(false)
                    && !checked_paths.contains(&p.to_path_buf())
                {
                    let partition = p
                        .strip_prefix(dump_dir)
                        .ok()
                        .and_then(|rel| rel.components().next())
                        .and_then(|c| c.as_os_str().to_str())
                        .unwrap_or("unknown");
                    store.load_file(p, partition);
                }
            }
        }

        // Parse Fingerprint
        let fingerprint = store
            .get_any(&[
                "ro.product.build.fingerprint",
                "ro.build.fingerprint",
                "ro.vendor.build.fingerprint",
                "ro.system.build.fingerprint",
                "ro.bootimage.build.fingerprint",
                "ro.tr_product.build.fingerprint",
                "ro.tr_region.build.fingerprint",
            ])
            .map(String::from);

        // Parse Brand
        let brand = store
            .get_any(&[
                "ro.product.vendor.brand",
                "ro.product.brand",
                "ro.product.system.brand",
                "ro.product.product.brand",
                "ro.product.odm.brand",
                "ro.product.manufacturer",
            ])
            .or_else(|| fingerprint.as_deref().and_then(|fp| fp.split('/').next()))
            .map(String::from);

        // Parse Model
        let model = store
            .get_any(&[
                "ro.product.vendor.model",
                "ro.product.model",
                "ro.product.product.model",
                "ro.product.system.model",
                "ro.product.odm.model",
                "ro.product.product.device",
                "ro.product.vendor.device",
            ])
            .map(|s| s.replace(' ', "-"))
            .or_else(|| {
                fingerprint.as_deref().and_then(|fp| {
                    let part = fp.split('/').nth(2)?;
                    Some(part.split(':').next()?.replace(' ', "-"))
                })
            });

        // Parse Description
        let description = store
            .get_any(&[
                "ro.vendor.build.description",
                "ro.product.build.description",
                "ro.build.description",
                "ro.system.build.description",
            ])
            .map(String::from)
            .or_else(|| {
                // Synthesize from components if build.description is missing
                let brand_str = brand.as_deref().unwrap_or("");
                let model_str = model.as_deref().unwrap_or("");
                let rel = store.get("ro.build.version.release").unwrap_or("");
                let id = store.get("ro.build.id").unwrap_or("");
                let inc = store.get("ro.build.version.incremental").unwrap_or("");
                let tags = store.get("ro.build.tags").unwrap_or("release-keys");
                if !brand_str.is_empty() && !model_str.is_empty() {
                    Some(
                        format!("{brand_str}-{model_str} {rel} {id} {inc} {tags}")
                            .trim()
                            .to_string(),
                    )
                } else {
                    None
                }
            });

        // Parse Platform
        let platform = store
            .get_any(&[
                "ro.board.platform",
                "ro.vendor.mediatek.platform",
                "ro.hardware",
                "ro.boot.hardware",
            ])
            .map(|s| {
                let lower = s.to_ascii_lowercase();
                if lower.starts_with("mt")
                    || lower.starts_with("sm")
                    || lower.starts_with("sdm")
                    || lower.starts_with("msm")
                    || lower.starts_with("qcom")
                    || lower.starts_with("exynos")
                    || lower.starts_with("sc")
                {
                    s.to_ascii_uppercase()
                } else {
                    s.to_string()
                }
            });

        // Parse Android build & version
        let android_build = store.get("ro.build.id").map(String::from);
        let android_version = store.get("ro.build.version.release").map(String::from);

        // Parse CPU abilist
        let cpu_abilist = store
            .get_any(&[
                "ro.product.cpu.abilist",
                "ro.vendor.product.cpu.abilist",
                "ro.product.cpu.abi",
            ])
            .map(String::from);

        // Parse A/B & Treble
        let is_ab = store
            .get("ro.build.ab_update")
            .map(|v| v.eq_ignore_ascii_case("true") || v == "1")
            .or_else(|| {
                // If payload.bin or slot-suffixes are used
                if dump_dir.join("payload.bin").exists() {
                    Some(true)
                } else {
                    None
                }
            });

        let treble_support = store
            .get("ro.treble.enabled")
            .map(|v| v.eq_ignore_ascii_case("true") || v == "1");

        // Parse Screen density
        let screen_density = store
            .get_any(&["ro.sf.lcd_density", "ro.sf.lcd.density"])
            .map(String::from);

        // Parse Security patch
        let security_patch = store
            .get("ro.build.version.security_patch")
            .map(String::from);

        // Detect Transsion / custom OS
        let tran_os_version = store
            .get_any(&[
                "ro.tranos.version",
                "ro.tranos.version:product",
                "ro.tranos.version:tr_product",
            ])
            .map(String::from);

        let is_transsion = brand
            .as_deref()
            .map(|b| {
                let lower = b.to_ascii_lowercase();
                lower.contains("infinix")
                    || lower.contains("tecno")
                    || lower.contains("itel")
                    || lower.contains("transsion")
            })
            .unwrap_or(false)
            || tran_os_version.is_some()
            || dump_dir.join("tr_manifest").exists()
            || dump_dir.join("tr_product").exists();

        let tran_os_build = if is_transsion {
            store
                .get_in_partition("tr_manifest", "ro.build.display.id")
                .or_else(|| store.get_in_partition("tr_product", "ro.build.display.id"))
                .or_else(|| store.get_in_partition("tr_region", "ro.build.display.id"))
                .or_else(|| store.get_in_partition("product", "ro.build.display.id"))
                .or_else(|| store.get("ro.tr_product.build.display.id"))
                .or_else(|| store.get("ro.build.display.id"))
                .map(String::from)
        } else {
            None
        };

        let (custom_os_name, custom_os_version) = if is_transsion {
            (Some("TranOS".to_string()), tran_os_version.clone())
        } else if let Some(ver) = store.get_any(&[
            "ro.build.version.oplusrom.display",
            "ro.build.version.oplusrom",
        ]) {
            let brand_lower = brand.as_deref().unwrap_or("").to_ascii_lowercase();
            let name = if brand_lower.contains("realme") {
                "RealmeUI"
            } else if brand_lower.contains("oneplus") {
                "OxygenOS"
            } else {
                "ColorOS"
            };
            (Some(name.to_string()), Some(ver.to_string()))
        } else if let Some(ver) =
            store.get_any(&["ro.mi.os.version.incremental", "ro.miui.ui.version.name"])
        {
            (Some("HyperOS/MIUI".to_string()), Some(ver.to_string()))
        } else if let Some(ver) = store.get("ro.build.version.oneui") {
            (Some("One UI".to_string()), Some(ver.to_string()))
        } else if let Some(ver) = store.get_any(&["ro.vivo.os.version", "ro.vivo.rom.version"]) {
            (Some("Vivo OS".to_string()), Some(ver.to_string()))
        } else {
            (None, None)
        };

        // Extract Kernel Version from boot/kernel
        let kernel_version = extract_kernel_version(dump_dir);

        // Parse Android device tree / makefile configuration properties (matching aospdtgen / sebaubuntu_libs)
        let device_codename = store
            .get_any(&[
                "ro.product.device",
                "ro.product.system.device",
                "ro.product.vendor.device",
                "ro.product.product.device",
                "ro.product.system_ext.device",
                "ro.product.odm.device",
                "ro.build.product",
            ])
            .map(String::from)
            .or_else(|| {
                fingerprint.as_deref().and_then(|fp| {
                    let part = fp.split('/').nth(1)?;
                    part.split('-').next().map(String::from)
                })
            });

        let product_brand = store
            .get_any(&[
                "ro.product.brand",
                "ro.product.system.brand",
                "ro.product.vendor.brand",
                "ro.product.product.brand",
                "ro.product.odm.brand",
            ])
            .map(|s| s.to_ascii_lowercase())
            .or_else(|| brand.as_ref().map(|b| b.to_ascii_lowercase()));

        let product_model = store
            .get_any(&[
                "ro.product.model",
                "ro.product.system.model",
                "ro.product.vendor.model",
                "ro.product.product.model",
                "ro.product.odm.model",
            ])
            .map(String::from)
            .or_else(|| model.clone());

        let manufacturer = store
            .get_any(&[
                "ro.product.manufacturer",
                "ro.product.system.manufacturer",
                "ro.product.vendor.manufacturer",
                "ro.product.product.manufacturer",
                "ro.product.odm.manufacturer",
            ])
            .map(|s| {
                s.split_whitespace()
                    .next()
                    .unwrap_or(s)
                    .to_ascii_lowercase()
            })
            .or_else(|| product_brand.clone());

        let gms_clientid_base = store
            .get_any(&[
                "ro.com.google.clientidbase",
                "ro.com.google.clientidbase.ms",
                "ro.com.google.clientidbase.am",
                "ro.com.google.clientidbase.yt",
                "ro.com.google.clientidbase.gmm",
            ])
            .map(String::from)
            .or_else(|| manufacturer.as_ref().map(|m| format!("android-{m}")));

        Self {
            description,
            brand,
            model,
            platform,
            cpu_abilist,
            is_ab,
            treble_support,
            screen_density,
            android_version,
            android_build,
            tran_os_build,
            tran_os_version,
            custom_os_name,
            custom_os_version,
            security_patch,
            kernel_version,
            fingerprint,
            device_codename,
            product_brand,
            product_model,
            manufacturer,
            gms_clientid_base,
        }
    }

    /// Generates markdown documentation formatted for README.md matching DumprX / standard dump repositories.
    pub fn generate_readme(&self) -> String {
        let mut md = String::with_capacity(1024);
        md.push_str("## FIRMWARE DUMP\n");
        if let Some(desc) = &self.description {
            md.push_str(&format!("### {desc}\n\n"));
        } else {
            md.push('\n');
        }

        if let Some(v) = &self.brand {
            md.push_str(&format!("- Brand: {v}\n"));
        }
        if let Some(v) = &self.model {
            md.push_str(&format!("- Model: {v}\n"));
        }
        if let Some(v) = &self.platform {
            md.push_str(&format!("- Platform: {v}\n"));
        }
        if let Some(v) = &self.cpu_abilist {
            md.push_str(&format!("- CPU abilist: {v}\n"));
        }
        if let Some(v) = self.is_ab {
            md.push_str(&format!("- A/B device: {v}\n"));
        }
        if let Some(v) = self.treble_support {
            md.push_str(&format!("- Treble device: {v}\n"));
        }
        if let Some(v) = &self.screen_density {
            md.push_str(&format!("- Screen density: {v}\n"));
        }
        if let Some(v) = &self.android_version {
            md.push_str(&format!("- Android version: {v}\n"));
        }
        if let Some(v) = &self.android_build {
            md.push_str(&format!("- Android build: {v}\n"));
        }
        if let Some(v) = &self.tran_os_build {
            md.push_str(&format!("- TranOS build: {v}\n"));
        }
        if let Some(v) = &self.tran_os_version {
            md.push_str(&format!("- TranOS version: {v}\n"));
        } else if let (Some(name), Some(ver)) = (&self.custom_os_name, &self.custom_os_version) {
            md.push_str(&format!("- {name} version: {ver}\n"));
        }
        if let Some(v) = &self.security_patch {
            md.push_str(&format!("- Security patch: {v}\n"));
        }
        if let Some(v) = &self.kernel_version {
            md.push_str(&format!("- Kernel version: {v}\n"));
        }
        if let Some(v) = &self.fingerprint {
            md.push_str(&format!("- Fingerprint: {v}\n"));
        }

        if self.device_codename.is_some() || self.manufacturer.is_some() {
            md.push_str("\n### Android Device Tree Configuration\n```makefile\n");
            if let Some(v) = &self.device_codename {
                md.push_str(&format!("PRODUCT_DEVICE := {v}\n"));
            }
            if let Some(v) = &self.product_brand {
                md.push_str(&format!("PRODUCT_BRAND := {v}\n"));
            }
            if let Some(v) = &self.product_model {
                md.push_str(&format!("PRODUCT_MODEL := {v}\n"));
            }
            if let Some(v) = &self.manufacturer {
                md.push_str(&format!("PRODUCT_MANUFACTURER := {v}\n"));
            }
            if let Some(v) = &self.gms_clientid_base {
                md.push_str(&format!("\nPRODUCT_GMS_CLIENTID_BASE := {v}\n"));
            }
            md.push_str("```\n");
        }

        md
    }

    /// Render formatted markdown summary directly to the terminal using termimad.
    pub fn render_terminal(&self) {
        let readme = self.generate_readme();
        termimad::print_text(&readme);
    }
}

fn extract_kernel_version(dump_dir: &Path) -> Option<String> {
    let kernel_candidates: [PathBuf; 4] = [
        dump_dir.join("boot").join("kernel"),
        dump_dir.join("vendor_boot").join("kernel"),
        dump_dir.join("kernel"),
        dump_dir.join("boot.img"),
    ];

    for kp in &kernel_candidates {
        if kp.is_file() {
            if let Ok(mut file) = File::open(kp) {
                let mut magic = [0u8; 4];
                if file.read_exact(&mut magic).is_ok()
                    && file.seek(std::io::SeekFrom::Start(0)).is_ok()
                {
                    if magic[0..2] == [0x1f, 0x8b] {
                        let gz = GzDecoder::new(file);
                        if let Some(v) = scan_for_linux_version(gz) {
                            return Some(v);
                        }
                    } else if magic == [0x04, 0x22, 0x4d, 0x18] {
                        let lz4 = lz4_flex::frame::FrameDecoder::new(file);
                        if let Some(v) = scan_for_linux_version(lz4) {
                            return Some(v);
                        }
                    } else {
                        if let Some(v) = scan_for_linux_version(file) {
                            return Some(v);
                        }
                    }
                }
            }
        }
    }
    None
}

fn scan_for_linux_version<R: Read>(mut reader: R) -> Option<String> {
    const NEEDLE: &[u8] = b"Linux version ";
    let mut chunk = vec![0u8; 64 * 1024];
    let mut overlap = 0usize;
    let mut total_read = 0usize;
    const MAX_SCAN: usize = 32 * 1024 * 1024; // 32MB max scan budget

    while total_read < MAX_SCAN {
        let n = match reader.read(&mut chunk[overlap..]) {
            Ok(0) => break,
            Ok(n) => n,
            Err(_) => break,
        };
        total_read += n;
        let valid_len = overlap + n;
        let buf = &chunk[..valid_len];

        if let Some(pos) = buf.windows(NEEDLE.len()).position(|w| w == NEEDLE) {
            let start = pos + NEEDLE.len();
            let remainder = &buf[start..];
            let end = remainder
                .iter()
                .position(|&b| b.is_ascii_whitespace() || b == b'(' || b == 0)
                .unwrap_or(remainder.len().min(64));
            let ver_bytes = &remainder[..end];
            if !ver_bytes.is_empty() {
                let ver_str = String::from_utf8_lossy(ver_bytes).trim().to_string();
                if ver_str
                    .chars()
                    .next()
                    .map(|c| c.is_ascii_digit())
                    .unwrap_or(false)
                {
                    return Some(ver_str);
                }
            }
        }

        if valid_len > NEEDLE.len() {
            chunk.copy_within(valid_len - NEEDLE.len()..valid_len, 0);
            overlap = NEEDLE.len();
        } else {
            overlap = 0;
        }
    }
    None
}

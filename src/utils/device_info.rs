use flate2::read::GzDecoder;
use std::collections::HashMap;
use std::fs::{self, File};
use std::io::{Read, Seek};
use std::path::{Path, PathBuf};
use walkdir::WalkDir;

#[derive(Debug, Clone, Default)]
pub struct DeviceInfo {
    // Basic identifiers
    pub description: Option<String>,
    pub brand: Option<String>,
    pub model: Option<String>,

    // OEM Market Names
    pub transname: Option<String>,
    pub xiaominame: Option<String>,
    pub motoname: Option<String>,
    pub opname: Option<String>,

    // Hardware & Platform
    pub platform: Option<String>,
    pub cpu_abilist: Option<String>,
    pub display_info: Option<String>,
    pub rearcam_display: Option<String>,
    pub frontcam_display: Option<String>,
    pub charging: Option<String>,

    // Android & System Build
    pub android_version: Option<String>,
    pub first_api_level: Option<String>,
    pub android_build: Option<String>,
    pub display_build: Option<String>,

    // OEM OS builds & versions
    pub tran_os_name: Option<String>,
    pub tran_os_build: Option<String>,
    pub tran_os_version: Option<String>,
    pub oem_ui_name: Option<String>,
    pub oem_ui_version: Option<String>,
    pub miui_ver: Option<String>,
    pub oneui_ver: Option<String>,
    pub vivo_ver: Option<String>,

    // Metadata & Signatures
    pub security_patch: Option<String>,
    pub build_date: Option<String>,
    pub kernel_version: Option<String>,
    pub fingerprint: Option<String>,

    // Flags
    pub is_ab: Option<bool>,
    pub treble_support: Option<bool>,
    pub screen_density: Option<String>,

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

    fn get_scoped(&self, key: &str, partitions: &[&str]) -> Option<&str> {
        if let Some(list) = self.props.get(key) {
            for &desired_part in partitions {
                for (part, val) in list {
                    if (part == desired_part || part.contains(desired_part)) && !val.is_empty() {
                        return Some(val.as_str());
                    }
                }
            }
            for (_, val) in list {
                if !val.is_empty() {
                    return Some(val.as_str());
                }
            }
        }
        None
    }

    fn get_any(&self, prop_names: &[&str]) -> Option<&str> {
        for &name in prop_names {
            if let Some(val) = self.get(name).filter(|v| !v.is_empty()) {
                return Some(val);
            }
        }
        None
    }

    fn get_any_scoped(&self, items: &[(&str, &[&str])]) -> Option<&str> {
        for &(key, parts) in items {
            if let Some(val) = self.get_scoped(key, parts)
                && !val.is_empty()
            {
                return Some(val);
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
            ("my_manifest", "my_manifest/build.prop"),
            ("my_manifest", "my_manifest/etc/build.prop"),
            ("tr_manifest", "tr_manifest/build.prop"),
            ("tr_product", "tr_product/build.prop"),
            ("tr_region", "tr_region/build.prop"),
            ("odm", "odm/etc/build.prop"),
            ("odm", "odm/build.prop"),
            ("vendor/odm", "vendor/odm/etc/build.prop"),
            ("vendor/odm", "vendor/odm/build.prop"),
            ("my_product", "my_product/build.prop"),
            ("my_product", "my_product/etc/build.prop"),
            ("product", "product/build.prop"),
            ("product", "product/etc/build.prop"),
            ("system_ext", "system_ext/build.prop"),
            ("system_ext", "system_ext/etc/build.prop"),
            ("vendor", "vendor/build.prop"),
            ("vendor", "vendor/etc/build.prop"),
            ("system", "system/system/build.prop"),
            ("system", "system/build.prop"),
            ("system", "system/etc/build.prop"),
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
            .get_any_scoped(&[
                ("ro.build.fingerprint", &["my_manifest", "tr_manifest"]),
                ("ro.tr_product.build.fingerprint", &["tr_product"]),
                ("ro.product.build.fingerprint", &["product"]),
                ("ro.tr_region.build.fingerprint", &["tr_region"]),
                ("ro.build.fingerprint", &["system", "system/system"]),
                ("ro.vendor.build.fingerprint", &["vendor"]),
                ("ro.system.build.fingerprint", &["system", "system/system"]),
                ("ro.bootimage.build.fingerprint", &["vendor", "my_manifest"]),
            ])
            .map(String::from);

        // Parse Brand / Manufacturer
        let brand = store
            .get_any_scoped(&[
                (
                    "ro.product.odm.brand",
                    &["odm", "vendor/odm", "my_manifest"],
                ),
                ("ro.product.brand", &["system", "system/system", "vendor"]),
                (
                    "ro.product.brand.sub",
                    &[
                        "system/system/euclid/my_product",
                        "tr_region",
                        "tr_manifest",
                    ],
                ),
                ("ro.product.vendor.brand", &["vendor"]),
                ("ro.vendor.product.brand", &["vendor"]),
                (
                    "ro.product.system.brand",
                    &["vendor/euclid/*", "system", "system/system"],
                ),
                (
                    "ro.product.product.brand",
                    &["vendor/euclid/product", "product"],
                ),
                ("ro.product.system_ext.brand", &["system_ext"]),
                (
                    "ro.product.manufacturer",
                    &["system", "system/system", "vendor"],
                ),
            ])
            .or_else(|| fingerprint.as_deref().and_then(|fp| fp.split('/').next()))
            .map(String::from);

        let manufacturer_raw = store
            .get_any_scoped(&[
                (
                    "ro.product.odm.brand",
                    &["odm", "vendor/odm", "my_manifest"],
                ),
                (
                    "ro.product.manufacturer",
                    &["system", "system/system", "vendor"],
                ),
                ("ro.product.vendor.manufacturer", &["vendor"]),
                (
                    "ro.product.system.manufacturer",
                    &["system", "system/system"],
                ),
                ("ro.product.odm.manufacturer", &["odm", "vendor/odm"]),
                ("ro.product.brand", &["system", "system/system", "vendor"]),
            ])
            .or(brand.as_deref());

        // Parse Model / Codename
        let model = store
            .get_any_scoped(&[
                ("ro.product.odm.model", &["my_manifest"]),
                (
                    "ro.product.odm.device",
                    &["odm", "vendor/odm", "my_manifest"],
                ),
                ("ro.product.vendor.model", &["vendor"]),
                ("ro.product.model", &["system", "system/system", "product"]),
                ("ro.product.product.model", &["product"]),
                ("ro.product.product.device", &["product"]),
                ("ro.product.vendor.device", &["vendor"]),
                (
                    "ro.product.device",
                    &["vendor", "product", "system", "system/system"],
                ),
                ("ro.product.system.device", &["system", "system/system"]),
            ])
            .map(|s| s.replace(' ', "-"))
            .or_else(|| {
                fingerprint.as_deref().and_then(|fp| {
                    let part = fp.split('/').nth(2)?;
                    Some(part.split(':').next()?.replace(' ', "-"))
                })
            });

        // Transsion Name
        let transname = find_transname(dump_dir, &store, brand.as_deref());

        // Xiaomi Name
        let xiaominame = find_xiaominame(&store);

        // Moto Name
        let motoname = find_motoname(&store);

        // OP Name (Oppo / OnePlus)
        let opname = find_opname(&store, model.as_deref());

        // Base Android IDs
        let release = store
            .get_any_scoped(&[
                (
                    "ro.build.version.release",
                    &["system", "system/system", "vendor"],
                ),
                ("ro.vendor.build.version.release", &["vendor"]),
                (
                    "ro.system.build.version.release",
                    &["system", "system/system"],
                ),
            ])
            .map(String::from);

        let id = store
            .get_any_scoped(&[
                ("ro.build.id", &["system", "system/system", "vendor"]),
                ("ro.vendor.build.id", &["vendor"]),
                ("ro.system.build.id", &["system", "system/system"]),
            ])
            .map(String::from);

        let incremental = store
            .get_any_scoped(&[
                (
                    "ro.build.version.incremental",
                    &["my_manifest", "tr_manifest"],
                ),
                ("ro.tr_product.build.version.incremental", &["tr_product"]),
                ("ro.product.build.version.incremental", &["product"]),
                (
                    "ro.build.version.incremental",
                    &["system", "system/system", "vendor", "my_product"],
                ),
            ])
            .map(String::from)
            .or_else(|| {
                fingerprint.as_deref().and_then(|fp| {
                    let part = fp.split(':').nth(1)?;
                    part.split('/').nth(2).map(String::from)
                })
            });

        let tags = store
            .get_any_scoped(&[
                ("ro.build.tags", &["system", "system/system", "vendor"]),
                ("ro.vendor.build.tags", &["vendor"]),
                ("ro.system.build.tags", &["system", "system/system"]),
            ])
            .map(String::from);

        // Parse Description
        let raw_description = store.get_any_scoped(&[
            (
                "ro.vendor.build.description",
                &["vendor", "odm", "vendor/odm"],
            ),
            (
                "ro.product.build.description",
                &["product", "vendor/euclid/product", "system_ext"],
            ),
            (
                "ro.build.description",
                &["vendor", "odm", "product", "system", "system/system"],
            ),
            ("ro.system.build.description", &["system", "system/system"]),
        ]);

        let flavor = store
            .get_any_scoped(&[
                ("ro.build.flavor", &["system", "system/system", "vendor"]),
                ("ro.vendor.build.flavor", &["vendor"]),
                ("ro.system.build.flavor", &["system", "system/system"]),
            ])
            .map(String::from);

        let description = raw_description.map(String::from).or_else(|| {
            if let Some(inc) = incremental.as_ref() {
                let flv = flavor.as_deref().unwrap_or("");
                let rel = release.as_deref().unwrap_or("");
                let b_id = id.as_deref().unwrap_or("");
                let tag = tags.as_deref().unwrap_or("release-keys");
                Some(format!("{flv} {rel} {b_id} {inc} {tag}").trim().to_string())
            } else {
                model.clone()
            }
        });

        // Parse Platform & Chipset
        let raw_platform = store.get_any_scoped(&[
            ("ro.vendor.mediatek.platform", &["vendor"]),
            ("ro.board.platform", &["vendor", "system", "system/system"]),
            ("ro.hardware", &["system", "system/system"]),
            ("ro.boot.hardware", &["system", "system/system"]),
        ]);

        let platform_base = raw_platform.map(|s| {
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

        let chipset = find_chipset(dump_dir, &store);
        let platform = match (platform_base, chipset) {
            (Some(pb), Some(cs)) => Some(format!("{pb} ({cs})")),
            (Some(pb), None) => Some(pb),
            (None, Some(cs)) => Some(cs),
            (None, None) => None,
        };

        // Parse CPU abilist
        let cpu_abilist = store
            .get_any_scoped(&[
                ("ro.product.cpu.abilist", &["system", "system/system"]),
                ("ro.vendor.product.cpu.abilist", &["vendor"]),
                ("ro.product.cpu.abi", &["system", "system/system"]),
            ])
            .map(String::from);

        // Display Info
        let display_info = find_display_info(dump_dir, &store);

        // Parse A/B & Treble
        let is_ab = store
            .get_scoped("ro.build.ab_update", &["system", "system/system", "vendor"])
            .map(|v| v.eq_ignore_ascii_case("true") || v == "1")
            .or_else(|| {
                if dump_dir.join("payload.bin").exists() {
                    Some(true)
                } else {
                    None
                }
            });

        let treble_support = store
            .get_scoped("ro.treble.enabled", &["system", "system/system"])
            .map(|v| v.eq_ignore_ascii_case("true") || v == "1");

        let screen_density = store
            .get_scoped(
                "ro.sf.lcd_density",
                &["vendor", "system", "system/system", "odm"],
            )
            .map(String::from);

        // Detect Transsion
        let tran_os_ver_raw =
            store.get_any_scoped(&[("ro.tranos.version", &["product", "tr_product"])]);

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
            || transname.is_some()
            || tran_os_ver_raw.is_some()
            || dump_dir.join("tr_manifest").exists()
            || dump_dir.join("tr_product").exists();

        // Cameras & Charging
        let (rearcam_display, frontcam_display, charging) =
            find_camera_and_charging(dump_dir, &store, is_transsion);

        // First API level
        let first_api_level = store
            .get_any_scoped(&[
                (
                    "ro.product.first_api_level",
                    &[
                        "vendor",
                        "odm",
                        "vendor/odm",
                        "product",
                        "my_manifest",
                        "system",
                        "system/system",
                    ],
                ),
                ("ro.board.first_api_level", &["vendor", "odm", "vendor/odm"]),
                ("ro.board.api_level", &["vendor", "odm", "vendor/odm"]),
            ])
            .filter(|v| *v != "10000" && !v.is_empty())
            .map(String::from);

        // Display Build
        let raw_display_id = store.get_any_scoped(&[
            ("ro.build.display.id.show", &["my_manifest"]),
            (
                "ro.build.display.id",
                &[
                    "my_manifest",
                    "system",
                    "system/system",
                    "product",
                    "vendor",
                ],
            ),
        ]);

        let display_build = if let Some(did) = raw_display_id {
            let mut clean = did.trim();
            clean = clean.strip_suffix(" release-keys").unwrap_or(clean);
            clean = clean.strip_suffix(" test-keys").unwrap_or(clean);
            if let Some(t) = tags.as_deref() {
                clean = clean.strip_suffix(&format!(" {t}")).unwrap_or(clean);
            }
            if let Some(aid) = id.as_deref() {
                if clean != aid {
                    Some(did.to_string())
                } else {
                    None
                }
            } else {
                Some(did.to_string())
            }
        } else {
            None
        };

        // TranOS / Vendor UI names and builds
        let (tran_os_name, tran_os_build, tran_os_version) = if is_transsion {
            let tranos_type =
                store.get_scoped("ro.tranos.type", &["tr_product", "tr_manifest", "product"]);
            let os_name = match tranos_type.map(|t| t.to_ascii_lowercase()).as_deref() {
                Some("xos") => "XOS".to_string(),
                Some("hios") => "HiOS".to_string(),
                Some("itelos") => "itelOS".to_string(),
                _ => {
                    let brand_check = format!(
                        "{} {} {}",
                        manufacturer_raw.unwrap_or(""),
                        brand.as_deref().unwrap_or(""),
                        transname.as_deref().unwrap_or("")
                    )
                    .to_ascii_lowercase();
                    if brand_check.contains("infinix") {
                        "XOS".to_string()
                    } else if brand_check.contains("tecno") {
                        "HiOS".to_string()
                    } else if brand_check.contains("itel") {
                        "itelOS".to_string()
                    } else {
                        "TranOS".to_string()
                    }
                }
            };

            let xosid = store
                .get_any_scoped(&[
                    (
                        "ro.build.display.id",
                        &["tr_manifest", "tr_region", "tr_product", "product"],
                    ),
                    ("ro.tr_product.build.display.id", &["tr_product"]),
                ])
                .map(String::from);

            let ver = tran_os_ver_raw.map(|v| {
                let trimmed = v.trim();
                let lower = trimmed.to_ascii_lowercase();
                if lower.starts_with("xos")
                    || lower.starts_with("hios")
                    || lower.starts_with("itelos")
                    || lower.starts_with("tranos")
                {
                    trimmed
                        .trim_start_matches(|c: char| {
                            c.is_alphabetic() || c == '.' || c == '_' || c == '-'
                        })
                        .to_string()
                } else {
                    trimmed.to_string()
                }
            });

            (Some(os_name), xosid, ver)
        } else {
            (None, None, None)
        };

        // OEM UI versions
        let (oem_ui_name, oem_ui_version) = if !is_transsion {
            if let Some(ver) = store.get_any_scoped(&[
                (
                    "ro.build.version.oplusrom.display",
                    &["my_manifest", "my_product", "system_ext"],
                ),
                (
                    "ro.build.version.oplusrom",
                    &["my_manifest", "my_product", "system_ext"],
                ),
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
            } else {
                (None, None)
            }
        } else {
            (None, None)
        };

        let miui_ver = store
            .get_any_scoped(&[
                (
                    "ro.mi.os.version.incremental",
                    &["odm", "vendor/odm", "product", "system"],
                ),
                (
                    "ro.miui.ui.version.name",
                    &["odm", "vendor/odm", "product", "system"],
                ),
            ])
            .map(String::from);

        let oneui_ver = store
            .get_any_scoped(&[
                ("ro.build.version.oneui", &["product", "system"]),
                ("ro.build.version.sep", &["product", "system"]),
            ])
            .map(String::from);

        let vivo_ver = store
            .get_any_scoped(&[
                ("ro.vivo.os.build.display.id", &["product", "system"]),
                ("ro.vivo.os.version", &["product", "system"]),
            ])
            .map(String::from);

        let security_patch = store
            .get_scoped(
                "ro.build.version.security_patch",
                &["system", "system/system", "vendor"],
            )
            .map(String::from);

        let build_date = store
            .get_any_scoped(&[
                (
                    "ro.build.date",
                    &[
                        "tr_manifest",
                        "my_manifest",
                        "system",
                        "system/system",
                        "product",
                    ],
                ),
                ("ro.vendor.build.date", &["my_manifest", "vendor"]),
                ("ro.bootimage.build.date", &["my_manifest"]),
                ("ro.system.build.date", &["system", "system/system"]),
            ])
            .map(String::from);

        // Kernel Version from boot/kernel
        let kernel_version = extract_kernel_version(dump_dir);

        // Parse Android Device Tree makefile variables (matching aospdtgen & sebaubuntu_libs)
        let device_codename = store
            .get_any_scoped(&[
                (
                    "ro.product.device",
                    &["vendor", "product", "system", "system/system"],
                ),
                ("ro.product.vendor.device", &["vendor"]),
                ("ro.product.product.device", &["product"]),
                ("ro.product.odm.device", &["odm", "vendor/odm"]),
                ("ro.build.product", &["vendor", "system", "system/system"]),
            ])
            .filter(|d| {
                let lower = d.to_ascii_lowercase();
                !lower.contains("full-64") && !lower.starts_with("aosp_") && !lower.contains("gsi")
            })
            .map(String::from)
            .or_else(|| {
                // Check ro.product.vendor.name or product.name (e.g. X6812B-OP -> X6812B)
                store
                    .get_any_scoped(&[
                        ("ro.product.vendor.name", &["vendor"]),
                        ("ro.product.product.name", &["product"]),
                        ("ro.product.odm.name", &["odm", "vendor/odm"]),
                    ])
                    .and_then(|n| n.split('-').next().map(String::from))
            })
            .or_else(|| {
                fingerprint.as_deref().and_then(|fp| {
                    let part = fp.split('/').nth(1)?;
                    part.split('-').next().map(String::from)
                })
            })
            .map(|d| {
                let mut res = d.as_str();
                if let Some(b) = &brand {
                    if let Some(stripped) = res.strip_prefix(b) {
                        let candidate = stripped.trim_start_matches(['-', '_']);
                        if !candidate.is_empty() {
                            res = candidate;
                        }
                    } else if res
                        .to_ascii_lowercase()
                        .starts_with(&b.to_ascii_lowercase())
                    {
                        let candidate = res[b.len()..].trim_start_matches(['-', '_']);
                        if !candidate.is_empty() {
                            res = candidate;
                        }
                    }
                }
                res.to_string()
            });

        let product_brand = store
            .get_any_scoped(&[
                ("ro.product.brand", &["system", "system/system", "vendor"]),
                ("ro.product.vendor.brand", &["vendor"]),
                ("ro.product.product.brand", &["product"]),
                ("ro.product.odm.brand", &["odm", "vendor/odm"]),
            ])
            .map(|s| s.to_ascii_lowercase())
            .or_else(|| brand.as_ref().map(|b| b.to_ascii_lowercase()));

        let product_model = store
            .get_any_scoped(&[
                ("ro.product.model", &["system", "system/system", "product"]),
                ("ro.product.vendor.model", &["vendor"]),
                ("ro.product.product.model", &["product"]),
                ("ro.product.odm.model", &["odm", "vendor/odm"]),
            ])
            .map(String::from)
            .or_else(|| model.clone());

        let manufacturer = store
            .get_any_scoped(&[
                (
                    "ro.product.manufacturer",
                    &["system", "system/system", "vendor"],
                ),
                ("ro.product.vendor.manufacturer", &["vendor"]),
                ("ro.product.product.manufacturer", &["product"]),
                ("ro.product.odm.manufacturer", &["odm", "vendor/odm"]),
            ])
            .map(|s| {
                s.split_whitespace()
                    .next()
                    .unwrap_or(s)
                    .to_ascii_lowercase()
            })
            .or_else(|| product_brand.clone());

        let gms_clientid_base = store
            .get_any_scoped(&[
                (
                    "ro.com.google.clientidbase",
                    &["system", "system/system", "product", "vendor"],
                ),
                (
                    "ro.com.google.clientidbase.ms",
                    &["system", "system/system", "product", "vendor"],
                ),
                (
                    "ro.com.google.clientidbase.am",
                    &["system", "system/system", "product", "vendor"],
                ),
                (
                    "ro.com.google.clientidbase.yt",
                    &["system", "system/system", "product", "vendor"],
                ),
                (
                    "ro.com.google.clientidbase.gmm",
                    &["system", "system/system", "product", "vendor"],
                ),
            ])
            .map(String::from)
            .or_else(|| manufacturer.as_ref().map(|m| format!("android-{m}")));

        Self {
            description,
            brand,
            model,
            transname,
            xiaominame,
            motoname,
            opname,
            platform,
            cpu_abilist,
            display_info,
            rearcam_display,
            frontcam_display,
            charging,
            android_version: release,
            first_api_level,
            android_build: id,
            display_build,
            tran_os_name,
            tran_os_build,
            tran_os_version,
            oem_ui_name,
            oem_ui_version,
            miui_ver,
            oneui_ver,
            vivo_ver,
            security_patch,
            build_date,
            kernel_version,
            fingerprint,
            is_ab,
            treble_support,
            screen_density,
            device_codename,
            product_brand,
            product_model,
            manufacturer,
            gms_clientid_base,
        }
    }

    /// Generates markdown documentation formatted for README.md matching DumprX / standard dump repositories.
    pub fn generate_readme(&self) -> String {
        let mut md = String::with_capacity(2048);
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
        if let Some(v) = &self.transname {
            md.push_str(&format!("- Transsion name: {v}\n"));
        }
        if let Some(v) = &self.xiaominame {
            md.push_str(&format!("- Xiaomi name: {v}\n"));
        }
        if let Some(v) = &self.motoname {
            md.push_str(&format!("- Moto name: {v}\n"));
        }
        if let Some(v) = &self.opname {
            md.push_str(&format!("- OP name: {v}\n"));
        }
        if let Some(v) = &self.platform {
            md.push_str(&format!("- Platform: {v}\n"));
        }
        if let Some(v) = &self.cpu_abilist {
            md.push_str(&format!("- CPU abilist: {v}\n"));
        }
        if let Some(v) = &self.display_info {
            md.push_str(&format!("- Display: {v}\n"));
        }
        if let Some(v) = &self.rearcam_display {
            md.push_str(&format!("- Rear camera: {v}\n"));
        }
        if let Some(v) = &self.frontcam_display {
            md.push_str(&format!("- Front camera: {v}\n"));
        }
        if let Some(v) = &self.charging {
            md.push_str(&format!("- Charging: {v}\n"));
        }
        if let Some(v) = &self.android_version {
            md.push_str(&format!("- Android version: {v}\n"));
        }
        if let Some(v) = &self.first_api_level {
            md.push_str(&format!("- First API level: {v}\n"));
        }
        if let Some(v) = &self.android_build {
            md.push_str(&format!("- Android build: {v}\n"));
        }
        if let Some(v) = &self.display_build {
            md.push_str(&format!("- Display build: {v}\n"));
        }
        if let (Some(name), Some(id)) = (&self.tran_os_name, &self.tran_os_build) {
            md.push_str(&format!("- {name} build: {id}\n"));
        }
        if let Some(v) = &self.tran_os_version {
            md.push_str(&format!("- TranOS version: {v}\n"));
        }
        if let (Some(name), Some(ver)) = (&self.oem_ui_name, &self.oem_ui_version) {
            md.push_str(&format!("- {name} version: {ver}\n"));
        }
        if let Some(v) = &self.miui_ver {
            md.push_str(&format!("- HyperOS/MIUI version: {v}\n"));
        }
        if let Some(v) = &self.oneui_ver {
            md.push_str(&format!("- One UI version: {v}\n"));
        }
        if let Some(v) = &self.vivo_ver {
            md.push_str(&format!("- Vivo OS version: {v}\n"));
        }
        if let Some(v) = &self.security_patch {
            md.push_str(&format!("- Security patch: {v}\n"));
        }
        if let Some(v) = &self.build_date {
            md.push_str(&format!("- Build date: {v}\n"));
        }
        if let Some(v) = &self.kernel_version {
            md.push_str(&format!("- Kernel version: {v}\n"));
        }
        if let Some(v) = &self.fingerprint {
            md.push_str(&format!("- Fingerprint: {v}\n"));
        }

        // Additional flags if not included in display
        if let Some(v) = self.is_ab {
            md.push_str(&format!("- A/B device: {v}\n"));
        }
        if let Some(v) = self.treble_support {
            md.push_str(&format!("- Treble device: {v}\n"));
        }
        if self.display_info.is_none()
            && let Some(v) = &self.screen_density
        {
            md.push_str(&format!("- Screen density: {v}\n"));
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

fn find_transname(
    dump_dir: &Path,
    store: &PropStore,
    manufacturer: Option<&str>,
) -> Option<String> {
    if let Some(name) = store.get_scoped(
        "ro.product.product.tran.device.name.default",
        &["product", "tr_product"],
    ) && !name.is_empty()
    {
        return Some(name.to_string());
    }
    let wm1 = dump_dir.join("odm/etc/goldwatermark/configs/TranssionWM.json");
    let wm2 = dump_dir.join("odm/etc/asset/camera/goldwatermark/configs/TranssionWM.json");
    for (path, prepend_mfg) in [(wm1, false), (wm2, true)] {
        if let Ok(content) = fs::read_to_string(path)
            && let Some(pos) = content.find("\"TEXT_BRAND_NAME\": \"")
        {
            let start = pos + "\"TEXT_BRAND_NAME\": \"".len();
            if let Some(end) = content[start..].find('"') {
                let val = content[start..start + end].trim();
                if !val.is_empty() {
                    if prepend_mfg && let Some(mfg) = manufacturer {
                        return Some(format!("{mfg} {val}"));
                    }
                    return Some(val.to_string());
                }
            }
        }
    }
    None
}

fn find_xiaominame(store: &PropStore) -> Option<String> {
    let mut names = Vec::new();
    if let Some(list) = store.props.get("ro.product.odm.marketname") {
        for (part, val) in list {
            if (part == "odm" || part.contains("odm"))
                && !val.is_empty()
                && val
                    .chars()
                    .any(|c| c.is_ascii_uppercase() || c.is_whitespace() || c.is_ascii_digit())
                && !names.contains(&val.as_str())
            {
                names.push(val.as_str());
            }
        }
    }
    if names.is_empty() {
        None
    } else {
        names.sort_unstable();
        Some(names.join(" | "))
    }
}

fn find_motoname(store: &PropStore) -> Option<String> {
    let mut names = Vec::new();
    for (key, list) in &store.props {
        if key.starts_with("ro.product.") && key.ends_with(".model") {
            for (_, val) in list {
                if val.to_ascii_lowercase().contains("moto") && !val.is_empty() {
                    let trimmed = val.trim();
                    if !names.contains(&trimmed) {
                        names.push(trimmed);
                    }
                }
            }
        }
    }
    if names.is_empty() {
        None
    } else {
        names.sort_unstable();
        Some(names.join(" | "))
    }
}

fn find_opname(store: &PropStore, codename: Option<&str>) -> Option<String> {
    let val = store.get_scoped(
        "ro.vendor.oplus.market.name",
        &["my_manifest", "odm", "vendor/odm", "my_product", "vendor"],
    )?;
    if let Some(code) = codename
        && val == code
    {
        return None;
    }
    Some(val.to_string())
}

fn find_chipset(dump_dir: &Path, store: &PropStore) -> Option<String> {
    // 1. Transsion chipset: tr_product/etc/asset/transettings/cpu_info
    let tr_cpu_info = dump_dir.join("tr_product/etc/asset/transettings/cpu_info");
    if let Ok(content) = fs::read_to_string(tr_cpu_info) {
        let trimmed = content.trim();
        if !trimmed.is_empty() {
            return Some(trimmed.to_string());
        }
    }

    // 2. OPlus chipset: matching ro.product.oplus.cpuinfo inside my_stock XML
    if let Some(cpu_model) = store.get_scoped("ro.product.oplus.cpuinfo", &["my_product"]) {
        let xml_path =
            dump_dir.join("my_stock/etc/extension/config_processor_com.android.settings.xml");
        if let Ok(content) = fs::read_to_string(xml_path) {
            let needle = format!("model_name=\"{cpu_model}\"");
            if let Some(pos) = content.find(&needle) {
                let slice = &content[pos..];
                if let Some(name_pos) = slice.find("name_en=\"") {
                    let start = name_pos + "name_en=\"".len();
                    if let Some(end) = slice[start..].find('"') {
                        let name = slice[start..start + end].trim();
                        if !name.is_empty() {
                            return Some(name.to_string());
                        }
                    }
                }
            }
        }
    }
    None
}

fn find_display_info(dump_dir: &Path, store: &PropStore) -> Option<String> {
    // 1. Panel type (AMOLED vs IPS LCD)
    let is_optical_fp = store
        .get_any(&[
            "ro.tr_fingerprint.optical.feature.support",
            "ro.hardware.fingerprint.optical",
            "vendor.fingerprint.optical",
        ])
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
        .unwrap_or(false);

    let mut disp_type: Option<&'static str> = if is_optical_fp { Some("AMOLED") } else { None };

    if disp_type.is_none() {
        let dts_dirs = [
            dump_dir.join("dtbodts"),
            dump_dir.join("vendor_bootdts"),
            dump_dir.join("bootdts"),
        ];
        for d in &dts_dirs {
            if d.is_dir()
                && let Ok(entries) = fs::read_dir(d)
            {
                for entry in entries.flatten() {
                    if let Ok(text) = fs::read_to_string(entry.path()) {
                        let lower = text.to_ascii_lowercase();
                        if lower.contains("amoled")
                            || lower.contains("oled")
                            || lower.contains("rm69")
                            || lower.contains("ea80")
                            || lower.contains("nt377")
                        {
                            disp_type = Some("AMOLED");
                            break;
                        } else if lower.contains("compatible") && lower.contains("ips") {
                            disp_type = Some("IPS LCD");
                        }
                    }
                }
            }
            if disp_type.is_some() {
                break;
            }
        }
    }

    // 2. Resolution (WIDTHxHEIGHT)
    let width = store.get_any_scoped(&[
        (
            "ro.vendor.camera.lcm.width",
            &["odm", "vendor/odm", "vendor"],
        ),
        (
            "ro.display.width",
            &["vendor", "system", "system/system", "product", "odm"],
        ),
        ("ro.vendor.display.width", &["vendor", "odm"]),
        (
            "ro.sf.lcd_width",
            &["vendor", "system", "system/system", "odm"],
        ),
    ]);
    let height = store.get_any_scoped(&[
        (
            "ro.vendor.camera.lcm.height",
            &["odm", "vendor/odm", "vendor"],
        ),
        (
            "ro.display.height",
            &["vendor", "system", "system/system", "product", "odm"],
        ),
        ("ro.vendor.display.height", &["vendor", "odm"]),
        (
            "ro.sf.lcd_height",
            &["vendor", "system", "system/system", "odm"],
        ),
    ]);

    let disp_res = match (width, height) {
        (Some(w), Some(h)) if !w.is_empty() && !h.is_empty() => Some(format!("{w}x{h}")),
        _ => None,
    };

    // 3. Refresh Rate (Hz)
    let mut disp_hz = None;
    let dts_dirs = [
        dump_dir.join("dtbodts"),
        dump_dir.join("vendor_bootdts"),
        dump_dir.join("bootdts"),
    ];
    for d in &dts_dirs {
        if d.is_dir()
            && let Ok(entries) = fs::read_dir(d)
        {
            for entry in entries.flatten() {
                if let Ok(text) = fs::read_to_string(entry.path()) {
                    for rate in ["165hz", "144hz", "120hz", "90hz", "60hz"] {
                        if text.to_ascii_lowercase().contains(rate) {
                            disp_hz = Some(rate.replace("hz", "Hz"));
                            break;
                        }
                    }
                }
                if disp_hz.is_some() {
                    break;
                }
            }
        }
        if disp_hz.is_some() {
            break;
        }
    }

    // 4. Density
    let density = store
        .get_scoped(
            "ro.sf.lcd_density",
            &["vendor", "system", "system/system", "odm"],
        )
        .filter(|d| *d != "undefined" && !d.is_empty());

    let mut parts: Vec<String> = Vec::new();
    if let Some(t) = disp_type {
        parts.push(t.to_string());
    }
    if let Some(r) = disp_res {
        parts.push(r);
    }
    match (disp_hz, density) {
        (Some(hz), Some(dpi)) => parts.push(format!("{hz} ({dpi} dpi)")),
        (Some(hz), None) => parts.push(hz),
        (None, Some(dpi)) => parts.push(format!("{dpi} dpi")),
        (None, None) => {}
    }

    if parts.is_empty() {
        None
    } else {
        Some(parts.join(", "))
    }
}

fn find_camera_and_charging(
    dump_dir: &Path,
    store: &PropStore,
    is_transsion: bool,
) -> (Option<String>, Option<String>, Option<String>) {
    let charging = store
        .get_scoped(
            "ro.tr_charging.animation_wire_power",
            &["tr_product", "tr_manifest", "product", "vendor", "odm"],
        )
        .filter(|p| p.chars().all(|c| c.is_ascii_digit()))
        .map(|p| format!("{p}W"));

    if !is_transsion {
        return (None, None, charging);
    }

    let rearcam = store.get_scoped(
        "ro.tr_build.rearcamera.config",
        &["tr_product", "tr_manifest", "product", "vendor", "odm"],
    );
    let frontcam = store.get_scoped(
        "ro.tr_build.frontcamera.config",
        &["tr_product", "tr_manifest", "product", "vendor", "odm"],
    );

    // Rear sensor names from tran_camera_stereo_setting.json
    let mut rear_sensors = Vec::new();
    let stereo_json = dump_dir.join("odm/etc/vconfig/camera/tran_camera_stereo_setting.json");
    if let Ok(content) = fs::read_to_string(stereo_json) {
        let mut cursor = &content[..];
        while let Some(pos) = cursor.find("\"Name\": \"") {
            let start = pos + "\"Name\": \"".len();
            if let Some(end) = cursor[start..].find('"') {
                let name = &cursor[start..start + end];
                let clean = name
                    .replace("_MIPI_RAW", "")
                    .replace("_mipi_raw", "")
                    .replace("_RAW", "")
                    .replace("_raw", "")
                    .replace("WIDE", "")
                    .replace("wide", "")
                    .to_ascii_uppercase();
                let clean_trimmed = clean.trim();
                if !clean_trimmed.is_empty() && !rear_sensors.contains(&clean_trimmed.to_string()) {
                    rear_sensors.push(clean_trimmed.to_string());
                }
                cursor = &cursor[start + end..];
            } else {
                break;
            }
        }
    }

    let rear_sensor_str = if rear_sensors.is_empty() {
        None
    } else {
        Some(rear_sensors.join(", "))
    };

    let rearcam_display = match (rearcam, rear_sensor_str) {
        (Some(rc), Some(sensors)) => Some(format!("{rc} ({sensors})")),
        (Some(rc), None) => Some(rc.to_string()),
        (None, Some(sensors)) => Some(sensors),
        (None, None) => None,
    };

    // Front sensor from odm/lib64/libCamera_*front*
    let mut front_sensor: Option<String> = None;
    let odm_lib64 = dump_dir.join("odm/lib64");
    if odm_lib64.is_dir()
        && let Ok(entries) = fs::read_dir(odm_lib64)
    {
        for entry in entries.flatten() {
            let fname = entry.file_name().to_string_lossy().to_string();
            if let Some(rest) = fname.strip_prefix("libCamera_")
                && let Some(pos) = rest.to_ascii_lowercase().find("front")
            {
                let model = rest[..pos].trim();
                if !model.is_empty() {
                    front_sensor = Some(model.to_ascii_uppercase());
                    break;
                }
            }
        }
    }

    let frontcam_display = match (frontcam, front_sensor) {
        (Some(fc), Some(s)) => Some(format!("{fc} ({s})")),
        (Some(fc), None) => Some(fc.to_string()),
        (None, Some(s)) => Some(s),
        (None, None) => None,
    };

    (rearcam_display, frontcam_display, charging)
}

fn extract_kernel_version(dump_dir: &Path) -> Option<String> {
    let kernel_candidates: [PathBuf; 4] = [
        dump_dir.join("boot").join("kernel"),
        dump_dir.join("vendor_boot").join("kernel"),
        dump_dir.join("kernel"),
        dump_dir.join("boot.img"),
    ];

    for kp in &kernel_candidates {
        if kp.is_file()
            && let Ok(mut file) = File::open(kp)
        {
            let mut magic = [0u8; 4];
            if file.read_exact(&mut magic).is_ok() && file.seek(std::io::SeekFrom::Start(0)).is_ok()
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
                } else if let Some(v) = scan_for_linux_version(file) {
                    return Some(v);
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

//! Mapping from a detected [`FirmwareKind`] to the pipeline action that
//! handles it.
//!
//! Keeping this decision in one table prevents the OEM branches from being
//! duplicated between archive extraction and image preparation.

use crate::utils::firmware::FirmwareKind;

/// Pipeline action selected for a firmware container.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FirmwareAction {
    /// Unpack a generic zip/tar/7z-style container.
    Container,
    /// Extract an Android OTA `payload.bin`.
    Payload,
    /// Unpack a `super.img` with liblp.
    Super,
    /// Hand the container to the OEM-specific extractor for this kind.
    Oem(FirmwareKind),
}

/// Select the action for a detected firmware kind.
#[must_use]
pub fn action_for(kind: FirmwareKind) -> FirmwareAction {
    match kind {
        FirmwareKind::Zip
        | FirmwareKind::Tar
        | FirmwareKind::TarMd5
        | FirmwareKind::TarGz
        | FirmwareKind::TarBz2
        | FirmwareKind::TarXz
        | FirmwareKind::Kdz
        | FirmwareKind::Dz
        | FirmwareKind::Other => FirmwareAction::Container,
        FirmwareKind::Payload => FirmwareAction::Payload,
        FirmwareKind::Super => FirmwareAction::Super,
        kind @ (FirmwareKind::Ozip
        | FirmwareKind::Ops
        | FirmwareKind::Ofp
        | FirmwareKind::Ruu
        | FirmwareKind::Amlogic
        | FirmwareKind::Qfil
        | FirmwareKind::Nb0
        | FirmwareKind::SonySin
        | FirmwareKind::Pac
        | FirmwareKind::HuaweiUpdateApp
        | FirmwareKind::Rockchip) => FirmwareAction::Oem(kind),
    }
}

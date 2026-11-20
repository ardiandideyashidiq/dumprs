//! Contract tests for the firmware dispatch table.
//!
//! The regression these guard against: an OEM container is detected correctly
//! but then falls through to the generic archive handler, so its specialized
//! extraction never runs and the dump is silently incomplete.

use dumprs::steps::dispatch::{FirmwareAction, action_for};
use dumprs::utils::firmware::FirmwareKind;

#[test]
fn routes_detected_kinds_to_the_correct_handler() {
    let cases: &[(FirmwareKind, FirmwareAction)] = &[
        (FirmwareKind::Zip, FirmwareAction::Container),
        (FirmwareKind::Tar, FirmwareAction::Container),
        (FirmwareKind::TarMd5, FirmwareAction::Container),
        (FirmwareKind::TarGz, FirmwareAction::Container),
        (FirmwareKind::TarBz2, FirmwareAction::Container),
        (FirmwareKind::TarXz, FirmwareAction::Container),
        (FirmwareKind::Kdz, FirmwareAction::Container),
        (FirmwareKind::Dz, FirmwareAction::Container),
        (FirmwareKind::Other, FirmwareAction::Container),
        (FirmwareKind::Payload, FirmwareAction::Payload),
        (FirmwareKind::Super, FirmwareAction::Super),
        (FirmwareKind::Ozip, FirmwareAction::Oem(FirmwareKind::Ozip)),
        (FirmwareKind::Ops, FirmwareAction::Oem(FirmwareKind::Ops)),
        (FirmwareKind::Ofp, FirmwareAction::Oem(FirmwareKind::Ofp)),
        (FirmwareKind::Ruu, FirmwareAction::Oem(FirmwareKind::Ruu)),
        (
            FirmwareKind::HuaweiUpdateApp,
            FirmwareAction::Oem(FirmwareKind::HuaweiUpdateApp),
        ),
        (FirmwareKind::Qfil, FirmwareAction::Oem(FirmwareKind::Qfil)),
        (FirmwareKind::Nb0, FirmwareAction::Oem(FirmwareKind::Nb0)),
        (
            FirmwareKind::SonySin,
            FirmwareAction::Oem(FirmwareKind::SonySin),
        ),
        (FirmwareKind::Pac, FirmwareAction::Oem(FirmwareKind::Pac)),
        (
            FirmwareKind::Amlogic,
            FirmwareAction::Oem(FirmwareKind::Amlogic),
        ),
        (
            FirmwareKind::Rockchip,
            FirmwareAction::Oem(FirmwareKind::Rockchip),
        ),
    ];

    for &(kind, expected) in cases {
        assert_eq!(action_for(kind), expected, "kind: {kind:?}");
    }
}

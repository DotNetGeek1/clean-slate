//! `clean-slate-graphics` has zero dependencies, so it mirrors the `Graphics` rights bits as
//! raw `u32` constants. native-abi is the one crate that sees both sides (capability as a
//! dependency, graphics as a dev-dependency), so the mirror is proven equal here.

use clean_slate_capability::{ResourceClass, Rights};
use clean_slate_graphics::protocol::ProtocolError;
use clean_slate_graphics::role::{
    validate_role, Layer, RoleGrant, SurfaceRole, GFX_CONNECT_BIT, GFX_OVERLAY_BIT, GFX_SHELL_BIT,
};

const SUPPORTED_ROLES: [SurfaceRole; 5] = [
    SurfaceRole::Toplevel,
    SurfaceRole::Popup,
    SurfaceRole::Background,
    SurfaceRole::ShellPanel,
    SurfaceRole::SystemOverlay,
];

/// Every subset of the rights that are valid on a `Graphics` capability.
fn graphics_subsets() -> Vec<u32> {
    let valid = Rights::valid_for(ResourceClass::Graphics).bits();
    let bits: Vec<u32> = (0..32)
        .map(|i| 1u32 << i)
        .filter(|b| valid & b != 0)
        .collect();
    (0..1u32 << bits.len())
        .map(|mask| {
            bits.iter()
                .enumerate()
                .filter(|(i, _)| mask & (1 << i) != 0)
                .fold(0, |acc, (_, b)| acc | b)
        })
        .collect()
}

#[test]
fn graphics_role_bit_mirrors_equal_capability_rights() {
    assert_eq!(GFX_CONNECT_BIT, Rights::GFX_CONNECT.bits());
    assert_eq!(GFX_SHELL_BIT, Rights::GFX_SHELL.bits());
    assert_eq!(GFX_OVERLAY_BIT, Rights::GFX_OVERLAY.bits());
}

#[test]
fn mirrored_bits_are_valid_graphics_rights() {
    let valid = Rights::valid_for(ResourceClass::Graphics);
    for bit in [GFX_CONNECT_BIT, GFX_SHELL_BIT, GFX_OVERLAY_BIT] {
        let right = Rights::from_bits(bit).expect("mirror names a defined right");
        assert!(valid.contains(right), "{bit:#x} not valid for Graphics");
    }
}

#[test]
fn shell_and_overlay_are_root_only_and_connect_is_delegable() {
    let root_only = Rights::root_only_for(ResourceClass::Graphics).bits();
    assert_ne!(root_only & GFX_SHELL_BIT, 0);
    assert_ne!(root_only & GFX_OVERLAY_BIT, 0);
    assert_eq!(root_only & GFX_CONNECT_BIT, 0);
}

#[test]
fn grant_decoding_matches_rights_contains_for_every_graphics_subset() {
    for bits in graphics_subsets() {
        let rights = Rights::from_bits(bits).unwrap();
        let grant = RoleGrant::from_rights_bits(rights.bits());
        assert_eq!(
            grant.can_connect(),
            rights.contains(Rights::GFX_CONNECT),
            "{bits:#x}"
        );
        assert_eq!(
            grant.has_shell(),
            rights.contains(Rights::GFX_SHELL),
            "{bits:#x}"
        );
        assert_eq!(
            grant.has_overlay(),
            rights.contains(Rights::GFX_OVERLAY),
            "{bits:#x}"
        );
    }
}

#[test]
fn gfx_serve_alone_authorises_no_client_role() {
    let grant = RoleGrant::from_rights_bits(Rights::GFX_SERVE.bits());
    assert!(!grant.can_connect());
    for role in SUPPORTED_ROLES {
        assert_eq!(
            validate_role(role, grant),
            Err(ProtocolError::RoleForbidden),
            "{role:?}"
        );
    }
}

/// Delegation strips root-only rights, so no delegated `Graphics` capability can ever reach a
/// shell or overlay layer, whatever else it carries.
#[test]
fn delegated_graphics_rights_never_authorise_shell_or_overlay_roles() {
    let root_only = Rights::root_only_for(ResourceClass::Graphics).bits();
    for bits in graphics_subsets() {
        let delegated = bits & !root_only;
        let grant = RoleGrant::from_rights_bits(delegated);
        for role in [
            SurfaceRole::Background,
            SurfaceRole::ShellPanel,
            SurfaceRole::SystemOverlay,
        ] {
            assert_eq!(
                validate_role(role, grant),
                Err(ProtocolError::RoleForbidden),
                "{role:?} with delegated bits {delegated:#x}"
            );
        }
        let window = if delegated & GFX_CONNECT_BIT != 0 {
            Ok(Layer::Windows)
        } else {
            Err(ProtocolError::RoleForbidden)
        };
        assert_eq!(
            validate_role(SurfaceRole::Toplevel, grant),
            window,
            "{delegated:#x}"
        );
        assert_eq!(
            validate_role(SurfaceRole::Popup, grant),
            window,
            "{delegated:#x}"
        );
    }
}

#[test]
fn full_root_graphics_grant_authorises_every_supported_role() {
    let grant = RoleGrant::from_rights_bits(Rights::valid_for(ResourceClass::Graphics).bits());
    assert_eq!(
        validate_role(SurfaceRole::Toplevel, grant),
        Ok(Layer::Windows)
    );
    assert_eq!(validate_role(SurfaceRole::Popup, grant), Ok(Layer::Windows));
    assert_eq!(
        validate_role(SurfaceRole::Background, grant),
        Ok(Layer::Background)
    );
    assert_eq!(
        validate_role(SurfaceRole::ShellPanel, grant),
        Ok(Layer::ShellFurniture)
    );
    assert_eq!(
        validate_role(SurfaceRole::SystemOverlay, grant),
        Ok(Layer::TrustedOverlay)
    );
    for role in [SurfaceRole::Cursor, SurfaceRole::Subsurface] {
        assert_eq!(
            validate_role(role, grant),
            Err(ProtocolError::UnsupportedFeature)
        );
    }
}

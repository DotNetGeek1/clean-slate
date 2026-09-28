//! Destination: `graphics/src/role/tests.rs`, included from `graphics/src/role.rs` with
//! `#[cfg(test)] mod tests;`.
//!
//! Stage D contract: role authority derives only from kernel-stamped rights bits (SPEC §3).

use crate::protocol::ProtocolError;
use crate::role::{
    validate_parent, validate_role, Layer, ParentRef, RoleGrant, SurfaceRole, GFX_CONNECT_BIT,
    GFX_OVERLAY_BIT, GFX_SHELL_BIT,
};

const ROLE_BITS: u32 = GFX_CONNECT_BIT | GFX_SHELL_BIT | GFX_OVERLAY_BIT;

const ALL_ROLES: [SurfaceRole; 7] = [
    SurfaceRole::Toplevel,
    SurfaceRole::Popup,
    SurfaceRole::Background,
    SurfaceRole::ShellPanel,
    SurfaceRole::SystemOverlay,
    SurfaceRole::Cursor,
    SurfaceRole::Subsurface,
];

/// The eight combinations of the three role bits.
fn role_bit_combinations() -> [u32; 8] {
    let mut out = [0u32; 8];
    for (i, slot) in out.iter_mut().enumerate() {
        let i = i as u32;
        *slot = (if i & 1 != 0 { GFX_CONNECT_BIT } else { 0 })
            | (if i & 2 != 0 { GFX_SHELL_BIT } else { 0 })
            | (if i & 4 != 0 { GFX_OVERLAY_BIT } else { 0 });
    }
    out
}

fn grant(bits: u32) -> RoleGrant {
    RoleGrant::from_rights_bits(bits)
}

#[test]
fn rights_bit_mirrors_have_frozen_values() {
    assert_eq!(GFX_CONNECT_BIT, 1 << 14);
    assert_eq!(GFX_SHELL_BIT, 1 << 15);
    assert_eq!(GFX_OVERLAY_BIT, 1 << 16);
}

#[test]
fn grant_ignores_every_non_role_bit() {
    let noise = !ROLE_BITS;
    assert_eq!(grant(noise), grant(0));
    for bits in role_bit_combinations() {
        assert_eq!(grant(bits | noise), grant(bits));
    }
    let empty = grant(noise);
    assert!(!empty.can_connect());
    assert!(!empty.has_shell());
    assert!(!empty.has_overlay());
}

#[test]
fn grant_accessors_track_each_bit_independently() {
    for bits in role_bit_combinations() {
        let g = grant(bits);
        assert_eq!(
            g.can_connect(),
            bits & GFX_CONNECT_BIT != 0,
            "bits {bits:#x}"
        );
        assert_eq!(g.has_shell(), bits & GFX_SHELL_BIT != 0, "bits {bits:#x}");
        assert_eq!(
            g.has_overlay(),
            bits & GFX_OVERLAY_BIT != 0,
            "bits {bits:#x}"
        );
    }
    let all = grant(u32::MAX);
    assert!(all.can_connect() && all.has_shell() && all.has_overlay());
}

#[test]
fn connect_only_grant_allows_toplevel_and_popup_in_windows_layer() {
    let g = grant(GFX_CONNECT_BIT);
    assert_eq!(validate_role(SurfaceRole::Toplevel, g), Ok(Layer::Windows));
    assert_eq!(validate_role(SurfaceRole::Popup, g), Ok(Layer::Windows));
}

#[test]
fn shell_roles_require_shell_right() {
    let app = grant(GFX_CONNECT_BIT);
    assert_eq!(
        validate_role(SurfaceRole::Background, app),
        Err(ProtocolError::RoleForbidden)
    );
    assert_eq!(
        validate_role(SurfaceRole::ShellPanel, app),
        Err(ProtocolError::RoleForbidden)
    );
    let shell = grant(GFX_CONNECT_BIT | GFX_SHELL_BIT);
    assert_eq!(
        validate_role(SurfaceRole::Background, shell),
        Ok(Layer::Background)
    );
    assert_eq!(
        validate_role(SurfaceRole::ShellPanel, shell),
        Ok(Layer::ShellFurniture)
    );
    assert_eq!(
        validate_role(SurfaceRole::Toplevel, shell),
        Ok(Layer::Windows)
    );
}

#[test]
fn system_overlay_requires_overlay_right() {
    assert_eq!(
        validate_role(SurfaceRole::SystemOverlay, grant(GFX_CONNECT_BIT)),
        Err(ProtocolError::RoleForbidden)
    );
    assert_eq!(
        validate_role(
            SurfaceRole::SystemOverlay,
            grant(GFX_CONNECT_BIT | GFX_SHELL_BIT)
        ),
        Err(ProtocolError::RoleForbidden)
    );
    assert_eq!(
        validate_role(
            SurfaceRole::SystemOverlay,
            grant(GFX_CONNECT_BIT | GFX_OVERLAY_BIT)
        ),
        Ok(Layer::TrustedOverlay)
    );
}

#[test]
fn overlay_right_does_not_imply_shell_roles() {
    let overlay = grant(GFX_CONNECT_BIT | GFX_OVERLAY_BIT);
    assert_eq!(
        validate_role(SurfaceRole::Background, overlay),
        Err(ProtocolError::RoleForbidden)
    );
    assert_eq!(
        validate_role(SurfaceRole::ShellPanel, overlay),
        Err(ProtocolError::RoleForbidden)
    );
}

#[test]
fn reserved_roles_are_unsupported_for_every_grant() {
    for bits in role_bit_combinations() {
        for role in [SurfaceRole::Cursor, SurfaceRole::Subsurface] {
            assert_eq!(
                validate_role(role, grant(bits)),
                Err(ProtocolError::UnsupportedFeature),
                "role {role:?} bits {bits:#x}"
            );
        }
    }
}

#[test]
fn missing_connect_forbids_every_supported_role_even_with_shell_and_overlay() {
    let no_connect = grant(GFX_SHELL_BIT | GFX_OVERLAY_BIT);
    for role in [
        SurfaceRole::Toplevel,
        SurfaceRole::Popup,
        SurfaceRole::Background,
        SurfaceRole::ShellPanel,
        SurfaceRole::SystemOverlay,
    ] {
        assert_eq!(
            validate_role(role, no_connect),
            Err(ProtocolError::RoleForbidden),
            "role {role:?}"
        );
    }
}

/// Independent statement of SPEC §3.2 used as the oracle for the full matrix.
fn expected_role(role: SurfaceRole, bits: u32) -> Result<Layer, ProtocolError> {
    let connect = bits & GFX_CONNECT_BIT != 0;
    let shell = bits & GFX_SHELL_BIT != 0;
    let overlay = bits & GFX_OVERLAY_BIT != 0;
    match role {
        SurfaceRole::Cursor | SurfaceRole::Subsurface => Err(ProtocolError::UnsupportedFeature),
        _ if !connect => Err(ProtocolError::RoleForbidden),
        SurfaceRole::Toplevel | SurfaceRole::Popup => Ok(Layer::Windows),
        SurfaceRole::Background => {
            if shell {
                Ok(Layer::Background)
            } else {
                Err(ProtocolError::RoleForbidden)
            }
        }
        SurfaceRole::ShellPanel => {
            if shell {
                Ok(Layer::ShellFurniture)
            } else {
                Err(ProtocolError::RoleForbidden)
            }
        }
        SurfaceRole::SystemOverlay => {
            if overlay {
                Ok(Layer::TrustedOverlay)
            } else {
                Err(ProtocolError::RoleForbidden)
            }
        }
    }
}

#[test]
fn validate_role_full_matrix_matches_spec_table() {
    for bits in role_bit_combinations() {
        for role in ALL_ROLES {
            assert_eq!(
                validate_role(role, grant(bits)),
                expected_role(role, bits),
                "role {role:?} bits {bits:#x}"
            );
        }
    }
}

#[test]
fn validate_role_never_yields_cursor_layer() {
    for bits in role_bit_combinations() {
        for role in ALL_ROLES {
            if let Ok(layer) = validate_role(role, grant(bits)) {
                assert_ne!(layer, Layer::Cursor, "role {role:?} bits {bits:#x}");
            }
        }
    }
}

#[test]
fn popup_requires_toplevel_or_popup_parent() {
    for parent_role in [SurfaceRole::Toplevel, SurfaceRole::Popup] {
        assert_eq!(
            validate_parent(
                SurfaceRole::Popup,
                ParentRef::Surface {
                    role: Some(parent_role),
                    is_self: false,
                }
            ),
            Ok(())
        );
    }
    assert_eq!(
        validate_parent(SurfaceRole::Popup, ParentRef::Absent),
        Err(ProtocolError::InvalidParent)
    );
}

#[test]
fn popup_rejects_self_roleless_and_non_window_parents() {
    let cases = [
        ParentRef::Surface {
            role: Some(SurfaceRole::Toplevel),
            is_self: true,
        },
        ParentRef::Surface {
            role: None,
            is_self: false,
        },
        ParentRef::Surface {
            role: Some(SurfaceRole::Background),
            is_self: false,
        },
        ParentRef::Surface {
            role: Some(SurfaceRole::ShellPanel),
            is_self: false,
        },
        ParentRef::Surface {
            role: Some(SurfaceRole::SystemOverlay),
            is_self: false,
        },
    ];
    for parent in cases {
        assert_eq!(
            validate_parent(SurfaceRole::Popup, parent),
            Err(ProtocolError::InvalidParent),
            "parent {parent:?}"
        );
    }
}

#[test]
fn non_popup_roles_reject_any_parent() {
    for role in [
        SurfaceRole::Toplevel,
        SurfaceRole::Background,
        SurfaceRole::ShellPanel,
        SurfaceRole::SystemOverlay,
    ] {
        assert_eq!(validate_parent(role, ParentRef::Absent), Ok(()));
        assert_eq!(
            validate_parent(
                role,
                ParentRef::Surface {
                    role: Some(SurfaceRole::Toplevel),
                    is_self: false,
                }
            ),
            Err(ProtocolError::InvalidParent),
            "role {role:?}"
        );
    }
}

#[test]
fn reserved_roles_parent_check_is_unsupported() {
    for role in [SurfaceRole::Cursor, SurfaceRole::Subsurface] {
        assert_eq!(
            validate_parent(role, ParentRef::Absent),
            Err(ProtocolError::UnsupportedFeature)
        );
    }
}

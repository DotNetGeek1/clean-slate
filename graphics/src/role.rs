//! Surface role wire types (compositor assigns layer in Stage D).

use crate::protocol::ProtocolError;

/// Mirror of `clean_slate_capability::Rights::GFX_CONNECT` (cross-checked in `native-abi`).
pub const GFX_CONNECT_BIT: u32 = 1 << 14;
/// Mirror of `clean_slate_capability::Rights::GFX_SHELL`.
pub const GFX_SHELL_BIT: u32 = 1 << 15;
/// Mirror of `clean_slate_capability::Rights::GFX_OVERLAY`.
pub const GFX_OVERLAY_BIT: u32 = 1 << 16;

/// Role authority derived only from the kernel-stamped rights bits of the caller's
/// `Graphics` capability (`TrustedEnvelope.granted_rights`); never from request fields.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RoleGrant {
    connect: bool,
    shell: bool,
    overlay: bool,
}

impl RoleGrant {
    /// Bits other than the three role bits are ignored.
    pub const fn from_rights_bits(bits: u32) -> Self {
        Self {
            connect: bits & GFX_CONNECT_BIT != 0,
            shell: bits & GFX_SHELL_BIT != 0,
            overlay: bits & GFX_OVERLAY_BIT != 0,
        }
    }

    pub const fn can_connect(self) -> bool {
        self.connect
    }

    pub const fn has_shell(self) -> bool {
        self.shell
    }

    pub const fn has_overlay(self) -> bool {
        self.overlay
    }
}

/// Authorises `role` and returns its compositor layer.
///
/// Order: reserved roles (`Cursor`, `Subsurface`) → `UnsupportedFeature` regardless of the
/// grant; then a grant without `GFX_CONNECT` → `RoleForbidden` for every role; then the
/// role-specific right.
pub fn validate_role(role: SurfaceRole, grant: RoleGrant) -> Result<Layer, ProtocolError> {
    match role {
        SurfaceRole::Cursor | SurfaceRole::Subsurface => Err(ProtocolError::UnsupportedFeature),
        _ if !grant.connect => Err(ProtocolError::RoleForbidden),
        SurfaceRole::Toplevel | SurfaceRole::Popup => Ok(Layer::Windows),
        SurfaceRole::Background if grant.shell => Ok(Layer::Background),
        SurfaceRole::ShellPanel if grant.shell => Ok(Layer::ShellFurniture),
        SurfaceRole::SystemOverlay if grant.overlay => Ok(Layer::TrustedOverlay),
        _ => Err(ProtocolError::RoleForbidden),
    }
}

/// `AssignRole.parent` after the compositor resolved it in the caller's own object table.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ParentRef {
    Absent,
    Surface {
        role: Option<SurfaceRole>,
        is_self: bool,
    },
}

/// `Popup` needs a parent that is another surface whose role is `Toplevel` or `Popup`;
/// every other supported role must have no parent. Reserved roles → `UnsupportedFeature`.
pub fn validate_parent(role: SurfaceRole, parent: ParentRef) -> Result<(), ProtocolError> {
    match role {
        SurfaceRole::Cursor | SurfaceRole::Subsurface => Err(ProtocolError::UnsupportedFeature),
        SurfaceRole::Popup => match parent {
            ParentRef::Surface {
                role: Some(SurfaceRole::Toplevel | SurfaceRole::Popup),
                is_self: false,
            } => Ok(()),
            _ => Err(ProtocolError::InvalidParent),
        },
        _ => match parent {
            ParentRef::Absent => Ok(()),
            ParentRef::Surface { .. } => Err(ProtocolError::InvalidParent),
        },
    }
}

/// Client-requested surface role (`AssignRole`).
#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SurfaceRole {
    Toplevel = 1,
    Popup = 2,
    Background = 3,
    ShellPanel = 4,
    SystemOverlay = 5,
    Cursor = 6,
    Subsurface = 7,
}

impl SurfaceRole {
    pub fn from_u8(raw: u8) -> Option<Self> {
        match raw {
            1 => Some(Self::Toplevel),
            2 => Some(Self::Popup),
            3 => Some(Self::Background),
            4 => Some(Self::ShellPanel),
            5 => Some(Self::SystemOverlay),
            6 => Some(Self::Cursor),
            7 => Some(Self::Subsurface),
            _ => None,
        }
    }

    pub const fn as_u8(self) -> u8 {
        self as u8
    }
}

/// Compositor layer (not on the wire in 1.0; derived by `validate_role` in Stage D).
#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Layer {
    Background = 0,
    Windows = 1,
    ShellFurniture = 2,
    TrustedOverlay = 3,
    Cursor = 4,
}

impl Layer {
    pub fn from_u8(raw: u8) -> Option<Self> {
        match raw {
            0 => Some(Self::Background),
            1 => Some(Self::Windows),
            2 => Some(Self::ShellFurniture),
            3 => Some(Self::TrustedOverlay),
            4 => Some(Self::Cursor),
            _ => None,
        }
    }

    pub const fn as_u8(self) -> u8 {
        self as u8
    }
}

#[cfg(test)]
mod tests;

//! Surface role wire types (compositor assigns layer in Stage D).

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

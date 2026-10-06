//! Design tokens: the single definition of Clean-Slate colour, spacing, shape, type, chrome,
//! shell and budget values. Renderer code reads these through a [`Theme`]; it never embeds
//! its own colours or metrics.

use clean_slate_graphics::pixel::over;
use clean_slate_raster::{Color, GlyphAtlas, Spleen8x16};

use crate::quality::QualityTier;

/// Straight-alpha sRGB colour token; premultiplied only at paint time.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Rgba {
    /// Red channel.
    pub r: u8,
    /// Green channel.
    pub g: u8,
    /// Blue channel.
    pub b: u8,
    /// Straight alpha; 255 is opaque.
    pub a: u8,
}

impl Rgba {
    /// Opaque colour.
    pub const fn rgb(r: u8, g: u8, b: u8) -> Self {
        Self { r, g, b, a: 255 }
    }

    /// Same channels with straight alpha `a`.
    pub const fn with_alpha(self, a: u8) -> Self {
        Self {
            r: self.r,
            g: self.g,
            b: self.b,
            a,
        }
    }

    /// True when `a == 255`.
    pub const fn is_opaque(self) -> bool {
        self.a == 255
    }

    /// Premultiplied B,G,R,A raster colour.
    pub const fn premultiplied(self) -> Color {
        Color::from_straight(self.r, self.g, self.b, self.a)
    }

    /// Opaque result of `self` over opaque `base`, using the shared `over()` rounding.
    pub fn flatten_over(self, base: Rgba) -> Rgba {
        let out = over(self.premultiplied().0, [base.b, base.g, base.r, 255]);
        Rgba::rgb(out[2], out[1], out[0])
    }
}

/// A surface fill with an explicit opaque fallback for tiers without translucency.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SurfaceFill {
    /// Used when translucency is disabled (Q0); always opaque.
    pub opaque: Rgba,
    /// Used from Q1 when translucency is enabled.
    pub translucent: Rgba,
}

/// Semantic colour roles. Every colour a primitive paints comes from one of these fields.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Palette {
    /// Deepest base behind everything.
    pub background: Rgba,
    /// Wallpaper gradient, top row.
    pub wallpaper_top: Rgba,
    /// Wallpaper gradient at the horizon row.
    pub wallpaper_horizon: Rgba,
    /// Wallpaper gradient, bottom row.
    pub wallpaper_bottom: Rgba,
    /// Thin accent line drawn on the horizon row (opaque, pre-mixed).
    pub wallpaper_horizon_line: Rgba,
    /// Panels and cards.
    pub surface: Rgba,
    /// Raised or selected surfaces.
    pub surface_raised: Rgba,
    /// Tracks and inset fields.
    pub surface_sunken: Rgba,
    /// Card fill on the wallpaper.
    pub card: SurfaceFill,
    /// Left rail background.
    pub rail: SurfaceFill,
    /// Rail item under the pointer.
    pub rail_hover: Rgba,
    /// Hairline separators and resting borders.
    pub border_subtle: Rgba,
    /// Emphasised borders (hover, toggle tracks).
    pub border_strong: Rgba,
    /// Secondary control at rest.
    pub control: Rgba,
    /// Secondary control under the pointer.
    pub control_hover: Rgba,
    /// Secondary control while pressed.
    pub control_pressed: Rgba,
    /// Primary text.
    pub text_primary: Rgba,
    /// Secondary text.
    pub text_secondary: Rgba,
    /// Captions and placeholders.
    pub text_muted: Rgba,
    /// Disabled text and glyphs.
    pub text_disabled: Rgba,
    /// Text on an accent fill.
    pub text_on_accent: Rgba,
    /// Primary accent (cyan): selection, primary actions, focus.
    pub accent_cyan: Rgba,
    /// Secondary accent (magenta): sparing highlights.
    pub accent_magenta: Rgba,
    /// Tertiary accent (blue): informational emphasis.
    pub accent_blue: Rgba,
    /// Primary control under the pointer.
    pub primary_hover: Rgba,
    /// Primary control while pressed.
    pub primary_pressed: Rgba,
    /// Keyboard focus ring.
    pub focus_ring: Rgba,
    /// Positive status.
    pub success: Rgba,
    /// Warning status.
    pub warning: Rgba,
    /// Error status.
    pub danger: Rgba,
    /// Focused window title bar.
    pub chrome_active_bar: Rgba,
    /// Inactive window title bar.
    pub chrome_inactive_bar: Rgba,
    /// Focused window border.
    pub chrome_active_border: Rgba,
    /// Inactive window border.
    pub chrome_inactive_border: Rgba,
    /// Focused window title text.
    pub chrome_active_title: Rgba,
    /// Inactive window title text.
    pub chrome_inactive_title: Rgba,
    /// Window control glyph, focused window.
    pub chrome_control_active: Rgba,
    /// Window control glyph, inactive window.
    pub chrome_control_inactive: Rgba,
    /// Window control background under the pointer.
    pub chrome_control_hover: Rgba,
    /// Window control background while pressed.
    pub chrome_control_pressed: Rgba,
    /// Focused window accent (title-bar underline).
    pub chrome_accent: Rgba,
    /// Window shadow (Q1 and above only).
    pub shadow: Rgba,
    /// Pointer cursor fill.
    pub cursor_fill: Rgba,
    /// Pointer cursor outline.
    pub cursor_outline: Rgba,
    /// Pointer cursor accent spine.
    pub cursor_accent: Rgba,
}

/// Text colour roles resolved through [`Palette::tone`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TextTone {
    /// [`Palette::text_primary`].
    Primary,
    /// [`Palette::text_secondary`].
    Secondary,
    /// [`Palette::text_muted`].
    Muted,
    /// [`Palette::text_disabled`].
    Disabled,
    /// [`Palette::text_on_accent`].
    OnAccent,
    /// [`Palette::accent_cyan`].
    Accent,
}

impl Palette {
    /// Colour for a text tone.
    pub const fn tone(&self, tone: TextTone) -> Rgba {
        match tone {
            TextTone::Primary => self.text_primary,
            TextTone::Secondary => self.text_secondary,
            TextTone::Muted => self.text_muted,
            TextTone::Disabled => self.text_disabled,
            TextTone::OnAccent => self.text_on_accent,
            TextTone::Accent => self.accent_cyan,
        }
    }
}

/// Spacing scale on a 4 px grid.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Spacing {
    /// Grid unit; every other spacing value is a multiple of it (`xxs` excepted).
    pub unit: u32,
    /// 2 px.
    pub xxs: u32,
    /// 4 px.
    pub xs: u32,
    /// 8 px.
    pub sm: u32,
    /// 12 px.
    pub md: u32,
    /// 16 px.
    pub lg: u32,
    /// 24 px.
    pub xl: u32,
    /// 32 px.
    pub xxl: u32,
}

/// Corner radii.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Radius {
    /// Small controls and window buttons.
    pub sm: u32,
    /// Buttons, rail items, inset fields.
    pub md: u32,
    /// Cards and panels.
    pub lg: u32,
    /// Fully rounded ends (clamped to half the shorter side).
    pub pill: u32,
}

/// Border and ring widths.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Stroke {
    /// Hairline borders.
    pub hairline: u32,
    /// Keyboard focus ring (drawn inside the widget bounds).
    pub focus: u32,
    /// Selected rail item indicator bar.
    pub indicator: u32,
}

/// One step of the type scale mapped onto the #111 fixed-cell bitmap font.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TextStyle {
    /// Integer glyph scale (1 = 8×16 cell).
    pub scale: u32,
    /// Faux-bold: the run is drawn twice, offset by 1 px.
    pub strong: bool,
    /// Extra pixels below the cell for line advance.
    pub leading: u32,
    /// Default colour role.
    pub tone: TextTone,
}

/// Typography roles.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TextRole {
    /// Hero text (3× cell).
    Display,
    /// Section titles (2× cell).
    Title,
    /// Card and window headings (1×, strong).
    Heading,
    /// Running text.
    Body,
    /// Control labels.
    Label,
    /// Captions and metadata.
    Caption,
}

/// Type scale. M10 has one bitmap face, so hierarchy comes from scale, weight and tone.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TypeScale {
    /// [`TextRole::Display`].
    pub display: TextStyle,
    /// [`TextRole::Title`].
    pub title: TextStyle,
    /// [`TextRole::Heading`].
    pub heading: TextStyle,
    /// [`TextRole::Body`].
    pub body: TextStyle,
    /// [`TextRole::Label`].
    pub label: TextStyle,
    /// [`TextRole::Caption`].
    pub caption: TextStyle,
}

impl TypeScale {
    /// Style for `role`.
    pub const fn style(&self, role: TextRole) -> TextStyle {
        match role {
            TextRole::Display => self.display,
            TextRole::Title => self.title,
            TextRole::Heading => self.heading,
            TextRole::Body => self.body,
            TextRole::Label => self.label,
            TextRole::Caption => self.caption,
        }
    }
}

/// Shell zone and rail metrics at the 1280×800 reference mode.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ShellMetrics {
    /// Persistent left rail width.
    pub rail_width: u32,
    /// Brand mark block at the top of the rail.
    pub rail_brand_height: u32,
    /// One rail item.
    pub rail_item_height: u32,
    /// Vertical gap between rail items.
    pub rail_item_gap: u32,
    /// Horizontal inset of a rail item's highlight inside the rail.
    pub rail_item_inset: u32,
    /// Height of the top global-search band (when present).
    pub search_band_height: u32,
    /// Search field width.
    pub search_field_width: u32,
    /// Search field height.
    pub search_field_height: u32,
    /// Right contextual stack width (when present).
    pub context_width: u32,
    /// Padding inside the workspace and context zones.
    pub zone_padding: u32,
}

/// Native window chrome metrics consumed by the window manager (#115) through
/// [`crate::chrome::ChromeStyle`]. Behaviour never depends on them; only geometry does.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ChromeMetrics {
    /// Title bar height inside the border.
    pub title_bar_height: u32,
    /// Frame border width.
    pub border_width: u32,
    /// Top corner radius of the frame.
    pub corner_radius: u32,
    /// Window control button edge length.
    pub control_size: u32,
    /// Gap between window controls.
    pub control_gap: u32,
    /// Inset of the control group from the frame's right edge.
    pub control_inset: u32,
    /// Horizontal padding before the title text.
    pub title_padding: u32,
    /// Invisible resize grab margin outside the border.
    pub resize_margin: u32,
}

/// A cheap layered shadow, painted only when the quality tier enables shadows.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ShadowToken {
    /// Number of concentric layers (each one pixel wider).
    pub layers: u32,
    /// Downward offset of the shadow.
    pub offset_y: u32,
}

/// Depth tokens.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Elevation {
    /// Focused window shadow.
    pub window_focused: ShadowToken,
    /// Inactive window shadow.
    pub window_inactive: ShadowToken,
}

/// Rendering-cost budget the shell and primitives are held to.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RenderBudget {
    /// Highest quality tier M10 renders; higher requests clamp to it.
    pub max_tier: QualityTier,
    /// Buffers the shell registers, of the per-client limit (8) and compositor limit (16).
    pub shell_buffers: u32,
    /// Damage rects a single shell state change may produce.
    pub max_damage_rects_per_update: u32,
    /// Pixels a single shell state change may repaint.
    pub max_damage_area_per_update: u32,
}

/// The complete token set. [`CLEAN_SLATE_DARK`] is the M10 theme.
#[derive(Clone, Copy)]
pub struct Theme {
    /// Theme name for diagnostics.
    pub name: &'static str,
    /// Colour roles.
    pub palette: Palette,
    /// Spacing scale.
    pub spacing: Spacing,
    /// Corner radii.
    pub radius: Radius,
    /// Border and ring widths.
    pub stroke: Stroke,
    /// Type scale.
    pub type_scale: TypeScale,
    /// Glyph source for every text role (the #111 bitmap font in M10).
    pub font: &'static dyn GlyphAtlas,
    /// Shell zone metrics.
    pub shell: ShellMetrics,
    /// Native window chrome metrics.
    pub chrome: ChromeMetrics,
    /// Depth tokens.
    pub elevation: Elevation,
    /// Cost budget.
    pub budget: RenderBudget,
}

/// The M10 Clean-Slate dark theme.
pub const CLEAN_SLATE_DARK: Theme = Theme {
    name: "clean-slate-dark",
    palette: Palette {
        background: Rgba::rgb(0x06, 0x08, 0x0D),
        wallpaper_top: Rgba::rgb(0x0B, 0x11, 0x24),
        wallpaper_horizon: Rgba::rgb(0x1B, 0x15, 0x33),
        wallpaper_bottom: Rgba::rgb(0x05, 0x06, 0x0B),
        wallpaper_horizon_line: Rgba::rgb(0x1E, 0x4A, 0x5C),
        surface: Rgba::rgb(0x10, 0x14, 0x1E),
        surface_raised: Rgba::rgb(0x18, 0x1E, 0x2B),
        surface_sunken: Rgba::rgb(0x0A, 0x0D, 0x14),
        card: SurfaceFill {
            opaque: Rgba::rgb(0x10, 0x14, 0x1E),
            translucent: Rgba::rgb(0x10, 0x14, 0x1E).with_alpha(0xD9),
        },
        rail: SurfaceFill {
            opaque: Rgba::rgb(0x0A, 0x0D, 0x15),
            translucent: Rgba::rgb(0x0A, 0x0D, 0x15).with_alpha(0xCC),
        },
        rail_hover: Rgba::rgb(0x14, 0x19, 0x25),
        border_subtle: Rgba::rgb(0x23, 0x2A, 0x3A),
        border_strong: Rgba::rgb(0x39, 0x44, 0x5A),
        control: Rgba::rgb(0x1A, 0x20, 0x30),
        control_hover: Rgba::rgb(0x23, 0x2B, 0x3D),
        control_pressed: Rgba::rgb(0x14, 0x19, 0x24),
        text_primary: Rgba::rgb(0xE9, 0xED, 0xF5),
        text_secondary: Rgba::rgb(0xAE, 0xB6, 0xC7),
        text_muted: Rgba::rgb(0x88, 0x92, 0xA7),
        text_disabled: Rgba::rgb(0x53, 0x5C, 0x70),
        text_on_accent: Rgba::rgb(0x04, 0x13, 0x1A),
        accent_cyan: Rgba::rgb(0x3C, 0xD6, 0xF2),
        accent_magenta: Rgba::rgb(0xD0, 0x6C, 0xF2),
        accent_blue: Rgba::rgb(0x62, 0x83, 0xFF),
        primary_hover: Rgba::rgb(0x6F, 0xE2, 0xF6),
        primary_pressed: Rgba::rgb(0x22, 0xB3, 0xCF),
        focus_ring: Rgba::rgb(0x3C, 0xD6, 0xF2),
        success: Rgba::rgb(0x3D, 0xDC, 0x97),
        warning: Rgba::rgb(0xF2, 0xC1, 0x4E),
        danger: Rgba::rgb(0xF2, 0x66, 0x7E),
        chrome_active_bar: Rgba::rgb(0x16, 0x1C, 0x29),
        chrome_inactive_bar: Rgba::rgb(0x0E, 0x11, 0x19),
        chrome_active_border: Rgba::rgb(0x2D, 0x66, 0x76),
        chrome_inactive_border: Rgba::rgb(0x1E, 0x24, 0x30),
        chrome_active_title: Rgba::rgb(0xE9, 0xED, 0xF5),
        chrome_inactive_title: Rgba::rgb(0x82, 0x8C, 0xA1),
        chrome_control_active: Rgba::rgb(0xC3, 0xCA, 0xD8),
        chrome_control_inactive: Rgba::rgb(0x68, 0x72, 0x87),
        chrome_control_hover: Rgba::rgb(0x25, 0x2D, 0x3E),
        chrome_control_pressed: Rgba::rgb(0x2F, 0x38, 0x4B),
        chrome_accent: Rgba::rgb(0x3C, 0xD6, 0xF2),
        shadow: Rgba::rgb(0x00, 0x00, 0x00).with_alpha(0x40),
        cursor_fill: Rgba::rgb(0xF3, 0xF6, 0xFB),
        cursor_outline: Rgba::rgb(0x04, 0x06, 0x0A),
        cursor_accent: Rgba::rgb(0x3C, 0xD6, 0xF2),
    },
    spacing: Spacing {
        unit: 4,
        xxs: 2,
        xs: 4,
        sm: 8,
        md: 12,
        lg: 16,
        xl: 24,
        xxl: 32,
    },
    radius: Radius {
        sm: 4,
        md: 8,
        lg: 12,
        pill: u32::MAX,
    },
    stroke: Stroke {
        hairline: 1,
        focus: 2,
        indicator: 3,
    },
    type_scale: TypeScale {
        display: TextStyle {
            scale: 3,
            strong: false,
            leading: 8,
            tone: TextTone::Primary,
        },
        title: TextStyle {
            scale: 2,
            strong: false,
            leading: 6,
            tone: TextTone::Primary,
        },
        heading: TextStyle {
            scale: 1,
            strong: true,
            leading: 6,
            tone: TextTone::Primary,
        },
        body: TextStyle {
            scale: 1,
            strong: false,
            leading: 6,
            tone: TextTone::Secondary,
        },
        label: TextStyle {
            scale: 1,
            strong: false,
            leading: 4,
            tone: TextTone::Primary,
        },
        caption: TextStyle {
            scale: 1,
            strong: false,
            leading: 4,
            tone: TextTone::Muted,
        },
    },
    font: &Spleen8x16,
    shell: ShellMetrics {
        rail_width: 88,
        rail_brand_height: 80,
        rail_item_height: 60,
        rail_item_gap: 4,
        rail_item_inset: 8,
        search_band_height: 72,
        search_field_width: 480,
        search_field_height: 40,
        context_width: 304,
        zone_padding: 32,
    },
    chrome: ChromeMetrics {
        title_bar_height: 32,
        border_width: 1,
        corner_radius: 8,
        control_size: 24,
        control_gap: 4,
        control_inset: 6,
        title_padding: 12,
        resize_margin: 6,
    },
    elevation: Elevation {
        window_focused: ShadowToken {
            layers: 6,
            offset_y: 4,
        },
        window_inactive: ShadowToken {
            layers: 3,
            offset_y: 2,
        },
    },
    budget: RenderBudget {
        max_tier: QualityTier::Q1,
        shell_buffers: 3,
        max_damage_rects_per_update: 2,
        max_damage_area_per_update: 2 * 88 * 60,
    },
};

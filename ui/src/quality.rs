//! Quality tiers, the effects they enable, and the [`Style`] every primitive paints with.

use clean_slate_graphics::pixel::PixelFormat;

use crate::tokens::{Rgba, SurfaceFill, TextTone, Theme};

/// Visual quality tier. M10 renders Q0 and Q1; Q2 and Q3 clamp to Q1.
///
/// | Tier | Surfaces | Effects |
/// |---|---|---|
/// | Q0 | `Xrgb8888`, opaque | none: no translucency, shadow, blur or animation |
/// | Q1 | `Argb8888Premultiplied` where needed | restrained translucency, cheap layered shadow |
/// | Q2 | (future) | richer shadows and transitions |
/// | Q3 | (future) | backdrop blur and premium effects |
#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum QualityTier {
    /// Opaque surfaces, no effects.
    Q0 = 0,
    /// Alpha-capable surfaces with restrained translucency.
    Q1 = 1,
    /// Richer shadows and transitions (not rendered in M10).
    Q2 = 2,
    /// Backdrop blur and premium effects (not rendered in M10).
    Q3 = 3,
}

impl QualityTier {
    /// Highest tier M10 renders.
    pub const M10_MAX: Self = Self::Q1;

    /// `self` clamped to [`Self::M10_MAX`].
    pub const fn clamp_m10(self) -> Self {
        match self {
            Self::Q0 => Self::Q0,
            _ => Self::M10_MAX,
        }
    }

    /// Pixel format for a surface whose content may be translucent at this tier.
    pub const fn translucent_surface_format(self) -> PixelFormat {
        match self.clamp_m10() {
            Self::Q0 => PixelFormat::Xrgb8888,
            _ => PixelFormat::Argb8888Premultiplied,
        }
    }
}

/// Individually switchable effects. Each one degrades to an opaque, effect-free rendering
/// that keeps the same layout, so the shell stays coherent with any subset disabled.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Effects {
    /// Translucent fills ([`SurfaceFill::translucent`]); otherwise the opaque fallback.
    pub translucency: bool,
    /// Layered window shadows; otherwise borders alone separate windows.
    pub shadows: bool,
    /// Backdrop blur. Never enabled in M10.
    pub blur: bool,
    /// Transitions. Never enabled in M10; every state change is an immediate repaint.
    pub animation: bool,
}

impl Effects {
    /// Everything off (Q0).
    pub const OPAQUE: Self = Self {
        translucency: false,
        shadows: false,
        blur: false,
        animation: false,
    };

    /// Effects for `tier` after clamping to [`QualityTier::M10_MAX`].
    pub const fn for_tier(tier: QualityTier) -> Self {
        match tier.clamp_m10() {
            QualityTier::Q0 => Self::OPAQUE,
            _ => Self {
                translucency: true,
                shadows: true,
                blur: false,
                animation: false,
            },
        }
    }

    /// Same effects with translucency disabled.
    pub const fn without_translucency(self) -> Self {
        Self {
            translucency: false,
            ..self
        }
    }

    /// Same effects with shadows disabled.
    pub const fn without_shadows(self) -> Self {
        Self {
            shadows: false,
            ..self
        }
    }
}

/// Theme plus effects: the only styling input to every primitive.
#[derive(Clone, Copy)]
pub struct Style<'t> {
    /// Token set.
    pub theme: &'t Theme,
    /// Effects in force.
    pub effects: Effects,
}

impl<'t> Style<'t> {
    /// Style for `theme` at `tier`.
    pub const fn new(theme: &'t Theme, tier: QualityTier) -> Self {
        Self {
            theme,
            effects: Effects::for_tier(tier),
        }
    }

    /// Style with explicit effects.
    pub const fn with_effects(theme: &'t Theme, effects: Effects) -> Self {
        Self { theme, effects }
    }

    /// Colour for a text tone.
    pub const fn tone(&self, tone: TextTone) -> Rgba {
        self.theme.palette.tone(tone)
    }

    /// Translucent or opaque variant of `fill` according to [`Effects::translucency`].
    pub const fn surface(&self, fill: SurfaceFill) -> Rgba {
        if self.effects.translucency {
            fill.translucent
        } else {
            fill.opaque
        }
    }
}

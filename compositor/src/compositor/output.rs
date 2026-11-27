//! Display modes (#314): the start-up mode choice and the re-layout after the output changes.
//!
//! The compositor never assumes a size. At start it asks for [`ModeList::choose`]; whenever a
//! fresh `QUERY_MODE` (epoch change or reset) reports another size, every toplevel is moved so
//! its whole frame is on the output and gets a `Configure` with the new bounds (and a smaller
//! size when its frame no longer fits), the pointer is clamped, and every connection that
//! negotiated `OUTPUT_EVENTS` (the shell) gets `OutputChanged`.
//!
//! [`ModeList::choose`]: clean_slate_graphics::mode::ModeList::choose

use clean_slate_graphics::geometry::{Point, Rect, Size};
use clean_slate_graphics::limits::{MAX_SURFACES, MAX_SURFACE_EXTENT};
use clean_slate_graphics::protocol::{Event, Features};
use clean_slate_graphics::role::SurfaceRole;
use clean_slate_graphics::window::{WindowConfig, WindowStates};

use super::{send_configure, Compositor, UNSOLICITED_TAG};
use crate::backend::DisplayBackend;
use crate::scene::SurfaceKey;
use crate::wm::{self, WindowPolicy};

/// The start-up `SET_MODE`: the chosen size when it differs from the current one and the
/// display accepted it. Any failure keeps the current mode; it never stops the compositor.
pub(super) fn pick_mode(display: &mut dyn DisplayBackend) -> Option<Size> {
    let modes = display.query_modes().ok()?;
    let choice = modes.choose()?;
    let current = modes.current()?;
    if (choice.width_px, choice.height_px) == (current.width_px, current.height_px) {
        return None;
    }
    display.set_mode(choice.width_px, choice.height_px).ok()?;
    Some(Size {
        width: choice.width_px,
        height: choice.height_px,
    })
}

impl<P: WindowPolicy> Compositor<P> {
    /// Largest content a `Configure` may ask for on the current output.
    pub(super) fn bounds(&self) -> Size {
        let output = self.output_size();
        Size {
            width: output.width.min(MAX_SURFACE_EXTENT),
            height: output.height.min(MAX_SURFACE_EXTENT),
        }
    }

    /// The output now has another size: re-lay out what depends on it and repaint everything.
    pub(super) fn output_changed(&mut self) {
        let output = self.output_size();
        self.seat.warp(self.seat.pointer(), output);
        let at = self.seat.pointer();
        self.move_cursor(at);
        self.fit_windows(output);
        if let Some(present) = self.present {
            let event = Event::OutputChanged {
                output: present.output_info(),
            };
            let wants = Features(Features::OUTPUT_EVENTS);
            for client in self.clients.iter_mut() {
                if client.is_live() && client.features().contains(wants) {
                    client.queue(UNSOLICITED_TAG, event);
                }
            }
        }
        self.stats.output_changes += 1;
        self.damage_full_output();
    }

    /// Moves every placed toplevel so its frame is on `output` and sends each window the new
    /// bounds; a frame larger than the output also gets a size that fits.
    fn fit_windows(&mut self, output: Size) {
        let bounds = self.bounds();
        let mut moves: [Option<(SurfaceKey, Point)>; MAX_SURFACES] = [None; MAX_SURFACES];
        let mut count = 0;
        let Self {
            scene,
            clients,
            policy,
            ..
        } = self;
        for (_, entry) in scene.iter() {
            if entry.role != Some(SurfaceRole::Toplevel) {
                continue;
            }
            let client = &mut clients[entry.client];
            let Ok(surface) = client.objects.surface(entry.key.surface) else {
                continue;
            };
            let Some(window) = surface.window else {
                continue;
            };
            let committed = *surface.state.committed();
            let content_size = committed.size();
            let mut fitted = None;
            if let (Some(origin), Some(_)) = (entry.origin, committed.buffer()) {
                let content = Rect {
                    x: origin.x,
                    y: origin.y,
                    width: content_size.width,
                    height: content_size.height,
                };
                let frame = policy.chrome().map_or(content, |c| c.frame_rect(content));
                let offset = Point {
                    x: wm::to_i32(i64::from(frame.x) - i64::from(content.x)),
                    y: wm::to_i32(i64::from(frame.y) - i64::from(content.y)),
                };
                let frame_size = Size {
                    width: frame.width,
                    height: frame.height,
                };
                let at = wm::fit_inside(offset, frame_size, origin, output);
                if at != origin && count < moves.len() {
                    moves[count] = Some((entry.key, at));
                    count += 1;
                }
                if frame.width > output.width || frame.height > output.height {
                    fitted = Some(wm::fit_size(content_size, frame_size, output));
                }
            }
            let Ok(entry) = client.objects.window(window) else {
                continue;
            };
            let current = entry
                .wanted
                .or_else(|| entry.configure.last_sent().map(|(_, c)| c))
                .or_else(|| entry.configure.acked().map(|(_, c)| c));
            let base = current.unwrap_or(WindowConfig::new(
                Size {
                    width: 0,
                    height: 0,
                },
                WindowStates::EMPTY,
                bounds,
            ));
            let size = fitted.unwrap_or(Size {
                width: base.size.width.min(bounds.width),
                height: base.size.height.min(bounds.height),
            });
            let config = WindowConfig {
                size,
                bounds,
                ..base
            };
            if current != Some(config) {
                let _ = send_configure(client, window, config, UNSOLICITED_TAG);
            }
        }
        for (key, at) in moves.into_iter().flatten() {
            if self.wm.anchor.is_some_and(|a| a.key == key) {
                self.wm.anchor = None;
            }
            self.move_surface(key, at);
        }
    }
}

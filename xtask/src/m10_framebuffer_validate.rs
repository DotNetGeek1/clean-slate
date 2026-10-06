//! Host-side parity checks for the M10 #111 GOP framebuffer lane: the serial readback and the
//! QMP screendump of the final frame.

use std::sync::OnceLock;

use clean_slate_raster::{
    draw_reference_a, draw_reference_b, pixel_at, reference_layout, visible_crc32, Canvas,
    REFERENCE_PROBES,
};

use crate::qmp::image::Screenshot;
use crate::XtaskError;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct GuestProbe {
    pub x: u32,
    pub y: u32,
    pub bgrx: [u8; 4],
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct GuestReadback {
    pub crc32: u32,
    pub probes: Vec<GuestProbe>,
}

/// The guest's final scanout: pattern A, then pattern B over it (the decoy is never damaged).
fn host_scanout_bytes() -> Vec<u8> {
    let layout = reference_layout();
    let mut bytes = vec![0u8; layout.byte_len()];
    let mut canvas = Canvas::new(&mut bytes, layout).expect("reference layout");
    draw_reference_a(&mut canvas);
    draw_reference_b(&mut canvas);
    bytes
}

pub(crate) fn host_scanout_expectations() -> (u32, Vec<GuestProbe>) {
    let layout = reference_layout();
    let bytes = host_scanout_bytes();
    let crc = visible_crc32(&bytes, layout).expect("reference crc");
    let probes = REFERENCE_PROBES
        .iter()
        .map(|&(x, y)| GuestProbe {
            x,
            y,
            bgrx: pixel_at(&bytes, layout, x, y).expect("probe pixel"),
        })
        .collect();
    (crc, probes)
}

pub(crate) fn parse_guest_readback(serial: &str) -> Option<GuestReadback> {
    let mut crc32 = None;
    let mut probes = Vec::new();
    for line in serial.lines() {
        let line = line.trim_end();
        if let Some(rest) = line.strip_prefix("[FB  ] readback crc32=0x") {
            let hex = rest.trim();
            if hex.len() != 8 {
                return None;
            }
            crc32 = u32::from_str_radix(hex, 16).ok();
            continue;
        }
        if let Some(rest) = line.strip_prefix("[FB  ] probe x=") {
            let (coords, colors) = rest.split_once(" bgrx=")?;
            let (x, y) = coords
                .split_once(" y=")
                .and_then(|(x, y)| Some((x.parse::<u32>().ok()?, y.parse::<u32>().ok()?)))?;
            if colors.len() != 8 {
                return None;
            }
            let mut bgrx = [0u8; 4];
            for (index, chunk) in colors.as_bytes().chunks(2).enumerate() {
                if chunk.len() != 2 {
                    return None;
                }
                let pair = std::str::from_utf8(chunk).ok()?;
                bgrx[index] = u8::from_str_radix(pair, 16).ok()?;
            }
            probes.push(GuestProbe { x, y, bgrx });
        }
    }
    let crc32 = crc32?;
    if probes.len() != REFERENCE_PROBES.len() {
        return None;
    }
    Some(GuestReadback { crc32, probes })
}

pub(crate) fn compare_readback(
    guest: &GuestReadback,
    expected_crc: u32,
    expected_probes: &[GuestProbe],
) -> Result<(), String> {
    if guest.crc32 != expected_crc {
        return Err(format!(
            "crc32 expected=0x{expected_crc:08x} actual=0x{actual:08x}",
            actual = guest.crc32
        ));
    }
    for (guest_probe, expected) in guest.probes.iter().zip(expected_probes.iter()) {
        if guest_probe.x != expected.x
            || guest_probe.y != expected.y
            || guest_probe.bgrx != expected.bgrx
        {
            return Err(format!(
                "probe ({}, {}) expected bgrx={:02x}{:02x}{:02x}{:02x} actual bgrx={:02x}{:02x}{:02x}{:02x}",
                guest_probe.x,
                guest_probe.y,
                expected.bgrx[0],
                expected.bgrx[1],
                expected.bgrx[2],
                expected.bgrx[3],
                guest_probe.bgrx[0],
                guest_probe.bgrx[1],
                guest_probe.bgrx[2],
                guest_probe.bgrx[3],
            ));
        }
    }
    Ok(())
}

/// Host render of the final scanout as screendump RGB (BGRX bytes reordered, X dropped).
fn host_scanout_rgb() -> &'static [u8] {
    static RGB: OnceLock<Vec<u8>> = OnceLock::new();
    RGB.get_or_init(|| {
        let layout = reference_layout();
        let bytes = host_scanout_bytes();
        let mut rgb = Vec::with_capacity(layout.width() as usize * layout.height() as usize * 3);
        for y in 0..layout.height() {
            for x in 0..layout.width() {
                let [b, g, r, _] = pixel_at(&bytes, layout, x, y).expect("visible pixel");
                rgb.extend_from_slice(&[r, g, b]);
            }
        }
        rgb
    })
}

/// QMP screendump check for the `m10-framebuffer` lane: the whole 1280x800 frame must equal the
/// host raster render pixel for pixel. Reports the mismatch count and the first differing pixel.
pub(crate) fn check_m10_framebuffer_screenshot(shot: &Screenshot) -> Result<(), String> {
    let layout = reference_layout();
    if (shot.width(), shot.height()) != (layout.width(), layout.height()) {
        return Err(format!(
            "expected a {}x{} frame, got {}x{}",
            layout.width(),
            layout.height(),
            shot.width(),
            shot.height()
        ));
    }
    let expected = host_scanout_rgb();
    let mut mismatches = 0usize;
    let mut first = None;
    for (index, (got, want)) in shot
        .rgb()
        .chunks_exact(3)
        .zip(expected.chunks_exact(3))
        .enumerate()
    {
        if got != want {
            mismatches += 1;
            first.get_or_insert((index, [got[0], got[1], got[2]], [want[0], want[1], want[2]]));
        }
    }
    match first {
        None => Ok(()),
        Some((index, got, want)) => {
            let width = layout.width() as usize;
            Err(format!(
                "{mismatches} pixels differ from the host render; first at ({},{}) rgb={got:02x?} expected={want:02x?}",
                index % width,
                index / width
            ))
        }
    }
}

pub(crate) fn validate_m10_framebuffer_serial(serial: &str) -> Result<(), XtaskError> {
    let guest = parse_guest_readback(serial).ok_or_else(|| {
        XtaskError::Validation("m10 framebuffer: missing or malformed readback/probe lines".into())
    })?;
    let (expected_crc, expected_probes) = host_scanout_expectations();
    compare_readback(&guest, expected_crc, &expected_probes).map_err(|detail| {
        eprintln!("[FAIL] m10-framebuffer readback {detail}");
        XtaskError::Validation(format!("m10 framebuffer readback: {detail}"))
    })?;
    println!("[M10.2] host readback match crc32=0x{:08x}", expected_crc);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use clean_slate_raster::{draw_reference_a, pixel_at, reference_layout, REFERENCE_PROBES};

    #[test]
    fn host_expectation_crc_matches_golden() {
        let (crc, _) = host_scanout_expectations();
        assert_eq!(crc, 0x20F2_EEC9);
    }

    #[test]
    fn decoy_probe_matches_pattern_a_only() {
        let layout = reference_layout();
        let mut bytes = vec![0u8; layout.byte_len()];
        draw_reference_a(&mut Canvas::new(&mut bytes, layout).unwrap());
        let (dx, dy) = REFERENCE_PROBES[5];
        let a_px = pixel_at(&bytes, layout, dx, dy).unwrap();
        let (_, probes) = host_scanout_expectations();
        let expected = probes
            .iter()
            .find(|p| p.x == dx && p.y == dy)
            .expect("decoy probe");
        assert_eq!(expected.bgrx, a_px);
    }

    #[test]
    fn parse_readback_round_trip() {
        let (crc, probes) = host_scanout_expectations();
        let mut serial = String::new();
        serial.push_str(&format!("[FB  ] readback crc32=0x{crc:08x}\n"));
        for probe in &probes {
            serial.push_str(&format!(
                "[FB  ] probe x={} y={} bgrx={:02x}{:02x}{:02x}{:02x}\n",
                probe.x, probe.y, probe.bgrx[0], probe.bgrx[1], probe.bgrx[2], probe.bgrx[3],
            ));
        }
        let parsed = parse_guest_readback(&serial).expect("parse");
        assert_eq!(parsed.crc32, crc);
        assert_eq!(parsed.probes, probes);
    }

    fn host_screenshot() -> Screenshot {
        let layout = reference_layout();
        Screenshot::new(layout.width(), layout.height(), host_scanout_rgb().to_vec())
            .expect("host frame")
    }

    #[test]
    fn screenshot_of_the_host_render_passes() {
        assert_eq!(check_m10_framebuffer_screenshot(&host_screenshot()), Ok(()));
    }

    #[test]
    fn screenshot_rgb_is_the_bgrx_scanout_reordered() {
        let (_, probes) = host_scanout_expectations();
        let shot = host_screenshot();
        for probe in probes {
            let [b, g, r, _] = probe.bgrx;
            assert_eq!(shot.pixel(probe.x, probe.y), Some([r, g, b]));
        }
    }

    #[test]
    fn one_stray_pixel_fails_the_screenshot() {
        let layout = reference_layout();
        let mut rgb = host_scanout_rgb().to_vec();
        let (x, y) = REFERENCE_PROBES[5];
        let index = (y * layout.width() + x) as usize * 3;
        rgb[index] ^= 0x80;
        let shot = Screenshot::new(layout.width(), layout.height(), rgb).unwrap();
        let err = check_m10_framebuffer_screenshot(&shot).unwrap_err();
        assert!(err.starts_with("1 pixels differ"), "{err}");
        assert!(err.contains(&format!("({x},{y})")), "{err}");
    }

    #[test]
    fn screenshot_with_pattern_a_only_or_the_wrong_size_fails() {
        let layout = reference_layout();
        let mut bytes = vec![0u8; layout.byte_len()];
        draw_reference_a(&mut Canvas::new(&mut bytes, layout).unwrap());
        let mut rgb = Vec::new();
        for y in 0..layout.height() {
            for x in 0..layout.width() {
                let [b, g, r, _] = pixel_at(&bytes, layout, x, y).unwrap();
                rgb.extend_from_slice(&[r, g, b]);
            }
        }
        let a_only = Screenshot::new(layout.width(), layout.height(), rgb).unwrap();
        assert!(check_m10_framebuffer_screenshot(&a_only).is_err());

        let small = Screenshot::new(640, 480, vec![0; 640 * 480 * 3]).unwrap();
        assert_eq!(
            check_m10_framebuffer_screenshot(&small),
            Err("expected a 1280x800 frame, got 640x480".to_owned())
        );
    }

    #[test]
    fn corrupted_probe_reports_mismatch() {
        let (crc, probes) = host_scanout_expectations();
        let mut guest = GuestReadback {
            crc32: crc,
            probes: probes.clone(),
        };
        guest.probes[0].bgrx[0] ^= 0x01;
        let err = compare_readback(&guest, crc, &probes).unwrap_err();
        assert!(err.contains("probe"));
    }
}

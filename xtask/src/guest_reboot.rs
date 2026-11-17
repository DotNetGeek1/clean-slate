//! Detects a guest that boots again inside one QEMU session (#253).
//!
//! Lanes run QEMU with `-no-reboot`, so a triple fault or a reset request ends QEMU. An INIT IPI
//! does not: QEMU resets only the CPU, the firmware boots the ESP again in the same session and
//! the transcript simply continues, so a lane that matches markers anywhere in its transcript can
//! pass on the second boot or time out far from the cause. A stray kernel store to the local APIC
//! page is one way to send that INIT. Every lane read loop feeds its transcript to a
//! [`GuestRebootDetector`] and fails at once, keeping the transcript.
//!
//! No lane boots twice in one QEMU session; lanes that need two boots start QEMU twice, and each
//! session is checked on its own.
//!
//! The detector keys on [`KERNEL_BOOT_BANNER`]; if the kernel stopped printing it, every reboot
//! would go unseen. So every lane that boots the kernel also refuses to pass a session whose
//! transcript never showed the banner ([`GuestRebootDetector::require_kernel_banner`]): rewording
//! or dropping the banner fails every such lane at once instead of quietly disabling the check.

/// Printed by OVMF's boot manager for each boot option it tries.
pub(crate) const FIRMWARE_BOOT_BANNER: &[u8] = b"BdsDxe: loading Boot";
/// The kernel's first line, printed once per boot.
pub(crate) const KERNEL_BOOT_BANNER: &[u8] = b"[BOOT] UEFI memory map acquired";

/// Watches one QEMU session's transcript for a second boot.
///
/// The firmware banner may repeat before the kernel starts (a boot option that fails falls
/// through to the next one), so only a firmware banner after the first kernel banner, or a second
/// kernel banner, counts as a reboot.
///
/// Lane loops call [`GuestRebootDetector::observe`] after every read, so it searches only the
/// bytes added since the previous call (plus enough of the old tail to catch a banner split
/// across reads). Rescanning the whole transcript on each read is quadratic, and on a chatty lane
/// it slowed the host reader enough to stall the guest on a full serial pipe.
#[derive(Debug, Default)]
pub(crate) struct GuestRebootDetector {
    scanned: usize,
    kernel_banner_end: Option<usize>,
}

impl GuestRebootDetector {
    /// The failure message once `transcript` shows a second boot, or `None`. `transcript` is the
    /// whole session so far and must only grow between calls.
    pub(crate) fn observe(&mut self, transcript: &[u8]) -> Option<String> {
        let longest_banner = KERNEL_BOOT_BANNER.len().max(FIRMWARE_BOOT_BANNER.len());
        let from = self.scanned.saturating_sub(longest_banner - 1);
        self.scanned = transcript.len();
        let kernel_banner_end = match self.kernel_banner_end {
            Some(end) => end,
            None => {
                let start = from + find(&transcript[from..], KERNEL_BOOT_BANNER)?;
                let end = start + KERNEL_BOOT_BANNER.len();
                self.kernel_banner_end = Some(end);
                end
            }
        };
        let after_kernel = &transcript[from.max(kernel_banner_end)..];
        let (what, banner) = if find(after_kernel, KERNEL_BOOT_BANNER).is_some() {
            ("a second kernel boot banner", KERNEL_BOOT_BANNER)
        } else if find(after_kernel, FIRMWARE_BOOT_BANNER).is_some() {
            (
                "a firmware boot banner after the kernel had started",
                FIRMWARE_BOOT_BANNER,
            )
        } else {
            return None;
        };
        Some(format!(
            "guest rebooted mid-run: {what} ({:?}) in one QEMU session",
            String::from_utf8_lossy(banner)
        ))
    }

    /// Fails unless an earlier [`observe`](Self::observe) saw the kernel boot banner. Lanes call it
    /// before reporting a pass, so a kernel that no longer prints the banner cannot blind the
    /// detector without failing every lane.
    pub(crate) fn require_kernel_banner(&self) -> Result<(), String> {
        if self.kernel_banner_end.is_some() {
            return Ok(());
        }
        Err(format!(
            "the session passed without the kernel boot banner ({:?}): either the guest is not this \
             kernel or the banner in kernel/src/boot/mod.rs changed, and the guest-reboot check \
             cannot see a second boot without it",
            String::from_utf8_lossy(KERNEL_BOOT_BANNER)
        ))
    }
}

fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

#[cfg(test)]
mod tests {
    use super::*;

    const FIRMWARE: &str = "\x1b[2J\x1b[01;01HBdsDxe: loading Boot0001 \"UEFI QEMU HARDDISK QM00001 \" from PciRoot(0x0)\r\nBdsDxe: starting Boot0001\r\n";
    const KERNEL: &str = "[BOOT] UEFI memory map acquired\n[BOOT] ExitBootServices OK\n";

    /// Observes `transcript` in one read and again one byte per read, so every banner is also
    /// seen split at every possible read boundary, and requires the same answer from both.
    fn guest_reboot(transcript: &[u8]) -> Option<String> {
        let whole = GuestRebootDetector::default().observe(transcript);
        let mut detector = GuestRebootDetector::default();
        let mut per_byte = None;
        for end in 0..=transcript.len() {
            per_byte = detector.observe(&transcript[..end]);
            let fresh = GuestRebootDetector::default().observe(&transcript[..end]);
            assert_eq!(
                per_byte, fresh,
                "per-byte observation disagrees at byte {end}"
            );
            if per_byte.is_some() {
                break;
            }
        }
        assert_eq!(whole, per_byte, "whole and per-byte observation disagree");
        whole
    }

    #[test]
    fn one_boot_is_not_a_reboot() {
        assert_eq!(guest_reboot(b""), None);
        assert_eq!(guest_reboot(FIRMWARE.as_bytes()), None);
        let one_boot = format!("{FIRMWARE}{KERNEL}[SYS ] ready\n");
        assert_eq!(guest_reboot(one_boot.as_bytes()), None);
    }

    #[test]
    fn a_pass_requires_the_kernel_banner_to_have_been_seen() {
        let mut detector = GuestRebootDetector::default();
        assert!(
            detector.require_kernel_banner().is_err(),
            "nothing observed"
        );
        assert_eq!(detector.observe(FIRMWARE.as_bytes()), None);
        let reworded = format!("{FIRMWARE}[BOOT] UEFI memory map obtained\n[SYS ] ready\n");
        assert_eq!(detector.observe(reworded.as_bytes()), None);
        let message = detector
            .require_kernel_banner()
            .expect_err("reworded banner");
        assert!(
            message.contains("without the kernel boot banner"),
            "{message}"
        );

        let mut detector = GuestRebootDetector::default();
        let one_boot = format!("{FIRMWARE}{KERNEL}[SYS ] ready\n");
        for end in 0..=one_boot.len() {
            assert_eq!(detector.observe(&one_boot.as_bytes()[..end]), None);
        }
        assert_eq!(detector.require_kernel_banner(), Ok(()));
    }

    #[test]
    fn firmware_retrying_boot_options_before_the_kernel_is_not_a_reboot() {
        let fallback = format!(
            "BdsDxe: loading Boot0002 \"UEFI PXEv4\"\r\nBdsDxe: failed to load Boot0002\r\n{FIRMWARE}{KERNEL}"
        );
        assert_eq!(guest_reboot(fallback.as_bytes()), None);
    }

    #[test]
    fn firmware_banner_after_the_kernel_is_a_reboot() {
        let reset = format!("{FIRMWARE}{KERNEL}[NET ] released\n{FIRMWARE}");
        let message = guest_reboot(reset.as_bytes()).expect("reboot");
        assert!(message.starts_with("guest rebooted mid-run: "), "{message}");
        assert!(message.contains("firmware boot banner"), "{message}");
    }

    #[test]
    fn second_kernel_banner_is_a_reboot_even_without_firmware_output() {
        let reset = format!("{KERNEL}[TIME] ticks=3\n{KERNEL}");
        let message = guest_reboot(reset.as_bytes()).expect("reboot");
        assert!(message.starts_with("guest rebooted mid-run: "), "{message}");
        assert!(message.contains("second kernel boot banner"), "{message}");
    }

    #[test]
    fn reboot_is_seen_in_a_partial_second_boot() {
        let partial = format!("{FIRMWARE}{KERNEL}[BLK ] request op=read id=2\nBdsDxe: loading Bo");
        assert_eq!(
            guest_reboot(partial.as_bytes()),
            None,
            "banner not complete yet"
        );
        let complete = format!("{partial}ot0001");
        assert!(guest_reboot(complete.as_bytes()).is_some());

        let mut detector = GuestRebootDetector::default();
        assert_eq!(detector.observe(partial.as_bytes()), None);
        assert!(detector.observe(complete.as_bytes()).is_some());
    }

    #[test]
    fn a_long_single_boot_read_in_small_chunks_is_not_a_reboot() {
        let mut transcript = format!("{FIRMWARE}{KERNEL}");
        let mut detector = GuestRebootDetector::default();
        for cycle in 0..2000 {
            transcript.push_str(&format!("[NET ] capacity cycle={cycle} BdsDxe [BOOT]\n"));
            assert_eq!(detector.observe(transcript.as_bytes()), None);
        }
    }

    #[test]
    fn the_reproduced_reset_transcript_is_a_reboot() {
        // Shape of the #253 reproduction: the kernel runs, then OVMF clears the screen and boots
        // again in the same session.
        let transcript = format!(
            "{FIRMWARE}{KERNEL}[KERN] scheduler initialized\n[NET ] released\n\
             \x1b[2J\x1b[01;01H\x1b[=3h\x1b[2J\x1b[01;01HBdsDxe: loading Boot0001 \"UEFI QEMU HARDDISK QM00001 \r\n\
             BdsDxe: starting"
        );
        assert!(guest_reboot(transcript.as_bytes()).is_some());
    }
}

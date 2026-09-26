//! Bounded Linux path normalization (bytes, not UTF-8).

use clean_slate_linux_abi::{LinuxErrno, ENAMETOOLONG};

pub const LINUX_PATH_MAX: usize = 256;

pub fn copy_bounded_path(input: &[u8]) -> Result<[u8; LINUX_PATH_MAX], LinuxErrno> {
    if input.len() >= LINUX_PATH_MAX {
        return Err(ENAMETOOLONG);
    }
    if input.contains(&0) {
        return Err(clean_slate_linux_abi::EINVAL);
    }
    let mut out = [0u8; LINUX_PATH_MAX];
    out[..input.len()].copy_from_slice(input);
    Ok(out)
}

/// Normalize `input` into `out` (absolute, no `//`, `.` dropped, `..` pops, root clamped).
pub fn normalize_path(input: &[u8], out: &mut [u8; LINUX_PATH_MAX]) -> Result<usize, LinuxErrno> {
    if input.len() >= LINUX_PATH_MAX {
        return Err(ENAMETOOLONG);
    }
    if input.contains(&0) {
        return Err(clean_slate_linux_abi::EINVAL);
    }
    let mut components: [[u8; 64]; 32] = [[0; 64]; 32];
    let mut comp_lens = [0usize; 32];
    let mut comp_count = 0usize;
    let mut i = 0usize;
    let absolute = !input.is_empty() && input[0] == b'/';
    while i < input.len() {
        while i < input.len() && input[i] == b'/' {
            i += 1;
        }
        if i >= input.len() {
            break;
        }
        let start = i;
        while i < input.len() && input[i] != b'/' {
            i += 1;
        }
        let seg = &input[start..i];
        if seg == b"." {
            continue;
        }
        if seg == b".." {
            comp_count = comp_count.saturating_sub(1);
            continue;
        }
        if seg.len() > 64 || comp_count >= 32 {
            return Err(ENAMETOOLONG);
        }
        components[comp_count][..seg.len()].copy_from_slice(seg);
        comp_lens[comp_count] = seg.len();
        comp_count += 1;
    }
    let mut pos = 0usize;
    if absolute || comp_count == 0 {
        out[pos] = b'/';
        pos += 1;
    }
    for index in 0..comp_count {
        if pos > 1 {
            if pos >= LINUX_PATH_MAX {
                return Err(ENAMETOOLONG);
            }
            out[pos] = b'/';
            pos += 1;
        }
        let len = comp_lens[index];
        if pos + len > LINUX_PATH_MAX {
            return Err(ENAMETOOLONG);
        }
        out[pos..pos + len].copy_from_slice(&components[index][..len]);
        pos += len;
    }
    if pos == 0 {
        out[0] = b'/';
        pos = 1;
    }
    Ok(pos)
}

/// Resolve `input` against an absolute normalized `cwd` (M9: `getcwd` is `/` until `chdir`).
pub fn resolve_path(
    cwd: &[u8],
    input: &[u8],
    out: &mut [u8; LINUX_PATH_MAX],
) -> Result<usize, LinuxErrno> {
    if input.is_empty() {
        return normalize_path(cwd, out);
    }
    if input[0] == b'/' {
        return normalize_path(input, out);
    }
    let mut scratch = [0u8; LINUX_PATH_MAX];
    let cwd_len = normalize_path(cwd, &mut scratch)?;
    let mut pos = cwd_len;
    if pos + 1 + input.len() >= LINUX_PATH_MAX {
        return Err(ENAMETOOLONG);
    }
    if scratch[pos - 1] != b'/' {
        scratch[pos] = b'/';
        pos += 1;
    }
    scratch[pos..pos + input.len()].copy_from_slice(input);
    pos += input.len();
    normalize_path(&scratch[..pos], out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn norm(s: &[u8]) -> Vec<u8> {
        let mut buf = [0u8; LINUX_PATH_MAX];
        let len = normalize_path(s, &mut buf).expect("norm");
        buf[..len].to_vec()
    }

    #[test]
    fn double_slash_and_dot() {
        assert_eq!(norm(b"//etc/./hostname"), b"/etc/hostname");
    }

    #[test]
    fn dotdot_clamped_at_root() {
        assert_eq!(norm(b"/.."), b"/");
        assert_eq!(norm(b"/tmp/../etc/hostname"), b"/etc/hostname");
    }

    #[test]
    fn trailing_slash() {
        assert_eq!(norm(b"/bin/"), b"/bin");
    }

    #[test]
    fn nul_rejected() {
        let mut buf = [0u8; LINUX_PATH_MAX];
        assert!(normalize_path(b"a\0b", &mut buf).is_err());
    }

    #[test]
    fn relative_path_resolves_against_cwd() {
        let mut out = [0u8; LINUX_PATH_MAX];
        let len = resolve_path(b"/", b"tmp/demo", &mut out).expect("resolve");
        assert_eq!(&out[..len], b"/tmp/demo");
    }

    #[test]
    fn relative_dotdot_cannot_escape_above_root() {
        let mut out = [0u8; LINUX_PATH_MAX];
        let len = resolve_path(b"/", b"..", &mut out).expect("resolve");
        assert_eq!(&out[..len], b"/");
        let len = resolve_path(b"/", b"tmp/../../etc/passwd", &mut out).expect("resolve");
        assert_eq!(&out[..len], b"/etc/passwd");
    }

    #[test]
    fn normalize_uses_path_len_not_padded_storage() {
        let mut padded = [0u8; LINUX_PATH_MAX];
        padded[..7].copy_from_slice(b"/bin/ls");
        let mut out = [0u8; LINUX_PATH_MAX];
        assert_eq!(normalize_path(&padded, &mut out).unwrap_err(), ENAMETOOLONG);
        let len = normalize_path(&padded[..7], &mut out).expect("short slice");
        assert_eq!(&out[..len], b"/bin/ls");
    }
}

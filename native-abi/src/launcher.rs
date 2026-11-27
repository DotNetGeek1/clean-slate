//! The launcher port (#237): a client asks init to start a manifest row by name, and lists the
//! rows it may start.
//!
//! Init serves one port, `ResourceRef::launcher_port()`, registered by the kernel when it
//! launches init; init's `LAUNCH_SERVE` handle is in its bootstrap page. A row with
//! `Grant::LauncherClient` gets a root `LAUNCH_CONNECT` on it. There is no exec of a path:
//! a name names a manifest row that declares it, and init starts that row with exactly the
//! grants the row declares, as it does at boot.
//!
//! Requests (client to init), one 64-byte port frame each; bytes past the payload are zero:
//!
//! | Byte | `LIST` | `START` |
//! |------|--------|---------|
//! | 0 | [`LAUNCHER_REQUEST_LIST`] | [`LAUNCHER_REQUEST_START`] |
//! | 1 | 0 | name length, 1..=[`LAUNCHER_NAME_MAX`] |
//! | 2.. | zero | name |
//!
//! `LIST` is answered with one [`LAUNCHER_EVENT_ENTRY`] per listed row, in manifest order, and
//! then one [`LAUNCHER_EVENT_LIST_END`]. `START` is answered with one
//! [`LAUNCHER_EVENT_START_RESULT`]. Each connection also gets a [`LAUNCHER_EVENT_CHANGED`],
//! laid out as an entry, whenever a listed row's state or instance changes, so a client that
//! listed once stays current. An unknown or malformed request closes the connection.
//!
//! Events (init to client):
//!
//! | Byte | `ENTRY` / `CHANGED` | `LIST_END` | `START_RESULT` |
//! |------|---------------------|------------|----------------|
//! | 0 | kind | [`LAUNCHER_EVENT_LIST_END`] | [`LAUNCHER_EVENT_START_RESULT`] |
//! | 1 | [`AppState`] | entry count | [`StartResult`] |
//! | 2 | name length | zero | zero |
//! | 3 | zero | zero | zero |
//! | 4..8 | service id, little-endian | zero | service id (0 when the name is unknown) |
//! | 8..12 | instance generation (0 before the first start) | zero | zero |
//! | 12..16 | zero | zero | zero |
//! | 16..24 | pid of the live instance, 0 when none | zero | zero |
//! | 24..56 | name | zero | zero |

use crate::port::PORT_FRAME_BYTES;

/// Longest row name, in bytes. Names are printable ASCII without spaces.
pub const LAUNCHER_NAME_MAX: usize = 32;

pub const LAUNCHER_REQUEST_LIST: u8 = 1;
pub const LAUNCHER_REQUEST_START: u8 = 2;

pub const LAUNCHER_EVENT_ENTRY: u8 = 1;
pub const LAUNCHER_EVENT_LIST_END: u8 = 2;
pub const LAUNCHER_EVENT_START_RESULT: u8 = 3;
pub const LAUNCHER_EVENT_CHANGED: u8 = 4;

const NAME_OFFSET: usize = 24;
const _: () = assert!(NAME_OFFSET + LAUNCHER_NAME_MAX <= PORT_FRAME_BYTES);

type Frame = [u8; PORT_FRAME_BYTES];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LauncherFrameError {
    UnknownKind,
    Name,
    UnknownValue,
    ReservedNonZero,
}

/// A row name: 1..=[`LAUNCHER_NAME_MAX`] bytes of printable ASCII other than space.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct AppName {
    len: u8,
    bytes: [u8; LAUNCHER_NAME_MAX],
}

impl AppName {
    pub const fn new(name: &[u8]) -> Option<Self> {
        if name.is_empty() || name.len() > LAUNCHER_NAME_MAX {
            return None;
        }
        let mut bytes = [0u8; LAUNCHER_NAME_MAX];
        let mut index = 0;
        while index < name.len() {
            let byte = name[index];
            if byte <= b' ' || byte > b'~' {
                return None;
            }
            bytes[index] = byte;
            index += 1;
        }
        Some(Self {
            len: name.len() as u8,
            bytes,
        })
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes[..usize::from(self.len)]
    }

    /// The name as text; always valid, since only printable ASCII is accepted.
    pub fn as_str(&self) -> &str {
        core::str::from_utf8(self.as_bytes()).unwrap_or("")
    }

    fn decode(len: u8, bytes: &[u8]) -> Result<Self, LauncherFrameError> {
        let len = usize::from(len);
        if len == 0 || len > LAUNCHER_NAME_MAX || len > bytes.len() {
            return Err(LauncherFrameError::Name);
        }
        if bytes[len..].iter().any(|byte| *byte != 0) {
            return Err(LauncherFrameError::ReservedNonZero);
        }
        Self::new(&bytes[..len]).ok_or(LauncherFrameError::Name)
    }
}

impl core::fmt::Debug for AppName {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "AppName({:?})", self.as_str())
    }
}

/// What init reports for a listed row.
#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AppState {
    /// Not running, and init will start it only when asked: never started, or its last
    /// instance exited or faulted.
    Idle = 0,
    /// Started; it has not reported ready yet.
    Starting = 1,
    /// Reported ready.
    Running = 2,
    /// Its instance ended and init will start it again by its restart policy.
    Restarting = 3,
    /// Init gave up on it, or a row it depends on is down; a `START` is refused.
    Down = 4,
}

impl AppState {
    pub const fn from_u8(raw: u8) -> Option<Self> {
        match raw {
            0 => Some(Self::Idle),
            1 => Some(Self::Starting),
            2 => Some(Self::Running),
            3 => Some(Self::Restarting),
            4 => Some(Self::Down),
            _ => None,
        }
    }

    pub const fn name(self) -> &'static str {
        match self {
            Self::Idle => "idle",
            Self::Starting => "starting",
            Self::Running => "running",
            Self::Restarting => "restarting",
            Self::Down => "down",
        }
    }
}

/// Init's answer to a `START`.
#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StartResult {
    /// Init asked the kernel to start the row.
    Started = 0,
    /// An instance is already starting or running; nothing was started.
    AlreadyRunning = 1,
    /// No listed row has that name.
    UnknownName = 2,
    /// The row's instance ended and init is restarting it, or a row it depends on is not
    /// running yet; ask again later.
    Busy = 3,
    /// Init gave up on the row or on a row it depends on, or the kernel refused the start.
    Refused = 4,
}

impl StartResult {
    pub const fn from_u8(raw: u8) -> Option<Self> {
        match raw {
            0 => Some(Self::Started),
            1 => Some(Self::AlreadyRunning),
            2 => Some(Self::UnknownName),
            3 => Some(Self::Busy),
            4 => Some(Self::Refused),
            _ => None,
        }
    }

    pub const fn name(self) -> &'static str {
        match self {
            Self::Started => "started",
            Self::AlreadyRunning => "already-running",
            Self::UnknownName => "unknown-name",
            Self::Busy => "busy",
            Self::Refused => "refused",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LauncherRequest {
    List,
    Start(AppName),
}

impl LauncherRequest {
    pub fn encode(&self) -> Frame {
        let mut frame = [0u8; PORT_FRAME_BYTES];
        match self {
            Self::List => frame[0] = LAUNCHER_REQUEST_LIST,
            Self::Start(name) => {
                frame[0] = LAUNCHER_REQUEST_START;
                frame[1] = name.len;
                frame[2..2 + name.as_bytes().len()].copy_from_slice(name.as_bytes());
            }
        }
        frame
    }

    pub fn decode(frame: &Frame) -> Result<Self, LauncherFrameError> {
        match frame[0] {
            LAUNCHER_REQUEST_LIST => {
                zero_after(frame, 1)?;
                Ok(Self::List)
            }
            LAUNCHER_REQUEST_START => AppName::decode(frame[1], &frame[2..]).map(Self::Start),
            _ => Err(LauncherFrameError::UnknownKind),
        }
    }
}

/// One listed row as init reports it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AppEntry {
    pub service: u32,
    pub state: AppState,
    /// 0 before the first start.
    pub generation: u32,
    /// The live instance's pid; 0 when none.
    pub pid: u64,
    pub name: AppName,
}

impl AppEntry {
    fn encode_into(&self, kind: u8) -> Frame {
        let mut frame = [0u8; PORT_FRAME_BYTES];
        frame[0] = kind;
        frame[1] = self.state as u8;
        frame[2] = self.name.len;
        frame[4..8].copy_from_slice(&self.service.to_le_bytes());
        frame[8..12].copy_from_slice(&self.generation.to_le_bytes());
        frame[16..24].copy_from_slice(&self.pid.to_le_bytes());
        let name = self.name.as_bytes();
        frame[NAME_OFFSET..NAME_OFFSET + name.len()].copy_from_slice(name);
        frame
    }

    fn decode_from(frame: &Frame) -> Result<Self, LauncherFrameError> {
        let state = AppState::from_u8(frame[1]).ok_or(LauncherFrameError::UnknownValue)?;
        if frame[3] != 0 || frame[12..16].iter().any(|byte| *byte != 0) {
            return Err(LauncherFrameError::ReservedNonZero);
        }
        let name = AppName::decode(frame[2], &frame[NAME_OFFSET..])?;
        Ok(Self {
            service: u32_at(frame, 4),
            state,
            generation: u32_at(frame, 8),
            pid: u64::from_le_bytes(frame[16..24].try_into().unwrap_or([0; 8])),
            name,
        })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LauncherEvent {
    /// An answer to `LIST`.
    Entry(AppEntry),
    /// The end of a `LIST` answer, with the number of entries sent.
    ListEnd { count: u8 },
    /// The answer to `START`; `service` is 0 for [`StartResult::UnknownName`].
    StartResult { result: StartResult, service: u32 },
    /// A listed row's state or instance changed.
    Changed(AppEntry),
}

impl LauncherEvent {
    pub fn encode(&self) -> Frame {
        match self {
            Self::Entry(entry) => entry.encode_into(LAUNCHER_EVENT_ENTRY),
            Self::Changed(entry) => entry.encode_into(LAUNCHER_EVENT_CHANGED),
            Self::ListEnd { count } => {
                let mut frame = [0u8; PORT_FRAME_BYTES];
                frame[0] = LAUNCHER_EVENT_LIST_END;
                frame[1] = *count;
                frame
            }
            Self::StartResult { result, service } => {
                let mut frame = [0u8; PORT_FRAME_BYTES];
                frame[0] = LAUNCHER_EVENT_START_RESULT;
                frame[1] = *result as u8;
                frame[4..8].copy_from_slice(&service.to_le_bytes());
                frame
            }
        }
    }

    pub fn decode(frame: &Frame) -> Result<Self, LauncherFrameError> {
        match frame[0] {
            LAUNCHER_EVENT_ENTRY => AppEntry::decode_from(frame).map(Self::Entry),
            LAUNCHER_EVENT_CHANGED => AppEntry::decode_from(frame).map(Self::Changed),
            LAUNCHER_EVENT_LIST_END => {
                zero_after(frame, 2)?;
                Ok(Self::ListEnd { count: frame[1] })
            }
            LAUNCHER_EVENT_START_RESULT => {
                let result =
                    StartResult::from_u8(frame[1]).ok_or(LauncherFrameError::UnknownValue)?;
                if frame[2..4].iter().any(|byte| *byte != 0) {
                    return Err(LauncherFrameError::ReservedNonZero);
                }
                zero_after(frame, 8)?;
                Ok(Self::StartResult {
                    result,
                    service: u32_at(frame, 4),
                })
            }
            _ => Err(LauncherFrameError::UnknownKind),
        }
    }
}

fn u32_at(frame: &Frame, offset: usize) -> u32 {
    u32::from_le_bytes([
        frame[offset],
        frame[offset + 1],
        frame[offset + 2],
        frame[offset + 3],
    ])
}

fn zero_after(frame: &Frame, from: usize) -> Result<(), LauncherFrameError> {
    if frame[from..].iter().any(|byte| *byte != 0) {
        Err(LauncherFrameError::ReservedNonZero)
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn name(text: &str) -> AppName {
        AppName::new(text.as_bytes()).unwrap()
    }

    #[test]
    fn names_are_printable_ascii_without_spaces_and_bounded() {
        assert_eq!(name("terminal").as_str(), "terminal");
        assert!(AppName::new(b"").is_none());
        assert!(AppName::new(b"two words").is_none());
        assert!(AppName::new(b"tab\t").is_none());
        assert!(AppName::new(&[0xc3, 0xa9]).is_none());
        assert!(AppName::new(&[b'a'; LAUNCHER_NAME_MAX]).is_some());
        assert!(AppName::new(&[b'a'; LAUNCHER_NAME_MAX + 1]).is_none());
    }

    #[test]
    fn requests_round_trip() {
        for request in [
            LauncherRequest::List,
            LauncherRequest::Start(name("terminal")),
            LauncherRequest::Start(AppName::new(&[b'z'; LAUNCHER_NAME_MAX]).unwrap()),
        ] {
            assert_eq!(LauncherRequest::decode(&request.encode()), Ok(request));
        }
    }

    #[test]
    fn malformed_requests_are_refused() {
        let mut frame = LauncherRequest::List.encode();
        frame[5] = 1;
        assert_eq!(
            LauncherRequest::decode(&frame),
            Err(LauncherFrameError::ReservedNonZero)
        );
        let mut frame = LauncherRequest::Start(name("abc")).encode();
        frame[1] = 0;
        assert_eq!(
            LauncherRequest::decode(&frame),
            Err(LauncherFrameError::Name)
        );
        let mut frame = LauncherRequest::Start(name("abc")).encode();
        frame[1] = LAUNCHER_NAME_MAX as u8 + 1;
        assert_eq!(
            LauncherRequest::decode(&frame),
            Err(LauncherFrameError::Name)
        );
        let mut frame = LauncherRequest::Start(name("abc")).encode();
        frame[10] = b'x';
        assert_eq!(
            LauncherRequest::decode(&frame),
            Err(LauncherFrameError::ReservedNonZero)
        );
        let mut frame = LauncherRequest::Start(name("abc")).encode();
        frame[3] = b' ';
        assert_eq!(
            LauncherRequest::decode(&frame),
            Err(LauncherFrameError::Name)
        );
        let mut frame = [0u8; PORT_FRAME_BYTES];
        frame[0] = 9;
        assert_eq!(
            LauncherRequest::decode(&frame),
            Err(LauncherFrameError::UnknownKind)
        );
    }

    #[test]
    fn events_round_trip() {
        let entry = AppEntry {
            service: 0x5700,
            state: AppState::Running,
            generation: 3,
            pid: 41,
            name: name("terminal"),
        };
        for event in [
            LauncherEvent::Entry(entry),
            LauncherEvent::Changed(AppEntry {
                state: AppState::Idle,
                pid: 0,
                ..entry
            }),
            LauncherEvent::ListEnd { count: 2 },
            LauncherEvent::StartResult {
                result: StartResult::AlreadyRunning,
                service: 0x5700,
            },
            LauncherEvent::StartResult {
                result: StartResult::UnknownName,
                service: 0,
            },
        ] {
            assert_eq!(LauncherEvent::decode(&event.encode()), Ok(event));
        }
    }

    #[test]
    fn the_entry_layout_is_the_documented_one() {
        let frame = LauncherEvent::Entry(AppEntry {
            service: 0x0102_0304,
            state: AppState::Starting,
            generation: 0x0a0b_0c0d,
            pid: 0x1122_3344_5566_7788,
            name: name("ab"),
        })
        .encode();
        assert_eq!(frame[0], LAUNCHER_EVENT_ENTRY);
        assert_eq!(frame[1], AppState::Starting as u8);
        assert_eq!(frame[2], 2);
        assert_eq!(frame[4..8], [4, 3, 2, 1]);
        assert_eq!(frame[8..12], [0x0d, 0x0c, 0x0b, 0x0a]);
        assert_eq!(frame[16..24], 0x1122_3344_5566_7788u64.to_le_bytes());
        assert_eq!(&frame[24..26], b"ab");
        assert!(frame[26..].iter().all(|byte| *byte == 0));
    }

    #[test]
    fn unknown_states_and_results_are_refused() {
        let mut frame = LauncherEvent::ListEnd { count: 0 }.encode();
        frame[0] = LAUNCHER_EVENT_START_RESULT;
        frame[1] = 9;
        assert_eq!(
            LauncherEvent::decode(&frame),
            Err(LauncherFrameError::UnknownValue)
        );
        let mut frame = LauncherEvent::Entry(AppEntry {
            service: 1,
            state: AppState::Idle,
            generation: 0,
            pid: 0,
            name: name("a"),
        })
        .encode();
        frame[1] = 5;
        assert_eq!(
            LauncherEvent::decode(&frame),
            Err(LauncherFrameError::UnknownValue)
        );
        for raw in 0..=4 {
            assert_eq!(AppState::from_u8(raw).map(|state| state as u8), Some(raw));
            assert_eq!(
                StartResult::from_u8(raw).map(|result| result as u8),
                Some(raw)
            );
        }
    }
}

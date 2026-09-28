//! Protocol-level bounds frozen by #110.
//!
//! Memory-level limits for shared buffers are owned by #195 and must stay within
//! [`MAX_BUFFER_BYTES`].

/// Maximum compositor port connections.
pub const MAX_CLIENTS: usize = 8;
/// Maximum surfaces per client connection.
pub const MAX_SURFACES_PER_CLIENT: usize = 8;
/// Maximum surfaces across all connections.
pub const MAX_SURFACES: usize = 32;
/// Maximum windows per client connection.
pub const MAX_WINDOWS_PER_CLIENT: usize = 4;
/// Maximum windows across all connections.
pub const MAX_WINDOWS: usize = 16;
/// Maximum registered [`crate::ids::ClientBufferId`] values per client.
pub const MAX_BUFFERS_PER_CLIENT: usize = 8;
/// Displayed plus latest pending commit per surface.
pub const MAX_IN_FLIGHT_BUFFERS_PER_SURFACE: usize = 2;
/// Damage rectangles per commit; overflow collapses to the bounding box.
pub const MAX_DAMAGE_RECTS_PER_COMMIT: usize = 16;
/// Maximum rectangles in an opaque or input region.
pub const MAX_REGION_RECTS: usize = 8;
/// Per-axis maximum for buffer pixels and logical units.
pub const MAX_SURFACE_EXTENT: u32 = 4096;
/// Maximum row stride in bytes (`width × 4` at the largest extent).
pub const MAX_STRIDE_BYTES: u32 = MAX_SURFACE_EXTENT * 4;
/// Maximum attested buffer byte length (covers 1920×1080×4; #195 must accept this).
pub const MAX_BUFFER_BYTES: u64 = 8 * 1024 * 1024;
/// Maximum UTF-8 title bytes in one protocol frame.
pub const MAX_TITLE_BYTES: usize = 40;
/// Per-connection client event ring depth.
pub const CLIENT_EVENT_QUEUE_DEPTH: usize = 64;
/// Port-wide server request ring depth.
pub const SERVER_REQUEST_QUEUE_DEPTH: usize = 64;
/// Maximum outstanding requests per client on the port.
pub const MAX_OUTSTANDING_REQUESTS_PER_CLIENT: usize = 16;
/// Kernel raw-input queue depth.
pub const RAW_INPUT_QUEUE_DEPTH: usize = 128;
/// Relative-motion coalescing begins at or above this fill level.
pub const RAW_INPUT_COALESCE_HIGH_WATER: usize = 96;
/// Kernel-owned scanout buffer count.
pub const SCANOUT_BUFFER_COUNT: usize = 2;
/// Maximum damage rectangles per present command.
pub const MAX_PRESENT_DAMAGE_RECTS: usize = 16;
/// Maximum physical outputs in M10.
pub const MAX_OUTPUTS: usize = 1;
/// Display backend command deadline before `ResetRequired`.
pub const DISPLAY_COMMAND_TIMEOUT_NS: u64 = 1_000_000_000;
/// Consecutive compositor iterations with a full client event ring before disconnect.
pub const MAX_CLIENT_STALL_ITERATIONS: u32 = 8;

// Proposed for #195 (memory-level; #195 owns and may adjust within MAX_BUFFER_BYTES):
//   MAX_SHARED_BUFFERS = 32, MAX_SHARED_BUFFERS_PER_OWNER = 8, MAX_SHARED_PAGES_TOTAL = 8192 (32 MiB),
//   MAX_SHARED_PAGES_PER_OWNER = 4096, MAX_ATTACHMENTS_PER_BUFFER = 2,
//   MAX_SHARED_MAPPINGS_PER_PROCESS = 16, MAX_EXTENTS_PER_BUFFER = 16

const _: () = assert!(MAX_STRIDE_BYTES == MAX_SURFACE_EXTENT * 4);
const _: () = assert!(MAX_SURFACES_PER_CLIENT <= MAX_SURFACES);
const _: () = assert!(MAX_WINDOWS_PER_CLIENT <= MAX_WINDOWS);
const _: () = assert!(4_096_000u64 <= MAX_BUFFER_BYTES);

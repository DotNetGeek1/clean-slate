//! Frozen body offset tables for protocol 1.0 (§2.3 / §3.3).
//!
//! Header bytes 0..12 are shared (§1.2). Below lists **body** fields only (offsets 12..64).
//! Static padding rows are enforced at decode step 6; dynamic slot rules at step 7.
//!
//! # Requests
//!
//! ## `Hello` (`0x0001`, object must be 0)
//!
//! | Off | W | Field |
//! |---|---|---|
//! | 12 | 2 | `version.major` u16 |
//! | 14 | 2 | `version.minor` u16 |
//! | 16 | 8 | `features` u64 |
//! | 24..64 | — | static padding |
//!
//! ## `RegisterBuffer` (`0x0010`, object must be 0)
//!
//! | Off | W | Field |
//! |---|---|---|
//! | 12 | 4 | `layout.width` u32 |
//! | 16 | 4 | `layout.height` u32 |
//! | 20 | 4 | `layout.stride_bytes` u32 |
//! | 24 | 1 | `layout.format` u8 |
//! | 25..64 | — | static padding |
//!
//! ## `UnregisterBuffer` / `CreateSurface` / `DestroySurface` / `CreateWindow` / `DestroyWindow` / `Show` / `Hide`
//!
//! Empty body (12..64 static padding). Object rule per §2.1.
//!
//! ## `AssignRole` (`0x0022`, object = `SurfaceId`)
//!
//! | Off | W | Field |
//! |---|---|---|
//! | 12 | 1 | `role` u8 |
//! | 13..16 | — | static padding |
//! | 16 | 4 | `parent` optional `SurfaceId` |
//! | 20..64 | — | static padding |
//!
//! ## `Attach` (`0x0023`)
//!
//! | Off | W | Field |
//! |---|---|---|
//! | 12 | 4 | `buffer` optional `ClientBufferId` |
//! | 16 | 2 | `buffer_scale` u16 |
//! | 18..64 | — | static padding |
//!
//! ## `Damage` (`0x0024`)
//!
//! | Off | W | Field |
//! |---|---|---|
//! | 12 | 1 | `count` u8 |
//! | 13..16 | — | static padding |
//! | 16 + 8·i | 8 | `rects[i]` `BufferRect`, i = 0..5 |
//! | 56..64 | — | static padding |
//!
//! ## `SetOpaqueRegion` / `SetInputRegion` (`0x0025` / `0x0026`)
//!
//! | Off | W | Field |
//! |---|---|---|
//! | 12 | 1 | `count` u8 |
//! | 13 | 1 | `replace` bool u8 |
//! | 14..16 | — | static padding |
//! | 16 + 16·i | 16 | `rects[i]` `Rect`, i = 0..3 |
//!
//! ## `Commit` (`0x0027`)
//!
//! | Off | W | Field |
//! |---|---|---|
//! | 12 | 1 | `request_frame` bool |
//! | 13 | 1 | `color_space` u8 |
//! | 14..16 | — | static padding |
//! | 16 | 4 | `ack` optional `Serial` |
//! | 20..64 | — | static padding |
//!
//! ## `SetTitle` (`0x0032`)
//!
//! | Off | W | Field |
//! |---|---|---|
//! | 12 | 1 | `len` u8 |
//! | 13..53 | 40 | UTF-8 bytes |
//! | 53..64 | — | static padding |
//!
//! ## `SetSizeLimits` (`0x0033`)
//!
//! | Off | W | Field |
//! |---|---|---|
//! | 12 | 4 | `min.width` u32 |
//! | 16 | 4 | `min.height` u32 |
//! | 20 | 4 | `max.width` u32 |
//! | 24 | 4 | `max.height` u32 |
//! | 28..64 | — | static padding |
//!
//! ## `BeginMove` / `AckConfigure`
//!
//! | Off | W | Field |
//! |---|---|---|
//! | 12 | 4 | `serial` u32 |
//! | 16..64 | — | static padding |
//!
//! ## `BeginResize` (`0x0037`)
//!
//! | Off | W | Field |
//! |---|---|---|
//! | 12 | 4 | `serial` u32 |
//! | 16 | 1 | `edges` u8 |
//! | 17..64 | — | static padding |
//!
//! # Events
//!
//! ## `Welcome` (`0x8001`, object must be 0)
//!
//! | Off | W | Field |
//! |---|---|---|
//! | 12 | 2 | `version.major` u16 |
//! | 14 | 2 | `version.minor` u16 |
//! | 16 | 8 | `features` u64 |
//! | 24 | 4 | `output.id` `OutputId` |
//! | 28 | 4 | `output.mode.width_px` u32 |
//! | 32 | 4 | `output.mode.height_px` u32 |
//! | 36 | 4 | `output.mode.stride_bytes` u32 |
//! | 40 | 1 | `output.mode.format` u8 |
//! | 41 | — | static padding |
//! | 42 | 2 | `output.mode.scale` u16 |
//! | 44 | 4 | `output.mode.refresh_mhz` u32 |
//! | 48 | 4 | `output.logical_size.width` u32 |
//! | 52 | 4 | `output.logical_size.height` u32 |
//! | 56..64 | — | static padding |
//!
//! ## `Error` (`0x8002`, object raw echo)
//!
//! | Off | W | Field |
//! |---|---|---|
//! | 12 | 2 | `code` u16 |
//! | 14 | 2 | `request_opcode` u16 |
//! | 16..64 | — | static padding |
//!
//! ## `FrameDone` (`0x8021`)
//!
//! | Off | W | Field |
//! |---|---|---|
//! | 12 | 8 | `presented_ns` u64 |
//! | 20 | 8 | `output_seq` u64 |
//! | 28..64 | — | static padding |
//!
//! ## `Configure` (`0x8031`)
//!
//! | Off | W | Field |
//! |---|---|---|
//! | 12 | 4 | `serial` u32 |
//! | 16 | 4 | `size.width` u32 |
//! | 20 | 4 | `size.height` u32 |
//! | 24 | 2 | `scale` u16 |
//! | 26 | 1 | `decoration` u8 |
//! | 27 | — | static padding |
//! | 28 | 4 | `states` u32 |
//! | 32 | 4 | `bounds.width` u32 |
//! | 36 | 4 | `bounds.height` u32 |
//! | 40..64 | — | static padding |
//!
//! ## `Key` (`0x8041`, object must be 0)
//!
//! | Off | W | Field |
//! |---|---|---|
//! | 12 | 4 | `serial` u32 |
//! | 16 | 8 | `time_ns` u64 |
//! | 24 | 2 | `usage` u16 |
//! | 26 | 1 | `state` u8 |
//! | 27 | — | static padding |
//! | 28 | 2 | `modifiers` u16 |
//! | 30..64 | — | static padding |
//!
//! ## `ModifiersChanged` (`0x8042`)
//!
//! | Off | W | Field |
//! |---|---|---|
//! | 12 | 2 | `modifiers` u16 |
//! | 14..64 | — | static padding |
//!
//! ## `PointerEnter` (`0x8050`)
//!
//! | Off | W | Field |
//! |---|---|---|
//! | 12 | 4 | `serial` u32 |
//! | 16 | 4 | `x` i32 |
//! | 20 | 4 | `y` i32 |
//! | 24..64 | — | static padding |
//!
//! ## `PointerLeave` (`0x8051`)
//!
//! | Off | W | Field |
//! |---|---|---|
//! | 12 | 4 | `serial` u32 |
//! | 16..64 | — | static padding |
//!
//! ## `PointerMotion` (`0x8052`, object must be 0)
//!
//! | Off | W | Field |
//! |---|---|---|
//! | 12 | 8 | `time_ns` u64 |
//! | 20 | 4 | `x` i32 |
//! | 24 | 4 | `y` i32 |
//! | 28..64 | — | static padding |
//!
//! ## `PointerButton` (`0x8053`, object must be 0)
//!
//! | Off | W | Field |
//! |---|---|---|
//! | 12 | 4 | `serial` u32 |
//! | 16 | 8 | `time_ns` u64 |
//! | 24 | 2 | `button` u16 |
//! | 26 | 1 | `state` u8 |
//! | 27..64 | — | static padding |
//!
//! ## `PointerAxis` (`0x8054`, object must be 0)
//!
//! | Off | W | Field |
//! |---|---|---|
//! | 12 | 8 | `time_ns` u64 |
//! | 20 | 4 | `vertical` i32 |
//! | 24 | 4 | `horizontal` i32 |
//! | 28..64 | — | static padding |
//!
//! Empty-body events (`BufferRegistered`, `BufferReleased`, `BufferUnregistered`, `SurfaceCreated`,
//! `WindowCreated`, `CloseRequested`, `KeyboardFocus`, `InputReset`): 12..64 static padding; see §3.1 for object rules.

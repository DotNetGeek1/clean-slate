//! M8.0 validated ELF64 load-plan representation.
//!
//! Host-testable, `no_std` contract shared by:
//! - `kernel/build.rs` native userspace image embedding;
//! - kernel runtime segment mapping;
//! - future Linux ELF loading in issue #92.
//!
//! Zero-fill (`p_memsz - p_filesz`) is never serialized as file bytes.

#![cfg_attr(not(test), no_std)]

mod error;
mod header;
mod plan;
mod policy;
mod segment;

pub use error::LoadPlanError;
pub use header::{
    Elf64Header, ELFCLASS64, ELFDATA2LSB, ELF64_EHDR_SIZE, ELF64_PHDR_SIZE, ELFMAG, EM_X86_64,
    ET_CORE, ET_DYN, ET_EXEC, ET_NONE, ET_REL, EV_CURRENT, PF_R, PF_W, PF_X, PT_INTERP, PT_LOAD,
};
pub use plan::{parse_load_plan, LoadPlan};
pub use policy::{LoadPlanPolicy, MAX_LOAD_SEGMENTS};
pub use segment::{LoadSegment, SegmentPermissions};

#[cfg(test)]
mod tests;

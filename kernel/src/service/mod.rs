//! Shared service-management contracts. Protocol/state definitions live here so
//! the later M4 kernel control path, userspace supervisor runtime, and service
//! fixtures can consume the same normal-build module instead of defining their
//! own feature-gated copies.

#[allow(dead_code)]
pub(crate) mod protocol;

// #218 S3b: the one rule for which kernel builds launch userspace init. Shared by `build.rs`,
// which emits `cfg(clean_slate_system_init)` from it, and by the kernel's drift test.

/// The only Cargo features a build may enable and still launch init.
pub const SYSTEM_INIT_ALLOWED_FEATURES: &[&str] = &["gdb-entry"];

/// A build launches init exactly when it enables no Cargo feature other than `gdb-entry`.
/// Every other build reaching the end of boot runs the demo threads instead.
pub fn launches_system_init<'a>(enabled_features: impl IntoIterator<Item = &'a str>) -> bool {
    enabled_features
        .into_iter()
        .all(|feature| SYSTEM_INIT_ALLOWED_FEATURES.contains(&feature))
}

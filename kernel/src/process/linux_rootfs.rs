//! Embedded M9 rootfs image (#104 consumer).

#[cfg(feature = "m9-rootfs")]
pub(crate) fn image() -> clean_slate_rootfs::Image<'static> {
    let bytes = include_bytes!(concat!(env!("OUT_DIR"), "/m9-rootfs.img"));
    clean_slate_rootfs::Image::parse(bytes).expect("m9 rootfs parse")
}

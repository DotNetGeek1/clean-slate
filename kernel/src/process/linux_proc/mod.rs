//! Linux process compatibility (#102).

#![allow(dead_code)]

#[cfg(clean_slate_linux_proc)]
pub(crate) mod fault;
pub(crate) mod pipe;
pub(crate) mod table;

#[cfg(clean_slate_linux_proc)]
pub(crate) mod exec_resolve;
#[cfg(clean_slate_linux_proc)]
pub(crate) mod exit_publish;
#[cfg(clean_slate_linux_proc)]
pub(crate) mod fork;
#[cfg(clean_slate_linux_proc)]
pub(crate) mod wait;

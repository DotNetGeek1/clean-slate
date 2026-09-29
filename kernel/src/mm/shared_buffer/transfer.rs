//! W6: the attestation a port SEND uses before moving a `SharedBuffer` capability.

use clean_slate_capability::{CapabilityHandle, HolderId, ResourceClass, Rights};
use clean_slate_native_abi::{SharedBufferId, STATUS_ESTALE};

use super::{state, ShareError};
use crate::capability::with_capability_space;

/// Attests that `holder` may transfer the buffer behind `handle` — a Live
/// `SharedBuffer` capability with `DELEGATE` naming a Live buffer — and returns the
/// kernel-attested `(id, byte_len)`. Pure and allocation-free, so it is callable with
/// interrupts off inside a port SEND. The transferred child can only be `READ`
/// (`Rights::root_only_for`). Errors are native statuses.
pub(crate) fn attest_for_transfer(
    holder: HolderId,
    handle: CapabilityHandle,
) -> Result<(SharedBufferId, u64), u64> {
    let record = with_capability_space(|table| {
        table.authorize_class(
            holder,
            handle,
            ResourceClass::SharedBuffer,
            Rights::DELEGATE,
        )
    })
    .map_err(|error| error.syscall_status())?;
    let id = SharedBufferId::decode(record.resource.id).map_err(|_| STATUS_ESTALE)?;
    let buffer = state().table.live(id).map_err(ShareError::status)?;
    Ok((id, buffer.byte_len))
}

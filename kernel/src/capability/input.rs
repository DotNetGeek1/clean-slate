//! Kernel root grants of seat-0 raw-input authority (#113). Launch policy (P5) decides who gets
//! one; in M10 that is only the live compositor. Until that policy (#112/#118) lands, this module
//! is compiled only for host tests and the input self-test.

use clean_slate_capability::{
    CapabilityError, CapabilityHandle, HolderId, ResourceClass, ResourceRef, Rights,
};

use super::grant_root;

const SEAT: u64 = 0;

/// `Input` is non-delegable: `DELEGATE` is outside `valid_for(Input)`, so it is rejected here.
fn input_grant_rights(rights: Rights) -> Result<Rights, CapabilityError> {
    if rights == Rights::empty() || !rights.is_subset_of(Rights::valid_for(ResourceClass::Input)) {
        return Err(CapabilityError::InvalidRights);
    }
    Ok(rights)
}

pub(crate) fn grant_input_authority(
    holder: HolderId,
    rights: Rights,
) -> Result<CapabilityHandle, CapabilityError> {
    grant_root(
        holder,
        ResourceRef::input(SEAT),
        input_grant_rights(rights)?,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn input_grants_accept_only_consume_and_inspect() {
        let both = Rights::INPUT_CONSUME.union(Rights::INSPECT);
        assert_eq!(input_grant_rights(both), Ok(both));
        assert_eq!(
            input_grant_rights(Rights::INPUT_CONSUME),
            Ok(Rights::INPUT_CONSUME)
        );
        for rejected in [
            Rights::empty(),
            Rights::INPUT_CONSUME.union(Rights::DELEGATE),
            Rights::DELEGATE,
            Rights::READ,
        ] {
            assert_eq!(
                input_grant_rights(rejected),
                Err(CapabilityError::InvalidRights)
            );
        }
    }

    #[test]
    fn root_grant_carries_exactly_the_requested_seat_zero_rights() {
        use crate::capability::holder_has_resource_rights;

        let holder = HolderId(88_113);
        let seat = ResourceRef::input(SEAT);
        grant_input_authority(holder, Rights::INPUT_CONSUME).expect("grant consume");
        assert!(holder_has_resource_rights(
            holder,
            seat,
            Rights::INPUT_CONSUME
        ));
        assert!(!holder_has_resource_rights(holder, seat, Rights::INSPECT));
        assert_eq!(
            grant_input_authority(holder, Rights::INPUT_CONSUME.union(Rights::DELEGATE)),
            Err(CapabilityError::InvalidRights)
        );
        assert!(!holder_has_resource_rights(
            HolderId(88_114),
            seat,
            Rights::INPUT_CONSUME
        ));
    }
}

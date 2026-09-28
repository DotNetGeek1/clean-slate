//! Kernel root grants of seat-0 raw-input authority (#113). Launch policy (P5) decides who gets
//! one; in M10 that is only the live compositor.

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

#[cfg_attr(not(feature = "m10-input-self-test"), allow(dead_code))] // P5 compositor launch policy (#112/#118)
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
}

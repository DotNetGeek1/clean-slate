//! Desktop grants (#118, P5; #218 S6c): the only root grants of `Graphics`, `Display` and
//! `Input` authority outside self-tests.
//!
//! The live compositor alone serves the graphics port and holds the display and seat; the shell
//! connects with `GFX_SHELL`; an app connects with `GFX_CONNECT` and nothing else. Every grant is a
//! root record for exactly one holder, so process teardown (`revoke_for_holder`) removes it.
//!
//! The system build applies them one manifest grant at a time (`grant_graphics`,
//! `grant_display_presenter`, `grant_input_seat`).

use clean_slate_capability::{CapabilityError, HolderId, ResourceRef, Rights};

use super::grant_root;
use super::input::grant_input_authority;
use crate::device::display::PRIMARY_OUTPUT_INDEX;

/// The compositor's port authority.
pub(crate) const COMPOSITOR_GRAPHICS_RIGHTS: Rights = Rights::GFX_SERVE;
pub(crate) const COMPOSITOR_DISPLAY_RIGHTS: Rights = Rights::DISPLAY_PRESENT.union(Rights::INSPECT);
pub(crate) const COMPOSITOR_INPUT_RIGHTS: Rights = Rights::INPUT_CONSUME.union(Rights::INSPECT);
/// Shell surfaces (background, panels) need `GFX_SHELL` on the connecting capability.
pub(crate) const SHELL_GRAPHICS_RIGHTS: Rights = Rights::GFX_CONNECT.union(Rights::GFX_SHELL);
pub(crate) const APP_GRAPHICS_RIGHTS: Rights = Rights::GFX_CONNECT;

/// Root `rights` on the graphics port `graphics` (one compositor generation).
pub(crate) fn grant_graphics(
    holder: HolderId,
    graphics: ResourceRef,
    rights: Rights,
) -> Result<(), CapabilityError> {
    grant_root(holder, graphics, rights).map(|_| ())
}

/// Root `DISPLAY_PRESENT | INSPECT` on output 0.
pub(crate) fn grant_display_presenter(holder: HolderId) -> Result<(), CapabilityError> {
    grant_root(
        holder,
        ResourceRef::display(PRIMARY_OUTPUT_INDEX),
        COMPOSITOR_DISPLAY_RIGHTS,
    )
    .map(|_| ())
}

/// Root `INPUT_CONSUME | INSPECT` on seat 0.
pub(crate) fn grant_input_seat(holder: HolderId) -> Result<(), CapabilityError> {
    grant_input_authority(holder, COMPOSITOR_INPUT_RIGHTS).map(|_| ())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::capability::{holder_has_resource_rights, revoke_for_holder};
    use clean_slate_capability::ResourceClass;

    const GRAPHICS: ResourceRef = ResourceRef::graphics(0x5300, 1);

    fn holds(holder: HolderId, resource: ResourceRef, rights: Rights) -> bool {
        holder_has_resource_rights(holder, resource, rights)
    }

    #[test]
    fn only_the_compositor_rights_serve_present_or_consume() {
        for rights in [SHELL_GRAPHICS_RIGHTS, APP_GRAPHICS_RIGHTS] {
            assert!(!rights.contains(Rights::GFX_SERVE));
            assert!(!rights.contains(Rights::DELEGATE));
        }
        for (rights, resource) in [
            (COMPOSITOR_GRAPHICS_RIGHTS, GRAPHICS),
            (
                COMPOSITOR_DISPLAY_RIGHTS,
                ResourceRef::display(PRIMARY_OUTPUT_INDEX),
            ),
            (COMPOSITOR_INPUT_RIGHTS, ResourceRef::input(0)),
        ] {
            assert!(rights.is_subset_of(Rights::valid_for(resource.class)));
            assert!(!rights.contains(Rights::DELEGATE));
        }
        assert_eq!(APP_GRAPHICS_RIGHTS, Rights::GFX_CONNECT);
        assert_eq!(
            SHELL_GRAPHICS_RIGHTS,
            Rights::GFX_CONNECT.union(Rights::GFX_SHELL)
        );
    }

    #[test]
    fn grants_land_on_one_holder_and_teardown_revokes_them() {
        let compositor = HolderId(91_181);
        let shell = HolderId(91_182);
        let app = HolderId(91_183);
        grant_graphics(compositor, GRAPHICS, COMPOSITOR_GRAPHICS_RIGHTS).expect("compositor");
        grant_display_presenter(compositor).expect("display");
        grant_input_seat(compositor).expect("seat");
        grant_graphics(shell, GRAPHICS, SHELL_GRAPHICS_RIGHTS).expect("shell");
        grant_graphics(app, GRAPHICS, APP_GRAPHICS_RIGHTS).expect("app");

        let display = ResourceRef::display(PRIMARY_OUTPUT_INDEX);
        let seat = ResourceRef::input(0);
        assert!(holds(compositor, GRAPHICS, Rights::GFX_SERVE));
        assert!(holds(compositor, display, Rights::DISPLAY_PRESENT));
        assert!(holds(compositor, seat, Rights::INPUT_CONSUME));
        assert!(!holds(compositor, GRAPHICS, Rights::GFX_CONNECT));

        assert!(holds(shell, GRAPHICS, SHELL_GRAPHICS_RIGHTS));
        assert!(!holds(shell, GRAPHICS, Rights::GFX_SERVE));
        assert!(!holds(shell, display, Rights::DISPLAY_PRESENT));
        assert!(!holds(shell, seat, Rights::INPUT_CONSUME));

        assert!(holds(app, GRAPHICS, Rights::GFX_CONNECT));
        assert!(!holds(app, GRAPHICS, Rights::GFX_SHELL));
        assert!(!holds(app, display, Rights::INSPECT));
        assert!(!holds(app, seat, Rights::INSPECT));

        // A restarted compositor's generation names a different resource.
        let next = ResourceRef::graphics(0x5300, 2);
        assert!(!holds(app, next, Rights::GFX_CONNECT));
        assert_eq!(GRAPHICS.class, ResourceClass::Graphics);

        assert_eq!(revoke_for_holder(compositor), 3);
        assert_eq!(revoke_for_holder(shell), 1);
        assert_eq!(revoke_for_holder(app), 1);
        assert!(!holds(app, GRAPHICS, Rights::GFX_CONNECT));
    }
}

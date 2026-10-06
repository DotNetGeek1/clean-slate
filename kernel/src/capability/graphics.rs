//! Desktop launch-policy grants (#118, P5): the only root grants of `Graphics`, `Display` and
//! `Input` authority outside self-tests.
//!
//! The live compositor alone serves the graphics port and holds the display and seat; the shell
//! connects with `GFX_SHELL`; an app connects with `GFX_CONNECT` and nothing else. Every grant is a
//! root record for exactly one holder, so process teardown (`revoke_for_holder`) removes it.

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

/// Who a desktop grant is for.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum GraphicsGrantee {
    Compositor,
    Shell,
    App,
}

/// The grants one role receives, as `(resource, rights)`.
pub(crate) const fn grants_for(grantee: GraphicsGrantee) -> &'static [(GrantTarget, Rights)] {
    match grantee {
        GraphicsGrantee::Compositor => &[
            (GrantTarget::Graphics, COMPOSITOR_GRAPHICS_RIGHTS),
            (GrantTarget::Display, COMPOSITOR_DISPLAY_RIGHTS),
            (GrantTarget::Input, COMPOSITOR_INPUT_RIGHTS),
        ],
        GraphicsGrantee::Shell => &[(GrantTarget::Graphics, SHELL_GRAPHICS_RIGHTS)],
        GraphicsGrantee::App => &[(GrantTarget::Graphics, APP_GRAPHICS_RIGHTS)],
    }
}

/// Resource a grant names; the graphics port resource is per compositor generation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum GrantTarget {
    Graphics,
    Display,
    Input,
}

impl GrantTarget {
    fn resource(self, graphics: ResourceRef) -> ResourceRef {
        match self {
            Self::Graphics => graphics,
            Self::Display => ResourceRef::display(PRIMARY_OUTPUT_INDEX),
            Self::Input => ResourceRef::input(0),
        }
    }
}

/// Grants `holder` every capability its role gets on the compositor generation `graphics`. On
/// failure nothing is rolled back here: the caller tears the new process down, which revokes
/// whatever was granted.
pub(crate) fn grant_desktop_role(
    holder: HolderId,
    grantee: GraphicsGrantee,
    graphics: ResourceRef,
) -> Result<(), CapabilityError> {
    for &(target, rights) in grants_for(grantee) {
        match target {
            GrantTarget::Input => grant_input_authority(holder, rights).map(|_| ())?,
            other => grant_root(holder, other.resource(graphics), rights).map(|_| ())?,
        }
    }
    Ok(())
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
    fn only_the_compositor_gets_serve_display_and_input() {
        for grantee in [GraphicsGrantee::Shell, GraphicsGrantee::App] {
            for &(target, rights) in grants_for(grantee) {
                assert_eq!(target, GrantTarget::Graphics, "{grantee:?}");
                assert!(!rights.contains(Rights::GFX_SERVE), "{grantee:?}");
                assert!(!rights.contains(Rights::DELEGATE), "{grantee:?}");
            }
        }
        let compositor = grants_for(GraphicsGrantee::Compositor);
        assert_eq!(compositor.len(), 3);
        for &(target, rights) in compositor {
            let class = target.resource(GRAPHICS).class;
            assert!(rights.is_subset_of(Rights::valid_for(class)), "{target:?}");
            assert!(!rights.contains(Rights::DELEGATE));
        }
        assert_eq!(
            grants_for(GraphicsGrantee::App),
            &[(GrantTarget::Graphics, Rights::GFX_CONNECT)]
        );
        assert_eq!(
            grants_for(GraphicsGrantee::Shell),
            &[(
                GrantTarget::Graphics,
                Rights::GFX_CONNECT.union(Rights::GFX_SHELL)
            )]
        );
    }

    #[test]
    fn grants_land_on_one_holder_and_teardown_revokes_them() {
        let compositor = HolderId(91_181);
        let shell = HolderId(91_182);
        let app = HolderId(91_183);
        grant_desktop_role(compositor, GraphicsGrantee::Compositor, GRAPHICS).expect("compositor");
        grant_desktop_role(shell, GraphicsGrantee::Shell, GRAPHICS).expect("shell");
        grant_desktop_role(app, GraphicsGrantee::App, GRAPHICS).expect("app");

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

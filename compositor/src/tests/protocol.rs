//! Protocol handling: isolation between connections, buffer grants, roles and windows.

use super::*;
use clean_slate_capability::ResourceClass;
use clean_slate_graphics::geometry::Size;
use clean_slate_graphics::ids::ObjectId;
use clean_slate_graphics::objects::ObjectKind;
use clean_slate_graphics::protocol::DisconnectReason;
use clean_slate_graphics::role::{GFX_CONNECT_BIT, GFX_SHELL_BIT};
use clean_slate_graphics::window::{WindowConfig, WindowStates};

#[test]
fn guessed_ids_cannot_mutate_or_read_another_clients_objects() {
    let mut h = Harness::new();
    let mut a = h.client(2);
    let mut b = h.client(3);
    let ba = h.buffer(&mut a, 16, 16, RED);
    let (sa, wa) = h.toplevel(&mut a, ba, Point { x: 4, y: 4 });
    h.drain(&a);
    let commits = h
        .comp
        .surface_state(a.key(sa))
        .unwrap()
        .committed()
        .commit_count();

    let attacks = [
        Request::Attach {
            surface: sa,
            buffer: Some(ba),
            buffer_scale: Scale120::ONE,
        },
        Request::Damage {
            surface: sa,
            rects: [rect(0, 0, 16, 16); 5],
            count: 1,
        },
        Request::Commit {
            surface: sa,
            request_frame: true,
            color_space: ColorSpace::Srgb,
            ack: None,
        },
        Request::AssignRole {
            surface: sa,
            role: SurfaceRole::Toplevel,
            parent: None,
        },
        Request::CreateWindow { surface: sa },
        Request::Hide { window: wa },
        Request::DestroyWindow { window: wa },
        Request::UnregisterBuffer { buffer: ba },
        Request::DestroySurface { surface: sa },
    ];
    for attack in attacks {
        let inbox = h.roundtrip(&mut b, attack);
        assert_eq!(inbox.disconnected, None);
        assert!(
            matches!(
                inbox.errors().as_slice(),
                [ProtocolError::InvalidObject | ProtocolError::StaleObject]
            ),
            "{attack:?} -> {inbox:?}"
        );
    }
    // Brute-force a range of slots and generations.
    for slot in 0..16u8 {
        for generation in 1..4u32 {
            let surface = SurfaceId(ObjectId::new(slot, generation).unwrap());
            let inbox = h.roundtrip(&mut b, Request::DestroySurface { surface });
            assert_eq!(inbox.errors().len(), 1);
        }
    }

    assert_eq!(h.pixel(5, 5), RED);
    let state = h.comp.surface_state(a.key(sa)).unwrap();
    assert_eq!(state.committed().commit_count(), commits);
    assert_eq!(state.committed().buffer().map(|b| b.id), Some(ba));
    assert!(h.drain(&a).events.is_empty(), "victim saw nothing");

    // The same numeric id in the attacker's own table names only the attacker's object.
    let own = h.surface(&mut b);
    let inbox = h.roundtrip(&mut b, Request::DestroySurface { surface: own });
    assert!(inbox.errors().is_empty());
    assert!(h.comp.surface_state(a.key(sa)).is_some());
}

#[test]
fn buffers_register_only_with_an_explicit_shared_buffer_grant() {
    let mut h = Harness::new();
    let mut a = h.client(2);
    let layout = BufferLayout::new(8, 8, 32, PixelFormat::Xrgb8888).unwrap();

    let inbox = h.roundtrip(&mut a, Request::RegisterBuffer { layout });
    assert_eq!(inbox.errors(), [ProtocolError::TransferMissing]);
    assert_eq!(h.comp.budget().used(ObjectKind::Buffer), 0);

    // Granted bytes smaller than the declared layout.
    let (_, cap, _) = h.shared_buffer(&a, 4, 4, RED);
    h.send_with(&mut a, Request::RegisterBuffer { layout }, Some(cap));
    h.pump();
    assert_eq!(h.drain(&a).errors(), [ProtocolError::BufferTooSmall]);
    assert_eq!(h.shm.live_mappings(), 0);
    assert_eq!(h.shm.discarded(), 1, "the unused transfer child is dropped");

    // A capability that is not a readable shared buffer.
    for (class, rights) in [
        (ResourceClass::Graphics.as_u8(), Rights::READ.bits()),
        (ResourceClass::SharedBuffer.as_u8(), Rights::WRITE.bits()),
    ] {
        let transfer = TransferredCap {
            handle: 0x55,
            buffer_id: SharedBufferId::new(30, 1).unwrap().encode(),
            byte_len: 4096,
            rights,
            class,
        };
        h.inject(&forged(
            &a,
            Request::RegisterBuffer { layout },
            GFX_CONNECT_BIT,
            Some(transfer),
        ));
        h.pump();
        assert_eq!(h.drain(&a).errors(), [ProtocolError::TransferWrongClass]);
    }
    assert_eq!(h.shm.live_mappings(), 0);

    // The successful mapping is bounded by the kernel-attested length.
    let (buffer, id) = h.buffer_with_id(&mut a, 8, 8, RED);
    let entry = *h
        .comp
        .client_for(a.conn.id())
        .unwrap()
        .objects()
        .buffer(buffer)
        .unwrap();
    assert_eq!(entry.mapping.buffer_id, id.encode());
    assert_eq!(entry.mapping.byte_len, 8 * 8 * 4);
    assert_eq!(h.shm.live_mappings(), 1);

    // A stray transfer on another request is discarded, the request still served.
    let (_, cap, _) = h.shared_buffer(&a, 4, 4, RED);
    let discarded = h.shm.discarded();
    h.send_with(&mut a, Request::CreateSurface, Some(cap));
    h.pump();
    let inbox = h.drain(&a);
    assert!(matches!(
        inbox.events.as_slice(),
        [(_, Event::SurfaceCreated { .. })]
    ));
    assert_eq!(h.shm.discarded(), discarded + 1);
}

#[test]
fn role_authority_comes_only_from_envelope_rights() {
    let mut h = Harness::new();
    let mut a = h.client(2);
    let surface = h.surface(&mut a);
    let inbox = h.roundtrip(
        &mut a,
        Request::AssignRole {
            surface,
            role: SurfaceRole::Background,
            parent: None,
        },
    );
    assert_eq!(inbox.errors(), [ProtocolError::RoleForbidden]);
    let inbox = h.roundtrip(
        &mut a,
        Request::AssignRole {
            surface,
            role: SurfaceRole::Cursor,
            parent: None,
        },
    );
    assert_eq!(inbox.errors(), [ProtocolError::UnsupportedFeature]);

    // With GFX_SHELL in the envelope the background role is granted and stacks lowest.
    let background = h.buffer(&mut a, 32, 32, GREEN);
    h.inject(&forged(
        &a,
        Request::AssignRole {
            surface,
            role: SurfaceRole::Background,
            parent: None,
        },
        GFX_CONNECT_BIT | GFX_SHELL_BIT,
        None,
    ));
    h.pump();
    assert!(h.drain(&a).errors().is_empty());
    h.attach_commit(&mut a, surface, Some(background), None, false);
    assert_eq!(h.pixel(1, 1), GREEN);

    let window_buffer = h.buffer(&mut a, 8, 8, RED);
    h.toplevel(&mut a, window_buffer, Point { x: 0, y: 0 });
    assert_eq!(
        h.pixel(1, 1),
        RED,
        "windows stack above the background layer"
    );
    assert_eq!(h.pixel(20, 20), GREEN);
}

#[test]
fn window_rules_follow_the_contract() {
    let mut h = Harness::new();
    let mut a = h.client(2);
    let buffer = h.buffer(&mut a, 8, 8, RED);
    let surface = h.surface(&mut a);

    let inbox = h.roundtrip(&mut a, Request::CreateWindow { surface });
    assert_eq!(inbox.errors(), [ProtocolError::NotPermitted], "role-less");

    let popup = h.surface(&mut a);
    let inbox = h.roundtrip(
        &mut a,
        Request::AssignRole {
            surface: popup,
            role: SurfaceRole::Popup,
            parent: None,
        },
    );
    assert_eq!(inbox.errors(), [ProtocolError::InvalidParent]);
    let inbox = h.roundtrip(
        &mut a,
        Request::AssignRole {
            surface: popup,
            role: SurfaceRole::Popup,
            parent: Some(popup),
        },
    );
    assert_eq!(inbox.errors(), [ProtocolError::InvalidParent]);

    h.roundtrip(
        &mut a,
        Request::AssignRole {
            surface,
            role: SurfaceRole::Toplevel,
            parent: None,
        },
    );
    let inbox = h.roundtrip(
        &mut a,
        Request::AssignRole {
            surface,
            role: SurfaceRole::Toplevel,
            parent: None,
        },
    );
    assert_eq!(inbox.errors(), [ProtocolError::RoleAlreadyAssigned]);

    let inbox = h.roundtrip(&mut a, Request::CreateWindow { surface });
    let (window, serial) = match inbox.events.as_slice() {
        [(_, Event::WindowCreated { window }), (_, Event::Configure { serial, bounds, .. })] => {
            assert_eq!(
                *bounds,
                Size {
                    width: WIDTH,
                    height: HEIGHT
                }
            );
            (*window, *serial)
        }
        other => panic!("{other:?}"),
    };
    let inbox = h.roundtrip(&mut a, Request::CreateWindow { surface });
    assert_eq!(inbox.errors(), [ProtocolError::RoleAlreadyAssigned]);

    let inbox = h.attach_commit(&mut a, surface, Some(buffer), None, false);
    assert_eq!(inbox.errors(), [ProtocolError::NotConfigured]);
    let inbox = h.attach_commit(
        &mut a,
        surface,
        Some(buffer),
        Some(Serial(serial.0 + 7)),
        false,
    );
    assert_eq!(inbox.errors(), [ProtocolError::SerialMismatch]);
    let inbox = h.attach_commit(&mut a, surface, Some(buffer), Some(serial), false);
    assert!(inbox.errors().is_empty(), "{inbox:?}");

    // Interactive operations need a live press serial.
    let inbox = h.roundtrip(&mut a, Request::BeginMove { window, serial });
    assert_eq!(inbox.errors(), [ProtocolError::SerialMismatch]);
    let minted = h.comp.mint_serial(a.conn.id()).unwrap();
    let inbox = h.roundtrip(
        &mut a,
        Request::BeginMove {
            window,
            serial: minted,
        },
    );
    assert_eq!(
        inbox.errors(),
        [ProtocolError::SerialMismatch],
        "a serial that is not a live press authorises nothing (see tests::windows)"
    );

    // The codec refuses to encode an out-of-range limit, so patch `max.width` in the frame.
    let mut frame = Request::SetSizeLimits {
        window,
        min: Size {
            width: 1,
            height: 1,
        },
        max: Size {
            width: 1,
            height: 1,
        },
    }
    .encode(0x99)
    .unwrap();
    frame[20..24].copy_from_slice(&5000u32.to_le_bytes());
    h.send_raw(&a, &frame, None);
    h.pump();
    let inbox = h.drain(&a);
    assert_eq!(inbox.errors(), [ProtocolError::InvalidLayout]);
    assert_eq!(inbox.disconnected, None);
}

#[test]
fn configures_coalesce_past_the_outstanding_limit() {
    let mut h = Harness::new();
    let mut a = h.client(2);
    let buffer = h.buffer(&mut a, 8, 8, RED);
    let (surface, window) = h.toplevel(&mut a, buffer, Point { x: 0, y: 0 });
    h.drain(&a);
    let config = |w| {
        WindowConfig::new(
            Size {
                width: w,
                height: 8,
            },
            WindowStates::EMPTY,
            Size {
                width: 0,
                height: 0,
            },
        )
    };
    for w in 1..=6 {
        h.comp.configure_window(a.key(surface), config(w)).unwrap();
    }
    h.pump();
    let serials: Vec<_> = h
        .drain(&a)
        .events
        .iter()
        .filter_map(|(_, e)| match e {
            Event::Configure { serial, size, .. } => Some((*serial, size.width)),
            _ => None,
        })
        .collect();
    assert_eq!(serials.len(), 4, "MAX_OUTSTANDING_CONFIGURES");
    let inbox = h.roundtrip(
        &mut a,
        Request::AckConfigure {
            window,
            serial: serials[3].0,
        },
    );
    assert!(matches!(
        inbox.events.as_slice(),
        [(_, Event::Configure { size, .. })] if size.width == 6
    ));
}

#[test]
fn unregister_waits_for_the_buffer_to_be_released() {
    let mut h = Harness::new();
    let mut a = h.client(2);
    let buffer = h.buffer(&mut a, 8, 8, RED);
    let (surface, _) = h.toplevel(&mut a, buffer, Point { x: 0, y: 0 });

    let inbox = h.roundtrip(&mut a, Request::UnregisterBuffer { buffer });
    assert_eq!(inbox.errors(), [ProtocolError::BufferBusy]);

    let inbox = h.attach_commit(&mut a, surface, None, None, false);
    assert_eq!(inbox.released(), [buffer]);
    assert_eq!(h.pixel(1, 1), BACKGROUND, "detached surface is unmapped");
    let inbox = h.roundtrip(&mut a, Request::UnregisterBuffer { buffer });
    assert!(matches!(
        inbox.events.as_slice(),
        [(_, Event::BufferUnregistered { buffer: b })] if *b == buffer
    ));
    assert_eq!(h.shm.live_mappings(), 0);
}

#[test]
fn destroy_surface_destroys_window_and_releases_buffers() {
    let mut h = Harness::new();
    let mut a = h.client(2);
    let buffer = h.buffer(&mut a, 8, 8, RED);
    let (surface, window) = h.toplevel(&mut a, buffer, Point { x: 0, y: 0 });
    let inbox = h.roundtrip(&mut a, Request::DestroySurface { surface });
    assert_eq!(inbox.released(), [buffer]);
    assert_eq!(h.comp.budget().used(ObjectKind::Window), 0);
    assert_eq!(h.comp.budget().used(ObjectKind::Surface), 0);
    assert_eq!(h.pixel(1, 1), BACKGROUND);

    let inbox = h.roundtrip(&mut a, Request::Show { window });
    assert_eq!(inbox.errors(), [ProtocolError::StaleObject]);
    let inbox = h.attach_commit(&mut a, surface, Some(buffer), None, false);
    assert_eq!(
        inbox.errors(),
        [ProtocolError::StaleObject, ProtocolError::StaleObject]
    );
    let inbox = h.roundtrip(&mut a, Request::UnregisterBuffer { buffer });
    assert!(inbox.errors().is_empty());
}

#[test]
fn fatal_protocol_errors_disconnect_and_release_everything() {
    let mut h = Harness::new();
    let mut a = h.client(2);
    let mut b = h.client(3);
    let buffer = h.buffer(&mut a, 8, 8, RED);
    let (surface, _) = h.toplevel(&mut a, buffer, Point { x: 0, y: 0 });

    // An unknown role byte is a malformed frame, which is fatal.
    let mut frame = Request::AssignRole {
        surface,
        role: SurfaceRole::Toplevel,
        parent: None,
    }
    .encode(0x99)
    .unwrap();
    frame[12] = 0xee;
    h.send_raw(&a, &frame, None);
    h.pump();
    let inbox = h.drain(&a);
    let reason = inbox.disconnected.expect("disconnected");
    assert!(matches!(
        DisconnectReason::decode(reason),
        Some(DisconnectReason::ProtocolViolation(_))
    ));
    assert_eq!(h.comp.client_count(), 1);
    assert_eq!(h.shm.live_mappings(), 0);
    assert_eq!(h.comp.budget().used(ObjectKind::Surface), 0);
    assert_eq!(h.pixel(1, 1), BACKGROUND);

    // Hello is accepted exactly once.
    let inbox = h.roundtrip(
        &mut b,
        Request::Hello {
            version: ProtocolVersion {
                major: PROTOCOL_MAJOR,
                minor: PROTOCOL_MINOR,
            },
            features: Features(0),
        },
    );
    assert_eq!(inbox.errors(), [ProtocolError::UnsupportedVersion]);
    assert_eq!(
        inbox.disconnected,
        Some(DisconnectReason::ProtocolViolation(ProtocolError::UnsupportedVersion).encode())
    );
}

#[test]
fn requests_before_hello_are_fatal() {
    let mut h = Harness::new();
    let mut a = h.connect(2);
    let inbox = h.roundtrip(&mut a, Request::CreateSurface);
    assert_eq!(inbox.errors(), [ProtocolError::UnsupportedVersion]);
    assert!(inbox.disconnected.is_some());
    assert_eq!(h.comp.client_count(), 0);
}

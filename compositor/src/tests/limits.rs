//! Capacity limits: every exhaustion is a recoverable error or a bounded disconnect, never a
//! compositor failure.

use super::*;
use clean_slate_graphics::limits::{
    MAX_BUFFERS_PER_CLIENT, MAX_CLIENTS, MAX_CLIENT_STALL_ITERATIONS, MAX_REGISTERED_BUFFERS,
    MAX_SURFACES, MAX_SURFACES_PER_CLIENT,
};
use clean_slate_graphics::objects::ObjectKind;
use clean_slate_graphics::protocol::DisconnectReason;

fn try_surface(h: &mut Harness, client: &mut Client) -> Result<SurfaceId, Vec<ProtocolError>> {
    let inbox = h.roundtrip(client, Request::CreateSurface);
    inbox
        .events
        .iter()
        .find_map(|(_, e)| match e {
            Event::SurfaceCreated { surface } => Some(*surface),
            _ => None,
        })
        .ok_or_else(|| inbox.errors())
}

fn try_buffer(h: &mut Harness, client: &mut Client) -> Vec<ProtocolError> {
    let (_, cap, layout) = h.shared_buffer(client, 4, 4, RED);
    try_register(h, client, cap, layout)
}

fn try_register(
    h: &mut Harness,
    client: &mut Client,
    cap: u64,
    layout: BufferLayout,
) -> Vec<ProtocolError> {
    h.send_with(client, Request::RegisterBuffer { layout }, Some(cap));
    h.pump();
    h.drain(client).errors()
}

/// A fresh grant of an existing buffer: the fake port holds only 16 distinct buffer ids.
fn regrant(h: &mut Harness, client: &Client, id: SharedBufferId) -> (u64, BufferLayout) {
    let layout = BufferLayout::new(4, 4, 16, PixelFormat::Xrgb8888).unwrap();
    let cap = h
        .port
        .grant_shared_buffer(
            client.holder,
            id,
            layout.byte_len() as u64,
            Rights::READ.union(Rights::DELEGATE),
        )
        .unwrap();
    (cap, layout)
}

#[test]
fn surface_capacity_is_bounded_and_recoverable() {
    let mut h = Harness::new();
    let mut a = h.client(2);
    let surfaces: Vec<_> = (0..MAX_SURFACES_PER_CLIENT)
        .map(|_| try_surface(&mut h, &mut a).unwrap())
        .collect();
    assert_eq!(
        try_surface(&mut h, &mut a),
        Err(vec![ProtocolError::LimitExceeded])
    );
    // Still connected and usable: freeing one makes room again.
    h.roundtrip(
        &mut a,
        Request::DestroySurface {
            surface: surfaces[0],
        },
    );
    assert!(try_surface(&mut h, &mut a).is_ok());

    // The global table is shared fairly: four full clients exhaust it, a fifth is refused.
    let mut others: Vec<_> = (3..6).map(|holder| h.client(holder)).collect();
    for client in &mut others {
        for _ in 0..MAX_SURFACES_PER_CLIENT {
            try_surface(&mut h, client).unwrap();
        }
    }
    assert_eq!(h.comp.budget().used(ObjectKind::Surface), MAX_SURFACES);
    let mut late = h.client(9);
    assert_eq!(
        try_surface(&mut h, &mut late),
        Err(vec![ProtocolError::LimitExceeded])
    );
    assert_eq!(h.comp.client_count(), 5);
}

#[test]
fn buffer_registration_capacity_is_bounded_per_client_and_globally() {
    let mut h = Harness::new();
    let mut a = h.client(2);
    let (first, cap, layout) = h.shared_buffer(&a, 4, 4, RED);
    assert!(try_register(&mut h, &mut a, cap, layout).is_empty());
    for _ in 1..MAX_BUFFERS_PER_CLIENT {
        assert!(try_buffer(&mut h, &mut a).is_empty());
    }
    let discarded = h.shm.discarded();
    let (cap, layout) = regrant(&mut h, &a, first);
    assert_eq!(
        try_register(&mut h, &mut a, cap, layout),
        [ProtocolError::LimitExceeded]
    );
    assert_eq!(h.shm.discarded(), discarded + 1, "refused grant is dropped");

    let mut b = h.client(3);
    for _ in 0..MAX_REGISTERED_BUFFERS - MAX_BUFFERS_PER_CLIENT {
        assert!(try_buffer(&mut h, &mut b).is_empty());
    }
    let mut c = h.client(4);
    let (cap, layout) = regrant(&mut h, &c, first);
    assert_eq!(
        try_register(&mut h, &mut c, cap, layout),
        [ProtocolError::LimitExceeded]
    );
    assert_eq!(h.shm.live_mappings() as usize, MAX_REGISTERED_BUFFERS);
}

#[test]
fn mapping_exhaustion_is_reported_not_fatal() {
    let mut h = Harness::new();
    let mut a = h.client(2);
    h.shm.limit_maps(0);
    assert_eq!(try_buffer(&mut h, &mut a), [ProtocolError::LimitExceeded]);
    h.shm.limit_maps(u32::MAX);
    assert!(try_buffer(&mut h, &mut a).is_empty());
}

#[test]
fn in_flight_buffers_are_bounded_per_surface() {
    let mut h = Harness::new();
    let mut a = h.client(2);
    let b1 = h.buffer(&mut a, 8, 8, RED);
    let b2 = h.buffer(&mut a, 8, 8, GREEN);
    let b3 = h.buffer(&mut a, 8, 8, BLUE);
    let (surface, _) = h.toplevel(&mut a, b1, Point { x: 0, y: 0 });
    let other = h.surface(&mut a);

    // Hold a present in flight so newer commits cannot be latched.
    h.auto_complete = false;
    h.damage_commit(&mut a, surface, &[rect(0, 0, 1, 1)], false);
    assert!(h.display.inner.status().in_flight_index.is_some());

    let inbox = h.attach_commit(&mut a, surface, Some(b2), None, false);
    assert!(inbox.errors().is_empty());
    for busy in [b1, b2] {
        let inbox = h.attach_commit(&mut a, other, Some(busy), None, false);
        assert_eq!(
            inbox.errors(),
            [ProtocolError::BufferBusy],
            "busy buffers cannot be attached anywhere"
        );
    }
    // A third commit supersedes the uncomposited one instead of growing the in-flight set.
    let mut damage = [rect(0, 0, 0, 0); 5];
    damage[0] = rect(0, 0, 8, 8);
    h.send(
        &mut a,
        Request::Damage {
            surface,
            rects: damage,
            count: 1,
        },
    );
    let inbox = h.attach_commit(&mut a, surface, Some(b3), None, false);
    assert_eq!(inbox.released(), [b2]);

    h.auto_complete = true;
    h.complete_present();
    h.pump();
    assert_eq!(h.drain(&a).released(), [b1]);
    assert_eq!(h.pixel(1, 1), BLUE);
}

#[test]
fn client_capacity_rejects_extra_connections_without_disturbing_others() {
    let mut h = Harness::new();
    let mut clients: Vec<_> = (0..MAX_CLIENTS as u64).map(|i| h.client(10 + i)).collect();
    let mut extra = h.connect(99);
    h.send(
        &mut extra,
        Request::Hello {
            version: ProtocolVersion {
                major: PROTOCOL_MAJOR,
                minor: PROTOCOL_MINOR,
            },
            features: Features(0),
        },
    );
    h.pump();
    let inbox = h.drain(&extra);
    assert_eq!(
        inbox.disconnected,
        Some(DisconnectReason::QueueOverflow.encode())
    );
    assert_eq!(h.comp.stats().rejected_connections, 1);
    assert_eq!(h.comp.client_count(), MAX_CLIENTS);
    for client in &mut clients {
        assert!(try_surface(&mut h, client).is_ok());
    }
}

#[test]
fn stalled_client_is_disconnected_after_bounded_retries() {
    let mut params = port_params();
    params.event_depth = 2;
    let mut h = Harness::with_params(params);
    let mut slow = h.connect(2);
    h.send(
        &mut slow,
        Request::Hello {
            version: ProtocolVersion {
                major: PROTOCOL_MAJOR,
                minor: PROTOCOL_MINOR,
            },
            features: Features(0),
        },
    );
    for _ in 0..6 {
        h.send(&mut slow, Request::CreateSurface);
    }
    let mut fast = h.connect(3);
    h.send(
        &mut fast,
        Request::Hello {
            version: ProtocolVersion {
                major: PROTOCOL_MAJOR,
                minor: PROTOCOL_MINOR,
            },
            features: Features(0),
        },
    );
    h.pump();
    // Request wakes also flush, so a few of the retries are not deadline wakes.
    let retries = u64::from(MAX_CLIENT_STALL_ITERATIONS);
    assert!(
        (retries - 2..=retries).contains(&(h.waiter.deadline_wakes as u64)),
        "bounded retries, not an indefinite wait: {}",
        h.waiter.deadline_wakes
    );
    let inbox = h.drain(&slow);
    assert_eq!(inbox.events.len(), 2, "ring depth");
    assert_eq!(
        inbox.disconnected,
        Some(DisconnectReason::QueueOverflow.encode())
    );
    assert!(matches!(
        h.drain(&fast).events.as_slice(),
        [(_, Event::Welcome { .. })]
    ));
    assert_eq!(h.comp.client_count(), 1);
    assert_eq!(h.comp.budget().used(ObjectKind::Surface), 0);
}

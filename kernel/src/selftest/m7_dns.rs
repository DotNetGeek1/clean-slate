use core::arch::asm;
use core::mem::MaybeUninit;

use clean_slate_network::device::NetworkLink;
use clean_slate_network::dns::{DnsError, DnsResolver, ResolveOutcome};
use clean_slate_network::error::NetworkError;
use clean_slate_network::fixture::{
    DNS_SERVER_ADDR, FIXTURE_A_RECORD, FIXTURE_A_TTL_SECS, FIXTURE_HOSTNAME, GUEST_IPV4,
};
use clean_slate_network::protocol::TrustedCaller;
use clean_slate_network::session::SessionGeneration;
use clean_slate_network::stack::L3Stack;

use crate::arch::x86_64::cpu::enable_interrupts;
use crate::device::virtio::net::VirtioNetDevice;
use crate::diagnostics::qemu::{qemu_exit, QEMU_EXIT_SUCCESS};
use crate::interrupt::timer::kernel_ticks;
use crate::{serial_write_fmt, serial_write_line};

const ARP_TTL_TICKS: u64 = 50_000;
const POLL_SPIN_LIMIT: usize = 50_000_000;
const DNS_OWNER: TrustedCaller = TrustedCaller::new(0x4D37, 0, 1);

static mut RESOLVER_STORAGE: MaybeUninit<DnsResolver<VirtioNetDevice>> = MaybeUninit::uninit();

#[allow(static_mut_refs)]
pub(crate) fn run_m7_dns_self_test() -> Result<(), &'static str> {
    enable_interrupts();
    let device = VirtioNetDevice::discover()?;
    let mac = device.link().mac;
    serial_write_fmt(format_args!("[DNS ] virtio ready mac="));
    mac.write_to(&mut SerialWriter)
        .map_err(|_| "serial write failed")?;
    serial_write_line("");

    unsafe {
        DnsResolver::init_in_place(
            RESOLVER_STORAGE.as_mut_ptr(),
            L3Stack::new(device, mac, GUEST_IPV4, ARP_TTL_TICKS),
            SessionGeneration::new(1),
            DNS_SERVER_ADDR,
            DnsResolver::<VirtioNetDevice>::DEFAULT_TICKS_PER_SEC,
        );
        run_cases(&mut *RESOLVER_STORAGE.as_mut_ptr())?;
    }
    serial_write_line("[M7.5] PASS");
    qemu_exit(QEMU_EXIT_SUCCESS);
}

fn run_cases(resolver: &mut DnsResolver<VirtioNetDevice>) -> Result<(), &'static str> {
    resolve_and_print(resolver, FIXTURE_HOSTNAME, true)?;
    resolve_cache_hit(resolver, FIXTURE_HOSTNAME)?;
    resolve_nxdomain(resolver, "nope.fixture.test")?;
    Ok(())
}

struct SerialWriter;

impl core::fmt::Write for SerialWriter {
    fn write_str(&mut self, s: &str) -> core::fmt::Result {
        serial_write_fmt(format_args!("{s}"));
        Ok(())
    }
}

fn resolve_and_print(
    resolver: &mut DnsResolver<VirtioNetDevice>,
    name: &str,
    expect_addr: bool,
) -> Result<(), &'static str> {
    let mut now = kernel_ticks();
    let outcome = resolver
        .resolve(now, DNS_OWNER, name)
        .map_err(map_dns_error)?;
    let query_id = match outcome {
        ResolveOutcome::Cached { addr, ttl } => {
            print_resolved(name, addr, ttl);
            return Ok(());
        }
        ResolveOutcome::Pending { query_id } => query_id,
    };

    for _ in 0..POLL_SPIN_LIMIT {
        resolver.poll(now).map_err(map_dns_error)?;
        if let Some(result) = resolver.take_result(query_id, DNS_OWNER) {
            match result {
                Ok((addr, ttl)) => {
                    if expect_addr {
                        if addr != FIXTURE_A_RECORD || ttl != FIXTURE_A_TTL_SECS {
                            return Err("unexpected DNS answer");
                        }
                        print_resolved(name, addr, ttl);
                    }
                    return Ok(());
                }
                Err(err) => return Err(map_dns_error(err)),
            }
        }
        now = paced_monotonic_tick(now);
    }
    fail("timeout waiting for DNS")
}

fn resolve_cache_hit(
    resolver: &mut DnsResolver<VirtioNetDevice>,
    name: &str,
) -> Result<(), &'static str> {
    let outcome = resolver
        .resolve(0, DNS_OWNER, name)
        .map_err(map_dns_error)?;
    match outcome {
        ResolveOutcome::Cached { .. } => {
            serial_write_fmt(format_args!("[DNS ] cache hit name={name}\n"));
            Ok(())
        }
        _ => Err("expected cache hit"),
    }
}

fn resolve_nxdomain(
    resolver: &mut DnsResolver<VirtioNetDevice>,
    name: &str,
) -> Result<(), &'static str> {
    let mut now = kernel_ticks();
    let query_id = match resolver
        .resolve(now, DNS_OWNER, name)
        .map_err(map_dns_error)?
    {
        ResolveOutcome::Pending { query_id } => query_id,
        _ => return Err("expected pending nxdomain query"),
    };
    for _ in 0..POLL_SPIN_LIMIT {
        resolver.poll(now).map_err(map_dns_error)?;
        if let Some(result) = resolver.take_result(query_id, DNS_OWNER) {
            match result {
                Err(DnsError::NameNotFound) => {
                    serial_write_fmt(format_args!("[DNS ] nxdomain name={name}\n"));
                    return Ok(());
                }
                Ok(_) => return Err("expected nxdomain"),
                Err(other) => return Err(map_dns_error(other)),
            }
        }
        now = paced_monotonic_tick(now);
    }
    fail("timeout waiting for nxdomain")
}

fn paced_monotonic_tick(now: u64) -> u64 {
    loop {
        let observed = kernel_ticks();
        if observed > now {
            return observed;
        }
        unsafe {
            asm!("hlt", options(nomem, nostack, preserves_flags));
        }
    }
}

fn print_resolved(name: &str, addr: clean_slate_network::addr::Ipv4Addr, ttl: u32) {
    serial_write_fmt(format_args!(
        "[DNS ] resolved name={name} addr={}.{}.{}.{} ttl={ttl}\n",
        addr.octets()[0],
        addr.octets()[1],
        addr.octets()[2],
        addr.octets()[3]
    ));
}

fn fail(reason: &'static str) -> Result<(), &'static str> {
    serial_write_fmt(format_args!("[DNS ] FAIL reason={reason}\n"));
    Err(reason)
}

fn map_dns_error(err: DnsError) -> &'static str {
    match err {
        DnsError::NameNotFound => "nxdomain",
        DnsError::Timeout => "timeout",
        DnsError::QueueFull => "queue full",
        DnsError::Transport(NetworkError::Unreachable) => "unreachable",
        DnsError::Transport(NetworkError::SessionExhausted) => "session exhausted",
        DnsError::Transport(_) => "transport error",
        _ => "dns protocol error",
    }
}

use core::mem::MaybeUninit;

use clean_slate_network::addr::Ipv4Addr;
use clean_slate_network::device::NetworkLink;
use clean_slate_network::dns::{DnsError, DnsResolver, ResolveOutcome, DNS_QUERY_TIMEOUT_MS};
use clean_slate_network::error::NetworkError;
use clean_slate_network::fixture::{
    DNS_SERVER_ADDR, FIXTURE_A_RECORD, FIXTURE_A_TTL_SECS, FIXTURE_HOSTNAME, GUEST_IPV4,
};
use clean_slate_network::protocol::TrustedCaller;
use clean_slate_network::session::SessionGeneration;
use clean_slate_network::stack::L3Stack;

use crate::device::virtio::net::{NetInterruptSinks, VirtioNetDevice};
use crate::diagnostics::qemu::{qemu_exit, QEMU_EXIT_SUCCESS};
use crate::selftest::boot_wait::{self, now_ms};
use crate::{serial_write_fmt, serial_write_line};

/// The stack and resolver clock is calibrated TSC milliseconds ([`now_ms`]).
const ARP_TTL_MS: u64 = 40_000;
const MS_PER_SEC: u64 = 1000;
/// Backstop over the resolver's own query deadline, which reports `Timeout` first.
const QUERY_WAIT_BUDGET_MS: u64 = 4 * DNS_QUERY_TIMEOUT_MS;
const DNS_OWNER: TrustedCaller = TrustedCaller::new(0x4D37, 0, 1);

static mut RESOLVER_STORAGE: MaybeUninit<DnsResolver<VirtioNetDevice>> = MaybeUninit::uninit();

#[allow(static_mut_refs)]
pub(crate) fn run_m7_dns_self_test() -> Result<(), &'static str> {
    boot_wait::init_clock()?;
    let device = VirtioNetDevice::discover(NetInterruptSinks::NONE)?;
    let mac = device.link().mac;
    serial_write_fmt(format_args!("[DNS ] virtio ready mac="));
    mac.write_to(&mut SerialWriter)
        .map_err(|_| "serial write failed")?;
    serial_write_line("");

    unsafe {
        DnsResolver::init_in_place(
            RESOLVER_STORAGE.as_mut_ptr(),
            L3Stack::new(device, mac, GUEST_IPV4, ARP_TTL_MS),
            SessionGeneration::new(1),
            DNS_SERVER_ADDR,
            MS_PER_SEC,
        );
        run_cases(&mut *RESOLVER_STORAGE.as_mut_ptr())?;
    }
    serial_write_line("[M7.5] PASS");
    qemu_exit(QEMU_EXIT_SUCCESS);
}

fn run_cases(resolver: &mut DnsResolver<VirtioNetDevice>) -> Result<(), &'static str> {
    resolve_and_print(resolver, FIXTURE_HOSTNAME)?;
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

/// Polls the resolver on the real clock, halting between polls, until `query_id` has a
/// result.
fn await_result(
    resolver: &mut DnsResolver<VirtioNetDevice>,
    query_id: u32,
) -> Result<Result<(Ipv4Addr, u32), DnsError>, &'static str> {
    boot_wait::wait_until(QUERY_WAIT_BUDGET_MS, "timeout waiting for DNS", |now| {
        resolver.poll(now).map_err(map_dns_error)?;
        Ok(resolver.take_result(query_id, DNS_OWNER))
    })
    .or_else(fail)
}

fn resolve_and_print(
    resolver: &mut DnsResolver<VirtioNetDevice>,
    name: &str,
) -> Result<(), &'static str> {
    let query_id = match resolver
        .resolve(now_ms(), DNS_OWNER, name)
        .map_err(map_dns_error)?
    {
        ResolveOutcome::Cached { .. } => return Err("first resolve hit an empty cache"),
        ResolveOutcome::Pending { query_id } => query_id,
    };
    let (addr, ttl) = await_result(resolver, query_id)?.map_err(map_dns_error)?;
    if addr != FIXTURE_A_RECORD || ttl != FIXTURE_A_TTL_SECS {
        return Err("unexpected DNS answer");
    }
    print_resolved(name, addr, ttl);
    Ok(())
}

fn resolve_cache_hit(
    resolver: &mut DnsResolver<VirtioNetDevice>,
    name: &str,
) -> Result<(), &'static str> {
    let outcome = resolver
        .resolve(now_ms(), DNS_OWNER, name)
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
    let query_id = match resolver
        .resolve(now_ms(), DNS_OWNER, name)
        .map_err(map_dns_error)?
    {
        ResolveOutcome::Pending { query_id } => query_id,
        _ => return Err("expected pending nxdomain query"),
    };
    match await_result(resolver, query_id)? {
        Err(DnsError::NameNotFound) => {
            serial_write_fmt(format_args!("[DNS ] nxdomain name={name}\n"));
            Ok(())
        }
        Ok(_) => Err("expected nxdomain"),
        Err(other) => Err(map_dns_error(other)),
    }
}

fn print_resolved(name: &str, addr: Ipv4Addr, ttl: u32) {
    serial_write_fmt(format_args!(
        "[DNS ] resolved name={name} addr={}.{}.{}.{} ttl={ttl}\n",
        addr.octets()[0],
        addr.octets()[1],
        addr.octets()[2],
        addr.octets()[3]
    ));
}

fn fail<T>(reason: &'static str) -> Result<T, &'static str> {
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

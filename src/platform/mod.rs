#[cfg(target_os = "linux")]
pub mod linux;
#[cfg(target_os = "macos")]
pub mod macos;
/// Locating Npcap before the capture path needs it. Windows only, and called
/// from `main` before anything touches libpcap.
#[cfg(target_os = "windows")]
pub mod npcap;
#[cfg(target_os = "macos")]
pub mod pktap;
/// Kernel-derived process identity — every platform, including the fallback
/// that returns nothing so callers keep the name they already had.
pub mod procname;
#[cfg(target_os = "windows")]
pub mod windows;

use anyhow::Result;
use std::collections::HashMap;

#[derive(Debug, Clone)]
pub struct InterfaceStats {
    #[allow(dead_code)]
    pub name: String,
    pub rx_bytes: u64,
    pub tx_bytes: u64,
    pub rx_packets: u64,
    pub tx_packets: u64,
    pub rx_errors: u64,
    pub tx_errors: u64,
    pub rx_drops: u64,
    pub tx_drops: u64,
    /// Signal level in dBm for an 802.11 interface, where the kernel reports
    /// one. `None` on wired links and on platforms without a source.
    pub signal_dbm: Option<i32>,
    /// Cumulative 802.11 transmit retries, same caveat. A rate is derived
    /// against `tx_packets` upstream.
    pub tx_retries: Option<u64>,
}

#[derive(Debug, Clone)]
pub struct InterfaceInfo {
    pub name: String,
    pub ipv4: Option<String>,
    pub ipv6: Option<String>,
    pub mac: Option<String>,
    pub mtu: Option<u32>,
    pub is_up: bool,
    /// `Some(true)` for wireless (Wi-Fi), `Some(false)` for wired Ethernet,
    /// `None` when the OS didn't give us a definitive answer (e.g. loopback,
    /// VPN, virtual interfaces — or the lookup failed).
    pub is_wireless: Option<bool>,
}

pub fn collect_interface_stats() -> Result<HashMap<String, InterfaceStats>> {
    #[cfg(target_os = "linux")]
    return linux::collect_interface_stats();

    #[cfg(target_os = "macos")]
    return macos::collect_interface_stats();

    #[cfg(target_os = "windows")]
    return windows::collect_interface_stats();

    #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
    anyhow::bail!("Unsupported platform")
}

/// Name of the interface carrying the default route, if the platform can
/// tell us. Used to bias capture-interface selection toward the NIC that
/// actually carries traffic — on multi-NIC machines enumeration order says
/// nothing about which port has the cable (issue #43).
pub fn default_route_interface() -> Option<String> {
    #[cfg(target_os = "linux")]
    return linux::default_route_interface();

    #[cfg(target_os = "macos")]
    return macos::default_route_interface();

    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    None
}

/// Negotiated link speed in bits per second, when the OS will tell us.
///
/// Feeds the Dense view's saturation meter: "51% of a 1 Gb link" is a fact
/// about your network, while "51% of the busiest second we've seen" is a fact
/// about our own sampling. Only the first is worth a red zone, so where this
/// returns `None` the meter re-labels itself rather than inventing a ceiling.
///
/// Two cfg'd definitions rather than one function with cfg'd blocks: the block
/// form leaves a `return` that is needless on exactly one platform, which is a
/// lint you only see on that platform's CI.
#[cfg(target_os = "linux")]
pub fn link_speed_bps(iface: &str) -> Option<u64> {
    // /sys/class/net/<if>/speed is in Mb/s, and reads -1 (or fails with
    // EINVAL) for virtual, down, or wireless interfaces that can't report one.
    let raw = std::fs::read_to_string(format!("/sys/class/net/{iface}/speed")).ok()?;
    let mbps: i64 = raw.trim().parse().ok()?;
    if mbps <= 0 {
        return None;
    }
    Some(mbps as u64 * 1_000_000)
}

/// macOS: `ifi_baudrate` from `getifaddrs`, which is the link's currently
/// negotiated rate — a real gigabit figure on Ethernet, and the live PHY rate
/// on Wi-Fi (it moves as the radio renegotiates, because the capacity really
/// does move).
///
/// `getifaddrs` is a syscall, deliberately: this is read on every refresh, and
/// the rest of this module already shells out to `netstat`/`ifconfig` per tick.
/// Adding a fourth fork to the tick path to fetch one integer would be a poor
/// trade.
#[cfg(target_os = "macos")]
pub fn link_speed_bps(iface: &str) -> Option<u64> {
    use std::ffi::CStr;

    let mut ifap: *mut nix::libc::ifaddrs = std::ptr::null_mut();
    // SAFETY: `getifaddrs` fills `ifap` with an owned list we free below; every
    // pointer is null-checked before it is read.
    if unsafe { nix::libc::getifaddrs(&mut ifap) } != 0 || ifap.is_null() {
        return None;
    }
    let mut speed = None;
    let mut cur = ifap;
    while !cur.is_null() {
        let entry = unsafe { &*cur };
        cur = entry.ifa_next;
        if entry.ifa_addr.is_null() || entry.ifa_data.is_null() {
            continue;
        }
        // Only the AF_LINK entry carries `if_data`; the AF_INET ones don't.
        if i32::from(unsafe { (*entry.ifa_addr).sa_family }) != nix::libc::AF_LINK {
            continue;
        }
        let name = unsafe { CStr::from_ptr(entry.ifa_name) };
        if name.to_string_lossy() != iface {
            continue;
        }
        let data = unsafe { &*(entry.ifa_data as *const nix::libc::if_data) };
        if data.ifi_baudrate > 0 {
            speed = Some(u64::from(data.ifi_baudrate));
        }
        break;
    }
    // SAFETY: `ifap` came from a successful `getifaddrs` and is freed once.
    unsafe { nix::libc::freeifaddrs(ifap) };
    speed
}

/// Windows would come from `GetIfEntry2`'s `TransmitLinkSpeed`; not wired up
/// yet, so the saturation meter falls back to labelling itself against the
/// observed peak rather than inventing a ceiling.
#[cfg(not(any(target_os = "linux", target_os = "macos")))]
pub fn link_speed_bps(_iface: &str) -> Option<u64> {
    None
}

pub fn collect_interface_info() -> Result<Vec<InterfaceInfo>> {
    #[cfg(target_os = "linux")]
    return linux::collect_interface_info();

    #[cfg(target_os = "macos")]
    return macos::collect_interface_info();

    #[cfg(target_os = "windows")]
    return windows::collect_interface_info();

    #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
    anyhow::bail!("Unsupported platform")
}

#[cfg(test)]
mod link_speed_tests {
    /// Talks to the running kernel, so it is environment-dependent and
    /// `#[ignore]`d. Run it to see what your link actually reports:
    /// `cargo test --lib link_speed -- --ignored --nocapture`
    ///
    /// A saturation meter is only worth drawing if this returns a real
    /// capacity; where it returns `None` the meter has to say so rather than
    /// invent a ceiling.
    #[test]
    #[ignore]
    fn live_link_speed_is_plausible() {
        for iface in ["en0", "eth0", "wlan0"] {
            if let Some(bps) = super::link_speed_bps(iface) {
                println!("{iface}: {bps} bps ({} Mb)", bps / 1_000_000);
                assert!(
                    (1_000_000..=800_000_000_000u64).contains(&bps),
                    "{iface} reported {bps} bps, which is not a link speed"
                );
            }
        }
    }
}

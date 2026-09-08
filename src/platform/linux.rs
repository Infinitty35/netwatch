use super::{InterfaceInfo, InterfaceStats};
use anyhow::Result;
use std::collections::HashMap;
use std::fs;
use std::path::Path;

/// Signal level and retry counter per wireless interface, from
/// `/proc/net/wireless`.
///
/// The file has one row per 802.11 device: `iface: status link level noise
/// nwid crypt frag retry misc beacon`. `level` is dBm on every driver that
/// matters now (mac80211 reports it signed); a positive value is a legacy
/// percentage and is dropped rather than reported as +60 dBm.
pub fn collect_wireless_stats() -> HashMap<String, (Option<i32>, u64)> {
    fs::read_to_string("/proc/net/wireless")
        .map(|t| parse_wireless(&t))
        .unwrap_or_default()
}

fn parse_wireless(text: &str) -> HashMap<String, (Option<i32>, u64)> {
    let mut out = HashMap::new();
    for line in text.lines().skip(2) {
        let Some((name, rest)) = line.split_once(':') else {
            continue;
        };
        let cols: Vec<&str> = rest.split_whitespace().collect();
        if cols.len() < 8 {
            continue;
        }
        let level = cols[2]
            .trim_end_matches('.')
            .parse::<f64>()
            .ok()
            .map(|v| v as i32)
            .filter(|v| *v < 0);
        let retry = cols[7].parse::<u64>().unwrap_or(0);
        out.insert(name.trim().to_string(), (level, retry));
    }
    out
}

pub fn collect_interface_stats() -> Result<HashMap<String, InterfaceStats>> {
    let mut stats = HashMap::new();
    let net_dir = Path::new("/sys/class/net");
    let wireless = collect_wireless_stats();

    for entry in fs::read_dir(net_dir)? {
        let entry = entry?;
        let name = entry.file_name().to_string_lossy().to_string();
        let base = net_dir.join(&name).join("statistics");

        let read = |file: &str| -> u64 {
            fs::read_to_string(base.join(file))
                .unwrap_or_default()
                .trim()
                .parse()
                .unwrap_or(0)
        };

        let wifi = wireless.get(&name).copied();
        stats.insert(
            name.clone(),
            InterfaceStats {
                name,
                rx_bytes: read("rx_bytes"),
                tx_bytes: read("tx_bytes"),
                rx_packets: read("rx_packets"),
                tx_packets: read("tx_packets"),
                rx_errors: read("rx_errors"),
                tx_errors: read("tx_errors"),
                rx_drops: read("rx_dropped"),
                tx_drops: read("tx_dropped"),
                signal_dbm: wifi.and_then(|w| w.0),
                tx_retries: wifi.map(|w| w.1),
            },
        );
    }

    Ok(stats)
}

pub fn collect_interface_info() -> Result<Vec<InterfaceInfo>> {
    let mut interfaces = Vec::new();
    let net_dir = Path::new("/sys/class/net");

    for entry in fs::read_dir(net_dir)? {
        let entry = entry?;
        let name = entry.file_name().to_string_lossy().to_string();
        let base = net_dir.join(&name);

        let operstate = fs::read_to_string(base.join("operstate")).unwrap_or_default();
        let operstate = operstate.trim();
        let is_up = operstate == "up"
            || (operstate == "unknown"
                && fs::read_to_string(base.join("carrier"))
                    .unwrap_or_default()
                    .trim()
                    == "1");

        let mtu = fs::read_to_string(base.join("mtu"))
            .unwrap_or_default()
            .trim()
            .parse()
            .ok();

        let mac = fs::read_to_string(base.join("address"))
            .ok()
            .map(|s| s.trim().to_string())
            .filter(|s| s != "00:00:00:00:00:00");

        // Get IP addresses from `ip addr show <name>` on Linux
        let (ipv4, ipv6) = get_ip_addresses(&name);

        // /sys/class/net/<name>/wireless is present iff the kernel registered
        // the device as 802.11 wireless. Absent for wired/virtual interfaces.
        let is_wireless = if base.join("wireless").exists() {
            Some(true)
        } else if mac.is_some() {
            // Has a MAC address but no wireless dir → wired Ethernet (or other
            // L2 device the kernel doesn't tag as wireless).
            Some(false)
        } else {
            None
        };

        interfaces.push(InterfaceInfo {
            name,
            ipv4,
            ipv6,
            mac,
            mtu,
            is_up,
            is_wireless,
        });
    }

    Ok(interfaces)
}

/// Name of the interface carrying the IPv4 default route, if any.
pub fn default_route_interface() -> Option<String> {
    let output = std::process::Command::new("ip")
        .args(["-4", "route", "show", "default"])
        .output()
        .ok()?;
    parse_default_route_dev(&String::from_utf8_lossy(&output.stdout))
}

fn parse_default_route_dev(text: &str) -> Option<String> {
    // e.g. "default via 192.168.1.1 dev eno2 proto dhcp metric 100"
    // With multiple default routes, `ip route show default` lists the
    // lowest-metric (preferred) one first, so take the first line's dev.
    text.lines()
        .filter(|l| l.starts_with("default"))
        .find_map(|l| {
            let mut tokens = l.split_whitespace();
            while let Some(t) = tokens.next() {
                if t == "dev" {
                    return tokens.next().map(str::to_string);
                }
            }
            None
        })
}

fn get_ip_addresses(iface: &str) -> (Option<String>, Option<String>) {
    let output = std::process::Command::new("ip")
        .args(["addr", "show", iface])
        .output();

    let Ok(output) = output else {
        return (None, None);
    };

    let text = String::from_utf8_lossy(&output.stdout);
    let mut ipv4 = None;
    let mut ipv6 = None;

    for line in text.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with("inet ") {
            ipv4 = trimmed
                .split_whitespace()
                .nth(1)
                .map(|s| s.split('/').next().unwrap_or(s).to_string());
        } else if trimmed.starts_with("inet6 ") && ipv6.is_none() {
            ipv6 = trimmed
                .split_whitespace()
                .nth(1)
                .map(|s| s.split('/').next().unwrap_or(s).to_string());
        }
    }

    (ipv4, ipv6)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_route_dev_typical_dhcp() {
        let out = "default via 192.168.1.1 dev eno2 proto dhcp src 192.168.1.50 metric 100 \n";
        assert_eq!(parse_default_route_dev(out).as_deref(), Some("eno2"));
    }

    #[test]
    fn default_route_dev_prefers_first_of_multiple() {
        // Two default routes: `ip route show default` orders by metric,
        // so the first line is the preferred route.
        let out = "default via 10.0.0.1 dev eno2 proto dhcp metric 100 \n\
                   default via 192.168.1.1 dev eno1 proto dhcp metric 200 \n";
        assert_eq!(parse_default_route_dev(out).as_deref(), Some("eno2"));
    }

    #[test]
    fn default_route_dev_none_when_no_default() {
        assert_eq!(parse_default_route_dev(""), None);
        assert_eq!(
            parse_default_route_dev("192.168.1.0/24 dev eno1 proto kernel scope link\n"),
            None
        );
    }

    #[test]
    fn default_route_dev_none_when_dev_missing() {
        // Malformed / unexpected line: "default" but no dev token.
        assert_eq!(parse_default_route_dev("default via 192.168.1.1\n"), None);
    }
}

#[cfg(test)]
mod wireless_tests {
    use super::*;

    #[test]
    fn proc_net_wireless_yields_level_and_retries() {
        let text =
            "Inter-| sta-|   Quality        |   Discarded packets               | Missed | WE\n\
 face | tus | link level noise |  nwid  crypt   frag  retry   misc | beacon | 22\n\
 wlan0: 0000   54.  -56.  -256        0      0      0   1234      0        0\n\
 wlan1: 0000   70.   70.  -256        0      0      0      7      0        0\n";
        let m = parse_wireless(text);
        assert_eq!(m["wlan0"], (Some(-56), 1234));
        // A positive level is a legacy percentage, not dBm.
        assert_eq!(m["wlan1"], (None, 7));
        assert!(parse_wireless("").is_empty());
    }
}

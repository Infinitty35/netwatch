//! SSDP — Simple Service Discovery Protocol (UPnP, port 1900).
//!
//! SSDP uses an HTTP-like text wire format over UDP. Two methods
//! dominate: `M-SEARCH * HTTP/1.1` (clients looking for services) and
//! `NOTIFY * HTTP/1.1` (services advertising themselves). The
//! interesting field is the search target (`ST:` for queries, `NT:` for
//! notifications) — that's the service the message is about.

use super::{AppProtocol, Classifier};
use crate::ui::sanitize::display;

pub struct SsdpClassifier;

impl Classifier for SsdpClassifier {
    fn classify(&self, payload: &[u8], is_tcp: bool) -> Option<AppProtocol> {
        if is_tcp {
            return None;
        }
        let text = std::str::from_utf8(payload).ok()?;
        let first_line = text.lines().next()?;

        let method = if first_line.starts_with("M-SEARCH ") {
            "M-SEARCH"
        } else if first_line.starts_with("NOTIFY ") {
            "NOTIFY"
        } else if first_line.starts_with("HTTP/1.1 200") {
            // Response to an M-SEARCH from a service. We classify those
            // too so a single SSDP-aware filter (`app:ssdp`) catches the
            // full exchange, not just one direction.
            "RESPONSE"
        } else {
            return None;
        };

        // First header value of ST (search target) or NT (notification
        // target) — both name the service.
        let target = text.lines().find_map(|l| {
            let lower = l.to_ascii_lowercase();
            if let Some(v) = lower.strip_prefix("st:") {
                Some(display(v.trim()).into_owned())
            } else {
                lower
                    .strip_prefix("nt:")
                    .map(|v| display(v.trim()).into_owned())
            }
        });

        Some(AppProtocol::Ssdp {
            method: method.to_string(),
            target,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn m_search_with_st() {
        let p = b"M-SEARCH * HTTP/1.1\r\nHost: 239.255.255.250:1900\r\nST: ssdp:all\r\n\r\n";
        let r = SsdpClassifier.classify(p, false).unwrap();
        assert_eq!(
            r,
            AppProtocol::Ssdp {
                method: "M-SEARCH".into(),
                target: Some("ssdp:all".into()),
            }
        );
    }

    #[test]
    fn notify_with_nt() {
        let p = b"NOTIFY * HTTP/1.1\r\nHost: 239.255.255.250:1900\r\nNT: upnp:rootdevice\r\n\r\n";
        let r = SsdpClassifier.classify(p, false).unwrap();
        assert_eq!(
            r,
            AppProtocol::Ssdp {
                method: "NOTIFY".into(),
                target: Some("upnp:rootdevice".into()),
            }
        );
    }

    /// Any host on the link can multicast a NOTIFY with any target.
    #[test]
    fn target_control_characters_are_replaced() {
        let p = "NOTIFY * HTTP/1.1\r\nNT: upnp:\x1b]52;c;AAAA\x07\u{FEFF}x\r\n\r\n";
        let r = SsdpClassifier.classify(p.as_bytes(), false).unwrap();
        assert_eq!(
            r,
            AppProtocol::Ssdp {
                method: "NOTIFY".into(),
                target: Some("upnp:·]52;c;aaaa··x".into()),
            }
        );
    }

    #[test]
    fn not_ssdp_returns_none() {
        let p = b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n";
        assert!(SsdpClassifier.classify(p, false).is_none());
    }

    #[test]
    fn tcp_returns_none() {
        let p = b"M-SEARCH * HTTP/1.1\r\n";
        assert!(SsdpClassifier.classify(p, true).is_none());
    }
}

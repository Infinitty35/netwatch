//! The HTTP client shared by the remote publisher and the geo and whois
//! lookups.
//!
//! ureq's default agent has no read or write timeout, so a server that
//! accepts the connection and then goes quiet holds the calling thread
//! forever. For the one geo or whois worker that means every later lookup
//! stalls behind it; for the remote sender it means the daemon's shutdown
//! drain never returns. Requests built from [`agent`] give up instead.

use std::sync::OnceLock;
use std::time::Duration;

/// How long to wait for the TCP connection to be established. The TLS
/// handshake after it is bounded by [`IO_TIMEOUT`] instead, per read and
/// write, like the rest of the request.
pub const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);

/// How long any single read or write may wait on the peer.
pub const IO_TIMEOUT: Duration = Duration::from_secs(10);

/// The shared agent. Built once, so its connection pool is shared too.
pub fn agent() -> &'static ureq::Agent {
    static AGENT: OnceLock<ureq::Agent> = OnceLock::new();
    AGENT.get_or_init(|| build(CONNECT_TIMEOUT, IO_TIMEOUT))
}

fn build(connect: Duration, io: Duration) -> ureq::Agent {
    ureq::AgentBuilder::new()
        .timeout_connect(connect)
        .timeout_read(io)
        .timeout_write(io)
        .build()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Instant;

    /// A server that accepts and then never answers. Without a read timeout
    /// the request below would never return.
    #[test]
    fn a_silent_server_times_out_instead_of_hanging() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!("http://{}/", listener.local_addr().unwrap());
        let _silent = std::thread::spawn(move || {
            let held: Vec<_> = listener.incoming().take(1).collect();
            std::thread::sleep(Duration::from_secs(5));
            drop(held);
        });

        let started = Instant::now();
        let result = build(CONNECT_TIMEOUT, Duration::from_millis(200))
            .get(&url)
            .call();
        assert!(
            matches!(result, Err(ureq::Error::Transport(_))),
            "{result:?}"
        );
        assert!(started.elapsed() < Duration::from_secs(3));
    }
}

//! Linux smoke check using a disposable sentinel, never real credentials.
//! Applies strict policy on the actual probe worker; parent cleans up the fixture.
#[cfg(not(target_os = "linux"))]
fn main() {
    println!("sandbox_smoke is Linux-only");
}

#[cfg(target_os = "linux")]
fn main() -> anyhow::Result<()> {
    use netwatch::sandbox::{worker, Mode, SandboxPaths};
    let root =
        std::env::temp_dir().join(format!("netwatch-sandbox-smoke-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir(&root)?;
    std::fs::write(root.join("sentinel"), b"test-only")?;
    let paths = SandboxPaths {
        cache_dir: Some(root.join("cache")),
        cwd: Some(root.join("exports")),
        ..Default::default()
    };
    paths.prepare()?;
    worker::install(Mode::Strict, paths).map_err(anyhow::Error::msg)?;
    let sentinel = root.join("sentinel");
    let exports = root.join("exports");
    worker::spawn("smoke", move || {
        assert_eq!(
            std::fs::read(sentinel).unwrap_err().kind(),
            std::io::ErrorKind::PermissionDenied
        );
        std::fs::write(exports.join("allowed"), b"test-only").unwrap();
        let sock = unsafe {
            nix::libc::socket(
                nix::libc::AF_INET,
                nix::libc::SOCK_RAW,
                nix::libc::IPPROTO_ICMP,
            )
        };
        if sock >= 0 {
            unsafe {
                nix::libc::close(sock);
            }
            panic!("raw socket remained available under strict policy");
        }
    })
    .join()
    .expect("probe worker panicked");
    let result = worker::wait_ready(std::time::Duration::from_secs(1));
    println!("{}", worker::summary());
    std::fs::remove_dir_all(root)?;
    result.map_err(anyhow::Error::msg)
}

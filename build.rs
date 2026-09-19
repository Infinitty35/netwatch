fn main() {
    embed_utf8_manifest();
    delay_load_wpcap();

    #[cfg(target_os = "windows")]
    windows::configure_npcap();
}

/// Delay-load `wpcap.dll` so a missing Npcap is our error to report.
///
/// Linked normally, `wpcap.dll` is a load-time import: the loader resolves it
/// before `main()` runs, and on a machine without Npcap — or with Npcap in its
/// default location, which isn't on the search path (issue #47) — the process
/// dies against a Windows message box. Nothing we can print, and `--version`
/// fails too, which is the one command a user runs to file the bug.
///
/// Delay-loading moves that resolution to first use, which lets
/// [`platform::npcap::ensure_wpcap`] point the loader at Npcap's directory and
/// load the DLL itself, with a readable failure if it isn't there.
///
/// Bins and tests: the flags belong to the final link, and `delayimp.lib` supplies
/// the `__delayLoadHelper2` thunk that the `/DELAYLOAD` imports call through.
/// Keyed on the *target* rather than the host, like the manifest above, so a
/// cross-compile gets the same treatment; MSVC-only because `/DELAYLOAD` is a
/// link.exe flag and the GNU toolchain neither needs nor understands it.
fn delay_load_wpcap() {
    if std::env::var_os("CARGO_CFG_WINDOWS").is_none() {
        return;
    }
    if std::env::var("CARGO_CFG_TARGET_ENV").as_deref() != Ok("msvc") {
        return;
    }
    println!("cargo:rustc-link-arg-bins=/DELAYLOAD:wpcap.dll");
    println!("cargo:rustc-link-arg-bins=delayimp.lib");
    // Test executables too: the lib's unit-test harness links pcap, and CI
    // runners have the SDK but not Npcap, so a load-time import kills the
    // test binary with STATUS_DLL_NOT_FOUND before a single test runs.
    println!("cargo:rustc-link-arg-tests=/DELAYLOAD:wpcap.dll");
    println!("cargo:rustc-link-arg-tests=delayimp.lib");
}

/// Embed a Windows application manifest that sets the process **active code
/// page to UTF-8** (Windows 10 1903+). libpcap / Npcap return device
/// descriptions and error strings in the system ANSI code page (e.g. CP936 on
/// Chinese-locale Windows); without this, the `pcap` crate's strict UTF-8
/// decode of those bytes fails with "libpcap returned invalid UTF-8", which
/// cascades into `Device::list()` and capture-open failures (issue #39).
/// Gated on `CARGO_CFG_WINDOWS` (the build *target*) so it works whether the
/// host is Windows or a cross-compile, and is a no-op for non-Windows targets.
fn embed_utf8_manifest() {
    println!("cargo:rerun-if-changed=build.rs");
    if std::env::var_os("CARGO_CFG_WINDOWS").is_none() {
        return;
    }
    use embed_manifest::manifest::ActiveCodePage;
    use embed_manifest::{embed_manifest, new_manifest};
    if let Err(e) = embed_manifest(new_manifest("NetWatch").active_code_page(ActiveCodePage::Utf8))
    {
        println!("cargo:warning=failed to embed Windows UTF-8 manifest: {e}");
    }
}

#[cfg(target_os = "windows")]
mod windows {
    use std::path::PathBuf;
    use std::process::Command;

    const NPCAP_SDK_URL: &str = "https://npcap.com/dist/npcap-sdk-1.13.zip";

    pub fn configure_npcap() {
        println!("cargo:rerun-if-env-changed=LIBPCAP_LIBDIR");
        println!("cargo:rerun-if-env-changed=NPCAP_SDK");

        // Defer to pcap crate if LIBPCAP_LIBDIR is explicitly set.
        if std::env::var("LIBPCAP_LIBDIR").is_ok() {
            return;
        }

        let arch = if std::env::var("CARGO_CFG_TARGET_ARCH").unwrap_or_default() == "x86" {
            "x86"
        } else {
            "x64"
        };

        // Check NPCAP_SDK env var.
        if let Ok(sdk) = std::env::var("NPCAP_SDK") {
            let lib_dir = PathBuf::from(&sdk).join("Lib").join(arch);
            if lib_dir.join("wpcap.lib").exists() {
                println!("cargo:rustc-link-search=native={}", lib_dir.display());
                return;
            }
        }

        // Check common install locations before downloading.
        let candidates = common_paths(arch);
        for path in &candidates {
            if path.join("wpcap.lib").exists() {
                println!("cargo:rustc-link-search=native={}", path.display());
                return;
            }
        }

        // Auto-download the SDK into OUT_DIR.
        let out_dir = PathBuf::from(std::env::var("OUT_DIR").unwrap());
        let sdk_dir = out_dir.join("npcap-sdk");
        let lib_dir = sdk_dir.join("Lib").join(arch);

        if lib_dir.join("wpcap.lib").exists() {
            println!("cargo:rustc-link-search=native={}", lib_dir.display());
            return;
        }

        eprintln!("Npcap SDK not found — downloading from npcap.com …");
        let zip_path = out_dir.join("npcap-sdk.zip");

        let ok = Command::new("powershell")
            .args([
                "-NoProfile", "-Command",
                &format!(
                    "[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12; \
                     Invoke-WebRequest -Uri '{}' -OutFile '{}'",
                    NPCAP_SDK_URL, zip_path.display()
                ),
            ])
            .status()
            .map(|s| s.success())
            .unwrap_or(false);

        if !ok {
            panic!(
                "\n\nFailed to download Npcap SDK.\n\
                 Install it manually from https://npcap.com/#download\n\
                 and set NPCAP_SDK=<path-to-extracted-sdk>\n"
            );
        }

        let ok = Command::new("powershell")
            .args([
                "-NoProfile",
                "-Command",
                &format!(
                    "Expand-Archive -Path '{}' -DestinationPath '{}' -Force",
                    zip_path.display(),
                    sdk_dir.display()
                ),
            ])
            .status()
            .map(|s| s.success())
            .unwrap_or(false);

        if !ok {
            panic!("\n\nFailed to extract Npcap SDK zip.\n");
        }

        println!("cargo:rustc-link-search=native={}", lib_dir.display());
    }

    fn common_paths(arch: &str) -> Vec<PathBuf> {
        let mut paths = vec![
            PathBuf::from(format!("C:\\Npcap SDK\\Lib\\{arch}")),
            PathBuf::from(format!("C:\\npcap-sdk\\Lib\\{arch}")),
        ];
        if let Ok(home) = std::env::var("USERPROFILE") {
            let home = PathBuf::from(home);
            paths.push(home.join("npcap-sdk").join("Lib").join(arch));
            paths.push(
                home.join("Downloads")
                    .join("npcap-sdk")
                    .join("Lib")
                    .join(arch),
            );
        }
        paths
    }
}

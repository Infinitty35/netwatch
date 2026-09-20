//! Packaging metadata that has to stay in step with the crate.
//!
//! The RPM spec carries its own `Version:`, because COPR builds it straight
//! from the repository rather than from Cargo.toml. A spec left behind at the
//! previous version builds the *old* tag's source under the new version's
//! name, which is the kind of packaging bug nobody notices until a user
//! reports a feature missing from a release that supposedly has it.

const SPEC: &str = include_str!("../packaging/rpm/netwatch.spec");

#[test]
fn spec_version_matches_the_crate() {
    let spec_version = SPEC
        .lines()
        .find_map(|l| l.strip_prefix("Version:"))
        .map(str::trim)
        .expect("the spec declares a Version");
    assert_eq!(
        spec_version,
        env!("CARGO_PKG_VERSION"),
        "packaging/rpm/netwatch.spec is at {spec_version}, the crate is at {} — \
         bump the spec (and add a %changelog entry) in the release commit",
        env!("CARGO_PKG_VERSION")
    );
}

/// Everything the spec installs must be something the repository ships. A
/// typo'd path fails the COPR build long after the release has gone out.
#[test]
fn spec_installs_only_files_that_exist() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    for (source, _) in [
        ("docs/netwatch.1", ()),
        ("completions/netwatch.bash", ()),
        ("completions/_netwatch", ()),
        ("completions/netwatch.fish", ()),
        ("packaging/systemd/netwatch.service", ()),
        ("LICENSE", ()),
        ("README.md", ()),
        ("CHANGELOG.md", ()),
    ] {
        assert!(
            root.join(source).exists(),
            "the spec installs {source}, which is not in the repository"
        );
    }
}

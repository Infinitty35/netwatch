//! The release guard: what `.github/workflows/release.yml` checks before it
//! builds anything, and `scripts/release.sh`, which makes a commit and tag
//! that pass those checks.
//!
//! 0.32.2 and 0.32.3 were published from commits whose CI was red, and a
//! hand edit produced a stray v0.33.0 release commit. The workflow now
//! refuses a tag on a red commit or one that disagrees with Cargo.toml, and
//! the script replaces the hand edit. These tests keep both honest.

const RELEASE_WORKFLOW: &str = include_str!("../.github/workflows/release.yml");
const CHANGELOG: &str = include_str!("../CHANGELOG.md");

/// The jobs in a workflow, each with its lines. Reads this repository's
/// layout (job names at two spaces, their keys at four); not a YAML parser.
fn jobs(workflow: &str) -> Vec<(&str, Vec<&str>)> {
    let mut jobs: Vec<(&str, Vec<&str>)> = Vec::new();
    let mut in_jobs = false;
    for line in workflow.lines() {
        if !line.is_empty() && !line.starts_with([' ', '#']) {
            in_jobs = line == "jobs:";
            continue;
        }
        if !in_jobs {
            continue;
        }
        match line.strip_prefix("  ").and_then(|l| l.strip_suffix(':')) {
            Some(name) if !name.starts_with([' ', '#']) => jobs.push((name, Vec::new())),
            _ => {
                if let Some((_, body)) = jobs.last_mut() {
                    body.push(line);
                }
            }
        }
    }
    jobs
}

/// The jobs a job's `needs:` names, in either the scalar or the `[a, b]` form.
fn needs<'a>(body: &[&'a str]) -> Vec<&'a str> {
    body.iter()
        .filter_map(|l| l.strip_prefix("    needs:"))
        .flat_map(|n| {
            n.trim()
                .trim_start_matches('[')
                .trim_end_matches(']')
                .split(',')
        })
        .map(str::trim)
        .filter(|n| !n.is_empty())
        .collect()
}

#[test]
fn every_release_job_waits_for_the_guard() {
    let jobs = jobs(RELEASE_WORKFLOW);
    let needs_of = |job: &str| {
        jobs.iter()
            .find(|(name, _)| *name == job)
            .map(|(_, body)| needs(body))
            .unwrap_or_default()
    };
    assert!(
        jobs.iter().any(|(name, _)| *name == "guard"),
        "release.yml has no guard job"
    );
    assert!(jobs.len() > 1, "found no jobs besides the guard: {jobs:?}");
    for (job, _) in jobs.iter().filter(|(name, _)| *name != "guard") {
        let mut seen = vec![*job];
        let mut pending = needs_of(job);
        let mut guarded = false;
        while let Some(next) = pending.pop() {
            if next == "guard" {
                guarded = true;
                break;
            }
            if !seen.contains(&next) {
                seen.push(next);
                pending.extend(needs_of(next));
            }
        }
        assert!(
            guarded,
            "release.yml's `{job}` job does not need `guard`, directly or through another \
             job, so it would run on a tag whose commit CI never passed"
        );
    }
}

/// The workflow's top-level permissions leave `actions` at none, which would
/// make `gh run list` fail rather than report CI's runs.
#[test]
fn the_guard_can_read_ci_runs() {
    let jobs = jobs(RELEASE_WORKFLOW);
    let (_, guard) = jobs
        .iter()
        .find(|(name, _)| *name == "guard")
        .expect("release.yml has a guard job");
    assert!(
        guard.iter().any(|l| l.trim() == "actions: read"),
        "the guard job needs `actions: read` to list CI's runs"
    );
    assert!(guard.iter().any(|l| l.contains("--workflow ci.yml")));
    assert!(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join(".github/workflows/ci.yml")
            .exists(),
        "the guard waits on ci.yml, which is not in the repository"
    );
}

/// The guard's second check, made here so a version bump without its
/// CHANGELOG section fails before anything is tagged.
#[test]
fn changelog_has_a_section_for_the_crate_version() {
    let heading = format!("## [{}]", env!("CARGO_PKG_VERSION"));
    assert!(
        CHANGELOG.lines().any(|l| l.starts_with(&heading)),
        "CHANGELOG.md has no `{heading}` section; the release workflow refuses a tag without one"
    );
}

/// scripts/release.sh, run in a throwaway repository. Unix only, like the
/// script: Windows has no bash to rely on.
#[cfg(unix)]
mod script {
    use std::{fs, path::PathBuf, process::Command};

    /// A throwaway repository shaped like this one, as far as scripts/release.sh
    /// can tell: a crate named netwatch-tui at 0.32.3 with no dependencies, so
    /// the script's own `cargo test` takes a second and needs no network.
    struct Fixture(PathBuf);

    impl Fixture {
        /// None without git or bash, as in a distribution's build sandbox.
        fn new() -> Option<Self> {
            for tool in ["git", "bash"] {
                if Command::new(tool).arg("--version").output().is_err() {
                    eprintln!("skipping: no {tool} to run scripts/release.sh with");
                    return None;
                }
            }
            let root =
                std::env::temp_dir().join(format!("netwatch-release-{}", uuid::Uuid::new_v4()));
            let repo = root.join("repo");
            fs::create_dir_all(repo.join("src")).unwrap();
            fs::create_dir_all(repo.join("scripts")).unwrap();
            fs::create_dir_all(repo.join("packaging/rpm")).unwrap();
            fs::write(
                repo.join("Cargo.toml"),
                "[package]\nname = \"netwatch-tui\"\nversion = \"0.32.3\"\nedition = \"2021\"\n\n\
                 [dependencies]\n",
            )
            .unwrap();
            fs::write(repo.join("src/lib.rs"), "").unwrap();
            fs::write(repo.join(".gitignore"), "/target\n").unwrap();
            fs::write(
                repo.join("CHANGELOG.md"),
                "# Changelog\n\n## [Unreleased]\n\n### Fixed\n- Something.\n\n\
                 ## [0.32.3] - 2026-09-20\n\n### Fixed\n- Something earlier.\n",
            )
            .unwrap();
            fs::write(
                repo.join("packaging/rpm/netwatch.spec"),
                "Name:           netwatch\nVersion:        0.32.3\nRelease:        1%{?dist}\n\n\
                 %changelog\n* Sun Sep 20 2026 Someone <someone@example.com> - 0.32.3-1\n- Earlier\n",
            )
            .unwrap();
            fs::copy(
                PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("scripts/release.sh"),
                repo.join("scripts/release.sh"),
            )
            .unwrap();
            let fixture = Self(root);
            let lock = fixture.cargo().arg("generate-lockfile").output().unwrap();
            assert!(
                lock.status.success(),
                "{}",
                String::from_utf8_lossy(&lock.stderr)
            );
            fixture.git(&["init", "-q", "-b", "main"]);
            fixture.git(&["config", "user.name", "Release Test"]);
            fixture.git(&["config", "user.email", "release-test@example.com"]);
            fixture.git(&["add", "-A"]);
            fixture.git(&["commit", "-q", "-m", "initial"]);
            Some(fixture)
        }

        fn repo(&self) -> PathBuf {
            self.0.join("repo")
        }

        /// Isolated from the user's git configuration, which may sign commits
        /// and tags or install hooks, and from `GIT_DIR` and the rest: under a
        /// git hook, `cargo test` inherits them, and they would point these
        /// commands at the real repository.
        fn command(&self, program: &str) -> Command {
            let mut cmd = Command::new(program);
            for (key, _) in std::env::vars_os() {
                if key.to_string_lossy().starts_with("GIT_") {
                    cmd.env_remove(key);
                }
            }
            cmd.current_dir(self.repo())
                .env("GIT_CONFIG_GLOBAL", "/dev/null")
                .env("GIT_CONFIG_NOSYSTEM", "1")
                .env("CARGO_TARGET_DIR", self.0.join("target"));
            cmd
        }

        fn cargo(&self) -> Command {
            self.command("cargo")
        }

        fn git(&self, args: &[&str]) -> String {
            let out = self.command("git").args(args).output().unwrap();
            assert!(
                out.status.success(),
                "git {args:?}: {}",
                String::from_utf8_lossy(&out.stderr)
            );
            String::from_utf8(out.stdout).unwrap()
        }

        fn release(&self, args: &[&str]) -> std::process::Output {
            self.command("bash")
                .arg("scripts/release.sh")
                .args(args)
                .output()
                .unwrap()
        }

        /// Gives the repository an `origin` one commit ahead of local `main`,
        /// with `main` tracking it.
        fn behind_origin(&self) {
            self.git(&["clone", "-q", "--bare", ".", "../origin.git"]);
            self.git(&["remote", "add", "origin", "../origin.git"]);
            self.git(&["commit", "-q", "--allow-empty", "-m", "on the remote"]);
            self.git(&["push", "-q", "-u", "origin", "main"]);
            self.git(&["reset", "-q", "--hard", "HEAD~1"]);
        }

        fn read(&self, path: &str) -> String {
            fs::read_to_string(self.repo().join(path)).unwrap()
        }

        /// Runs the script, expects a refusal naming `reason`, and checks that it
        /// left no commit, no tag and no edit behind.
        fn refuses(&self, args: &[&str], reason: &str) {
            let head = self.git(&["rev-parse", "HEAD"]);
            let status = self.git(&["status", "--porcelain"]);
            let out = self.release(args);
            let stderr = String::from_utf8_lossy(&out.stderr);
            assert!(
                !out.status.success(),
                "release.sh {args:?} should have refused"
            );
            assert!(
                stderr.contains(reason),
                "release.sh {args:?}: expected {reason:?} in {stderr}"
            );
            assert_eq!(self.git(&["rev-parse", "HEAD"]), head);
            assert_eq!(self.git(&["tag", "--list"]), "");
            assert_eq!(self.git(&["status", "--porcelain"]), status);
        }
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn release_script_bumps_every_version_commits_and_tags() {
        let Some(fixture) = Fixture::new() else {
            return;
        };
        let out = fixture.release(&["0.32.4", "the security hotfix"]);
        assert!(
            out.status.success(),
            "{}\n{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );

        assert!(fixture
            .read("Cargo.toml")
            .contains("\nversion = \"0.32.4\"\n"));
        assert!(fixture
            .read("Cargo.lock")
            .contains("name = \"netwatch-tui\"\nversion = \"0.32.4\"\n"));

        let spec = fixture.read("packaging/rpm/netwatch.spec");
        assert!(spec.contains("\nVersion:        0.32.4\n"), "{spec}");
        let entry = spec.split("%changelog\n").nth(1).unwrap();
        let mut entry = entry.lines();
        let header = entry.next().unwrap();
        assert!(
            header.starts_with("* ")
                && header.ends_with("Release Test <release-test@example.com> - 0.32.4-1"),
            "{header}"
        );
        assert_eq!(entry.next(), Some("- the security hotfix"));
        assert_eq!(entry.next(), Some(""));
        assert!(spec.contains("- 0.32.3-1\n- Earlier\n"), "{spec}");

        let changelog = fixture.read("CHANGELOG.md");
        assert!(!changelog.contains("[Unreleased]"), "{changelog}");
        let date = changelog
            .lines()
            .find_map(|l| l.strip_prefix("## [0.32.4] - "))
            .expect("the Unreleased section became 0.32.4's");
        assert_eq!(date.len(), "YYYY-MM-DD".len(), "{date}");
        assert!(
            changelog.contains("\n## [0.32.3] - 2026-09-20\n"),
            "{changelog}"
        );

        assert_eq!(
            fixture.git(&["log", "-1", "--format=%s"]).trim(),
            "release: netwatch v0.32.4 — the security hotfix"
        );
        assert_eq!(
            fixture.git(&["rev-parse", "v0.32.4^{commit}"]),
            fixture.git(&["rev-parse", "HEAD"])
        );
        assert_eq!(fixture.git(&["cat-file", "-t", "v0.32.4"]).trim(), "tag");
        assert_eq!(fixture.git(&["status", "--porcelain"]), "");
        let stdout = String::from_utf8_lossy(&out.stdout);
        assert!(
            stdout.contains("git push --atomic origin main v0.32.4"),
            "{stdout}"
        );
    }

    #[test]
    fn release_script_refuses_a_dirty_tree() {
        let Some(fixture) = Fixture::new() else {
            return;
        };
        fs::write(fixture.repo().join("src/lib.rs"), "// unfinished\n").unwrap();
        fixture.refuses(&["0.32.4", "summary"], "not clean");
        fs::write(fixture.repo().join("src/lib.rs"), "").unwrap();
        fs::write(fixture.repo().join("stray.txt"), "").unwrap();
        fixture.refuses(&["0.32.4", "summary"], "not clean");
    }

    #[test]
    fn release_script_refuses_a_branch_that_does_not_match() {
        let Some(fixture) = Fixture::new() else {
            return;
        };
        fixture.git(&["checkout", "-q", "-b", "diagnose-enhancements"]);
        fixture.refuses(&["0.32.4", "summary"], "on diagnose-enhancements");
        fixture.git(&["checkout", "-q", "-b", "release/0.32.5"]);
        fixture.refuses(&["0.32.4", "summary"], "on release/0.32.5");
        fixture.git(&["checkout", "-q", "--detach"]);
        fixture.refuses(&["0.32.4", "summary"], "detached");
    }

    #[test]
    fn release_script_refuses_a_version_that_does_not_follow() {
        let Some(fixture) = Fixture::new() else {
            return;
        };
        fixture.refuses(&["v0.32.4", "summary"], "is not X.Y.Z");
        fixture.refuses(&["0.33", "summary"], "is not X.Y.Z");
        fixture.refuses(&["0.32.3", "summary"], "is not above the current version");
        fixture.refuses(&["0.31.9", "summary"], "is not above the current version");
        fixture.refuses(&["0.32.4"], "usage");
    }

    #[test]
    fn release_script_refuses_an_existing_tag_or_missing_notes() {
        let Some(fixture) = Fixture::new() else {
            return;
        };
        fixture.git(&["tag", "v0.32.4"]);
        let head = fixture.git(&["rev-parse", "HEAD"]);
        let out = fixture.release(&["0.32.4", "summary"]);
        assert!(!out.status.success());
        assert!(String::from_utf8_lossy(&out.stderr).contains("v0.32.4 already exists"));
        assert_eq!(fixture.git(&["rev-parse", "HEAD"]), head);
        fixture.git(&["tag", "-d", "v0.32.4"]);

        let empty = fixture
            .read("CHANGELOG.md")
            .replace("### Fixed\n- Something.\n\n## [0.32.3]", "## [0.32.3]");
        fs::write(fixture.repo().join("CHANGELOG.md"), empty).unwrap();
        fixture.git(&["commit", "-q", "-am", "empty notes"]);
        fixture.refuses(&["0.32.4", "summary"], "[Unreleased]");

        let none = fixture
            .read("CHANGELOG.md")
            .replace("## [Unreleased]\n\n", "");
        fs::write(fixture.repo().join("CHANGELOG.md"), none).unwrap();
        fixture.git(&["commit", "-q", "-am", "no notes"]);
        fixture.refuses(&["0.32.4", "summary"], "[Unreleased]");
    }

    #[test]
    fn release_script_refuses_a_branch_behind_its_remote() {
        let Some(fixture) = Fixture::new() else {
            return;
        };
        fixture.behind_origin();
        fixture.refuses(&["0.32.4", "summary"], "1 commit(s) behind origin/main");
    }

    /// This hotfix's own layout: release/0.32.4 tracks origin/main, which is
    /// allowed to be ahead of it. CI does not run on the branch by itself, so
    /// the printed commands ask for it.
    #[test]
    fn release_script_on_a_release_branch_asks_for_ci() {
        let Some(fixture) = Fixture::new() else {
            return;
        };
        fixture.behind_origin();
        fixture.git(&["checkout", "-q", "-b", "release/0.32.4"]);
        fixture.git(&["branch", "-q", "-u", "origin/main"]);
        let out = fixture.release(&["0.32.4", "the security hotfix"]);
        let stdout = String::from_utf8_lossy(&out.stdout);
        assert!(
            out.status.success(),
            "{stdout}\n{}",
            String::from_utf8_lossy(&out.stderr)
        );
        assert!(
            stdout.contains("gh workflow run ci.yml --ref release/0.32.4"),
            "{stdout}"
        );
        assert!(stdout.contains("git push origin v0.32.4"), "{stdout}");
    }
}

//! Applying and un-applying remediations.
//!
//! ## Why there is a journal
//!
//! "netwatch writes resolv.conf, keeps a backup, and reverts on quit" is only
//! true if netwatch gets to quit. `SIGKILL`, a panic in the render loop, an
//! OOM kill, or a laptop losing power all leave the host's resolver pointing
//! wherever netwatch put it, with a backup file nobody will ever restore. A
//! diagnostic tool that can silently and permanently reconfigure DNS is worse
//! than one that never offered to.
//!
//! So the order is: **journal first, mutate second.** Before touching a file,
//! [`Journal::apply_file_edit`] writes an entry naming the target, the backup, and the
//! value we are about to install. On startup [`Journal::reconcile`] reads that
//! file back, and anything still open belongs to a process that did not exit
//! cleanly — it is reverted before the UI is drawn, and reported.
//!
//! The revert is conservative: if the target's current contents no longer
//! match what netwatch installed, something else has edited it since, and the
//! entry is abandoned (backup kept, loudly reported) rather than stomping a
//! third party's change.

use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

use super::issue::{Action, Applied};

/// Where a journal entry is in its lifecycle.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EntryState {
    /// Journalled but the write hadn't been confirmed. Treated as open —
    /// reconciliation checks the file and reverts only if we really wrote it.
    Pending,
    /// Change is live on the host.
    Applied,
    /// Change has been undone; kept in the file as history.
    Reverted,
    /// Could not be undone safely. The backup path is preserved for a human.
    Abandoned,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct JournalEntry {
    pub id: String,
    /// Issue this remediation belongs to, for the report.
    pub issue_id: String,
    pub action: Action,
    /// File the change lands in, when it's a file edit.
    pub target: Option<PathBuf>,
    /// Copy of `target` as it was before the change.
    pub backup: Option<PathBuf>,
    /// Exactly what we wrote, so reconciliation can tell "still ours" from
    /// "someone else has edited this since".
    pub installed: Option<String>,
    pub state: EntryState,
    pub applied_at: String,
    /// PID that made the change. An entry from a live process is not stale.
    pub pid: u32,
    /// True once the user asked for the change to outlive the session. A
    /// permanent entry is never reverted on quit or by reconciliation.
    #[serde(default)]
    pub permanent: bool,
}

/// Outcome of a reconciliation pass, surfaced at startup.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Reconciliation {
    /// Entries put back the way they were.
    pub reverted: Vec<String>,
    /// Entries left alone because the file changed underneath us. Each string
    /// is a human-readable explanation including the backup path.
    pub abandoned: Vec<String>,
}

impl Reconciliation {
    pub fn is_empty(&self) -> bool {
        self.reverted.is_empty() && self.abandoned.is_empty()
    }

    /// One line for the startup toast, or `None` when nothing needed doing.
    pub fn summary(&self) -> Option<String> {
        if self.is_empty() {
            return None;
        }
        let mut parts = Vec::new();
        if !self.reverted.is_empty() {
            parts.push(format!(
                "reverted {} change{} left by a previous run",
                self.reverted.len(),
                if self.reverted.len() == 1 { "" } else { "s" }
            ));
        }
        if !self.abandoned.is_empty() {
            parts.push(format!(
                "{} could not be reverted safely — see the backups",
                self.abandoned.len()
            ));
        }
        Some(parts.join("; "))
    }
}

/// Filesystem operations the journal needs. A trait so the whole
/// apply/crash/reconcile cycle can be tested without touching `/etc`.
pub trait Host {
    fn read(&self, path: &Path) -> std::io::Result<String>;
    fn write(&mut self, path: &Path, contents: &str) -> std::io::Result<()>;
    fn exists(&self, path: &Path) -> bool;
    /// Whether a process is still running. Entries owned by a live process are
    /// not stale, so two netwatch instances don't revert each other's work.
    fn process_alive(&self, pid: u32) -> bool;
    fn now(&self) -> String;
    fn pid(&self) -> u32;
}

/// Real filesystem.
pub struct RealHost;

impl Host for RealHost {
    fn read(&self, path: &Path) -> std::io::Result<String> {
        std::fs::read_to_string(path)
    }

    fn write(&mut self, path: &Path, contents: &str) -> std::io::Result<()> {
        if let Some(dir) = path.parent() {
            std::fs::create_dir_all(dir)?;
        }
        std::fs::write(path, contents)
    }

    fn exists(&self, path: &Path) -> bool {
        path.exists()
    }

    fn process_alive(&self, pid: u32) -> bool {
        #[cfg(unix)]
        {
            Path::new(&format!("/proc/{pid}")).exists()
        }
        #[cfg(not(unix))]
        {
            let _ = pid;
            false
        }
    }

    fn now(&self) -> String {
        chrono::Local::now().format("%Y-%m-%d %H:%M:%S").to_string()
    }

    fn pid(&self) -> u32 {
        std::process::id()
    }
}

pub struct Journal {
    path: PathBuf,
    entries: Vec<JournalEntry>,
    /// A failed load or persistence operation blocks subsequent writes.
    blocked: Option<String>,
}

impl Journal {
    pub fn new(path: PathBuf) -> Self {
        Self {
            path,
            entries: Vec::new(),
            blocked: None,
        }
    }

    pub fn default_path() -> PathBuf {
        dirs::cache_dir()
            .unwrap_or_else(|| PathBuf::from("."))
            .join("netwatch")
            .join("applied.json")
    }

    pub fn entries(&self) -> &[JournalEntry] {
        &self.entries
    }

    pub fn open_entries(&self) -> impl Iterator<Item = &JournalEntry> {
        self.entries
            .iter()
            .filter(|e| matches!(e.state, EntryState::Pending | EntryState::Applied))
    }

    pub fn load<H: Host>(path: PathBuf, host: &H) -> Self {
        let mut journal = Self::new(path);
        match host.read(&journal.path) {
            Ok(text) => match serde_json::from_str::<Vec<JournalEntry>>(&text) {
                Ok(entries) => journal.entries = entries,
                Err(e) => journal.blocked = Some(format!(
                    "invalid or unsupported journal {}: {e}; original preserved; host changes blocked",
                    journal.path.display()
                )),
            },
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => journal.blocked = Some(format!(
                "cannot read journal {}: {e}; host changes blocked", journal.path.display()
            )),
        }
        journal
    }

    pub fn blocked_reason(&self) -> Option<&str> {
        self.blocked.as_deref()
    }

    fn ensure_writable(&self) -> std::io::Result<()> {
        match &self.blocked {
            Some(reason) => Err(std::io::Error::other(reason.clone())),
            None => Ok(()),
        }
    }

    fn flush<H: Host>(&mut self, host: &mut H) -> std::io::Result<()> {
        self.ensure_writable()?;
        let text = serde_json::to_string_pretty(&self.entries)?;
        if let Err(e) = host.write(&self.path, &text) {
            self.blocked = Some(format!(
                "cannot persist journal {}: {e}; recovery review required; further host changes blocked",
                self.path.display()
            ));
            return Err(e);
        }
        Ok(())
    }

    /// Apply a file-edit remediation: journal the intent, back the file up,
    /// then write. Errors are returned only before the target write is attempted.
    /// Any subsequent failure is recorded as recovery-required, even if a
    /// failed write may have left only part of the intended contents.
    ///
    /// Returns the [`Applied`] record to attach to the [`Step`], carrying the
    /// before/after values the report prints.
    ///
    /// [`Step`]: super::issue::Step
    pub fn apply_file_edit<H: Host>(
        &mut self,
        host: &mut H,
        issue_id: &str,
        action: Action,
        target: &Path,
        new_contents: &str,
        summarise: impl Fn(&str) -> String,
    ) -> std::io::Result<Applied> {
        self.ensure_writable()?;
        if self
            .entries
            .iter()
            .any(|e| e.target.as_deref() == Some(target) && e.state != EntryState::Reverted)
        {
            return Err(std::io::Error::other(
                "target has an existing change; review recovery before applying again",
            ));
        }
        let before = host.read(target)?;
        let backup = backup_path(target, host.pid());

        // 1. Journal the intent *first*. A crash between here and the write
        //    leaves a Pending entry, and reconciliation can check whether the
        //    write actually landed.
        let entry = JournalEntry {
            id: format!("{}-{}", issue_id, self.entries.len() + 1),
            issue_id: issue_id.to_string(),
            action,
            target: Some(target.to_path_buf()),
            backup: Some(backup.clone()),
            installed: Some(new_contents.to_string()),
            state: EntryState::Pending,
            applied_at: host.now(),
            pid: host.pid(),
            permanent: false,
        };
        let idx = self.entries.len();
        self.entries.push(entry);
        self.flush(host)?;

        // 2. Back up, then write.
        host.write(&backup, &before)?;
        if let Err(e) = host.write(target, new_contents) {
            return Ok(self.recovery_required(idx, "target write", &e));
        }

        // 3. Confirm.
        self.entries[idx].state = EntryState::Applied;
        if let Err(e) = self.flush(host) {
            return Ok(self.recovery_required(idx, "completion journal write", &e));
        }

        Ok(Applied::Yes {
            at: self.entries[idx].applied_at.clone(),
            before: summarise(&before),
            after: summarise(new_contents),
        })
    }

    fn recovery_required(&self, idx: usize, stage: &str, error: &std::io::Error) -> Applied {
        let entry = &self.entries[idx];
        Applied::RecoveryRequired {
            operation_id: entry.id.clone(),
            reason: format!("{stage} failed: {error}; target may have changed"),
            backup: entry
                .backup
                .as_ref()
                .map(|p| p.display().to_string())
                .unwrap_or_default(),
        }
    }

    /// Mark an issue's changes permanent — they survive quit and are never
    /// reconciled away.
    pub fn make_permanent<H: Host>(&mut self, host: &mut H, issue_id: &str) -> std::io::Result<()> {
        self.ensure_writable()?;
        let previous = self.entries.clone();
        for e in self.entries.iter_mut() {
            if e.issue_id == issue_id && e.state == EntryState::Applied {
                e.permanent = true;
            }
        }
        if let Err(e) = self.flush(host) {
            self.entries = previous;
            return Err(e);
        }
        Ok(())
    }

    /// Put one entry back. Refuses when the target no longer contains what we
    /// installed — that means something else edited it, and clobbering that
    /// would be worse than leaving our change in place.
    fn revert_entry<H: Host>(&mut self, host: &mut H, idx: usize) -> Result<(), String> {
        let entry = self.entries[idx].clone();
        let (Some(target), Some(backup)) = (entry.target.clone(), entry.backup.clone()) else {
            self.entries[idx].state = EntryState::Reverted;
            return Ok(());
        };

        let current = host.read(&target).map_err(|e| {
            format!(
                "could not read {}: {e}; recovery required; backup: {}",
                target.display(),
                backup.display()
            )
        })?;
        if let Some(installed) = &entry.installed {
            if entry.state == EntryState::Applied && &current != installed {
                let msg = format!(
                    "{} was edited after netwatch changed it — left as found; \
                     netwatch's backup of the original is at {}",
                    target.display(),
                    backup.display()
                );
                self.entries[idx].state = EntryState::Abandoned;
                return Err(msg);
            }
            // Pending entries whose write never landed need no revert.
            if entry.state == EntryState::Pending && &current != installed {
                // A differing target may be a partial write. Only a
                // readable backup matching the current file proves no
                // restoration is needed.
                if host.read(&backup).is_ok_and(|original| original == current) {
                    self.entries[idx].state = EntryState::Reverted;
                    return Ok(());
                }
                return Err(format!(
                    "unconfirmed write to {}; recovery required; backup: {}",
                    target.display(),
                    backup.display()
                ));
            }
        }

        if !host.exists(&backup) {
            let msg = format!(
                "no backup found at {} — {} left as netwatch set it",
                backup.display(),
                target.display()
            );
            self.entries[idx].state = EntryState::Abandoned;
            return Err(msg);
        }

        let original = host
            .read(&backup)
            .map_err(|e| format!("could not read backup {}: {e}", backup.display()))?;
        host.write(&target, &original)
            .map_err(|e| format!("could not restore {}: {e}", target.display()))?;
        self.entries[idx].state = EntryState::Reverted;
        Ok(())
    }

    /// Revert everything this process applied and isn't permanent. Called on
    /// clean shutdown.
    pub fn revert_session<H: Host>(&mut self, host: &mut H) -> Reconciliation {
        let me = host.pid();
        self.revert_matching(host, |e| e.pid == me && !e.permanent)
    }

    /// Startup pass. Reverts changes left behind by a netwatch that died
    /// without cleaning up — identified by an open entry whose owning process
    /// is gone. Entries belonging to a *live* process are another instance's
    /// business and are left alone.
    pub fn reconcile<H: Host>(&mut self, host: &mut H) -> Reconciliation {
        let me = host.pid();
        let dead: Vec<u32> = self
            .entries
            .iter()
            .map(|e| e.pid)
            .filter(|p| *p != me && !host.process_alive(*p))
            .collect();
        self.revert_matching(host, |e| !e.permanent && dead.contains(&e.pid))
    }

    fn revert_matching<H: Host>(
        &mut self,
        host: &mut H,
        pred: impl Fn(&JournalEntry) -> bool,
    ) -> Reconciliation {
        let mut out = Reconciliation::default();
        if let Some(reason) = &self.blocked {
            out.abandoned.push(reason.clone());
            return out;
        }
        let targets: Vec<usize> = self
            .entries
            .iter()
            .enumerate()
            .filter(|(_, e)| matches!(e.state, EntryState::Pending | EntryState::Applied))
            .filter(|(_, e)| pred(e))
            .map(|(i, _)| i)
            .collect();

        let changed = !targets.is_empty();
        for idx in targets {
            let desc = describe(&self.entries[idx]);
            match self.revert_entry(host, idx) {
                Ok(()) => out.reverted.push(desc),
                Err(msg) => out.abandoned.push(msg),
            }
        }
        if changed {
            if let Err(e) = self.flush(host) {
                out.abandoned.push(format!(
                    "recovery completion could not be recorded: {e}; journal: {}",
                    self.path.display()
                ));
            }
        }
        out
    }
}

fn describe(e: &JournalEntry) -> String {
    match (&e.action, &e.target) {
        (Action::SetResolver { addr }, Some(t)) => {
            format!("resolver {addr} in {}", t.display())
        }
        (_, Some(t)) => t.display().to_string(),
        _ => e.id.clone(),
    }
}

/// `/etc/resolv.conf` → `/etc/resolv.conf.netwatch-<pid>.bak`, kept next to
/// the original so a human looking at the directory finds it immediately.
fn backup_path(target: &Path, pid: u32) -> PathBuf {
    let mut name = target.file_name().unwrap_or_default().to_os_string();
    name.push(format!(".netwatch-{pid}.bak"));
    target.with_file_name(name)
}

/// Build the resolv.conf text that switching to `addr` produces: replace the
/// first `nameserver` line, leave every other directive (search, options,
/// comments) untouched.
pub fn resolv_conf_with(original: &str, addr: &str) -> String {
    let mut out = String::new();
    let mut replaced = false;
    for line in original.lines() {
        if !replaced && line.trim_start().starts_with("nameserver") {
            out.push_str(&format!("nameserver {addr}\n"));
            replaced = true;
        } else {
            out.push_str(line);
            out.push('\n');
        }
    }
    if !replaced {
        out.push_str(&format!("nameserver {addr}\n"));
    }
    out
}

/// First `nameserver` in a resolv.conf, for before/after reporting.
pub fn first_nameserver(text: &str) -> String {
    text.lines()
        .find_map(|l| {
            let l = l.trim();
            l.strip_prefix("nameserver").map(|r| r.trim().to_string())
        })
        .unwrap_or_else(|| "none".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::{HashMap, HashSet};

    /// In-memory host. `alive` lets a test simulate "the process that made
    /// this change is gone", which is the whole point of reconciliation.
    #[derive(Default)]
    struct FakeHost {
        files: HashMap<PathBuf, String>,
        alive: HashSet<u32>,
        pid: u32,
        clock: u32,
        writes: usize,
        fail_write: Option<usize>,
        partial_write: bool,
        unreadable: HashSet<PathBuf>,
    }

    impl FakeHost {
        fn new(pid: u32) -> Self {
            Self {
                pid,
                alive: HashSet::from([pid]),
                ..Default::default()
            }
        }
    }

    impl Host for FakeHost {
        fn read(&self, path: &Path) -> std::io::Result<String> {
            if self.unreadable.contains(path) {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::PermissionDenied,
                    "read denied",
                ));
            }
            self.files
                .get(path)
                .cloned()
                .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::NotFound, "no file"))
        }
        fn write(&mut self, path: &Path, contents: &str) -> std::io::Result<()> {
            self.writes += 1;
            if self.fail_write == Some(self.writes) {
                if self.partial_write {
                    self.files
                        .insert(path.to_path_buf(), contents.chars().take(7).collect());
                }
                return Err(std::io::Error::other("injected write failure"));
            }
            self.files.insert(path.to_path_buf(), contents.to_string());
            Ok(())
        }
        fn exists(&self, path: &Path) -> bool {
            self.files.contains_key(path)
        }
        fn process_alive(&self, pid: u32) -> bool {
            self.alive.contains(&pid)
        }
        fn now(&self) -> String {
            format!("2026-09-03 06:5{}:00", self.clock % 10)
        }
        fn pid(&self) -> u32 {
            self.pid
        }
    }

    const RESOLV: &str = "# generated\nsearch lan\nnameserver 169.254.1.1\noptions edns0\n";
    const TARGET: &str = "/etc/resolv.conf";

    fn journal_path() -> PathBuf {
        PathBuf::from("/var/cache/netwatch/applied.json")
    }

    fn apply_resolver(host: &mut FakeHost, journal: &mut Journal, addr: &str) -> Applied {
        let target = PathBuf::from(TARGET);
        let current = host.read(&target).unwrap_or_default();
        let new = resolv_conf_with(&current, addr);
        journal
            .apply_file_edit(
                host,
                "2026-0903-01",
                Action::SetResolver { addr: addr.into() },
                &target,
                &new,
                first_nameserver,
            )
            .unwrap()
    }

    #[test]
    fn resolv_conf_rewrite_preserves_other_directives() {
        let out = resolv_conf_with(RESOLV, "192.168.8.1");
        assert!(out.contains("nameserver 192.168.8.1"));
        assert!(out.contains("search lan"), "search line must survive");
        assert!(out.contains("options edns0"), "options must survive");
        assert!(out.contains("# generated"), "comments must survive");
        assert!(!out.contains("169.254.1.1"));
    }

    #[test]
    fn resolv_conf_rewrite_adds_a_nameserver_when_there_is_none() {
        let out = resolv_conf_with("search lan\n", "1.1.1.1");
        assert!(out.contains("nameserver 1.1.1.1"));
        assert!(out.contains("search lan"));
    }

    #[test]
    fn apply_then_clean_quit_restores_the_original() {
        let mut host = FakeHost::new(100);
        host.write(Path::new(TARGET), RESOLV).unwrap();
        let mut journal = Journal::new(journal_path());

        let applied = apply_resolver(&mut host, &mut journal, "192.168.8.1");
        assert_eq!(
            applied,
            Applied::Yes {
                at: "2026-09-03 06:50:00".into(),
                before: "169.254.1.1".into(),
                after: "192.168.8.1".into()
            }
        );
        assert_eq!(
            first_nameserver(&host.read(Path::new(TARGET)).unwrap()),
            "192.168.8.1"
        );

        let r = journal.revert_session(&mut host);
        assert_eq!(r.reverted.len(), 1);
        assert_eq!(host.read(Path::new(TARGET)).unwrap(), RESOLV);
    }

    #[test]
    fn a_killed_netwatch_does_not_leave_the_resolver_rewritten() {
        // Run 1 applies the change and is then SIGKILLed: no revert_session,
        // and the journal on disk still says Applied.
        let mut host = FakeHost::new(100);
        host.write(Path::new(TARGET), RESOLV).unwrap();
        let mut journal = Journal::new(journal_path());
        apply_resolver(&mut host, &mut journal, "192.168.8.1");
        drop(journal);
        host.alive.remove(&100);

        // Run 2 starts up and reconciles before drawing anything.
        host.pid = 200;
        host.alive.insert(200);
        let mut journal2 = Journal::load(journal_path(), &host);
        let recon = journal2.reconcile(&mut host);

        assert_eq!(recon.reverted.len(), 1, "{recon:?}");
        assert!(recon.abandoned.is_empty());
        assert_eq!(
            host.read(Path::new(TARGET)).unwrap(),
            RESOLV,
            "the crashed run's resolver change must not outlive it"
        );
        assert!(recon.summary().unwrap().contains("reverted 1 change"));
    }

    #[test]
    fn a_crash_between_journal_and_write_leaves_nothing_to_revert() {
        // Simulate: entry journalled Pending, process died before writing.
        let mut host = FakeHost::new(100);
        host.write(Path::new(TARGET), RESOLV).unwrap();
        let mut journal = Journal::new(journal_path());
        journal.entries.push(JournalEntry {
            id: "x".into(),
            issue_id: "2026-0903-01".into(),
            action: Action::SetResolver {
                addr: "192.168.8.1".into(),
            },
            target: Some(PathBuf::from(TARGET)),
            backup: Some(PathBuf::from("/etc/resolv.conf.netwatch-100.bak")),
            installed: Some(resolv_conf_with(RESOLV, "192.168.8.1")),
            state: EntryState::Pending,
            applied_at: "2026-09-03 06:50:00".into(),
            pid: 100,
            permanent: false,
        });
        journal.flush(&mut host).unwrap();
        host.alive.remove(&100);

        host.pid = 200;
        host.alive.insert(200);
        let mut j2 = Journal::load(journal_path(), &host);
        let recon = j2.reconcile(&mut host);
        assert_eq!(
            recon.abandoned.len(),
            1,
            "missing backup needs review: {recon:?}"
        );
        assert_eq!(host.read(Path::new(TARGET)).unwrap(), RESOLV);
    }

    #[test]
    fn a_file_edited_by_someone_else_is_not_clobbered() {
        let mut host = FakeHost::new(100);
        host.write(Path::new(TARGET), RESOLV).unwrap();
        let mut journal = Journal::new(journal_path());
        apply_resolver(&mut host, &mut journal, "192.168.8.1");
        drop(journal);
        host.alive.remove(&100);

        // NetworkManager rewrites resolv.conf while netwatch is dead.
        host.write(Path::new(TARGET), "nameserver 10.0.0.1\n")
            .unwrap();

        host.pid = 200;
        host.alive.insert(200);
        let mut j2 = Journal::load(journal_path(), &host);
        let recon = j2.reconcile(&mut host);

        assert!(recon.reverted.is_empty());
        assert_eq!(recon.abandoned.len(), 1);
        assert!(recon.abandoned[0].contains("was edited after netwatch changed it"));
        assert_eq!(
            host.read(Path::new(TARGET)).unwrap(),
            "nameserver 10.0.0.1\n",
            "a third party's edit must survive reconciliation"
        );
        assert!(recon
            .summary()
            .unwrap()
            .contains("could not be reverted safely"));
    }

    #[test]
    fn a_permanent_change_survives_both_quit_and_reconciliation() {
        let mut host = FakeHost::new(100);
        host.write(Path::new(TARGET), RESOLV).unwrap();
        let mut journal = Journal::new(journal_path());
        apply_resolver(&mut host, &mut journal, "192.168.8.1");
        journal.make_permanent(&mut host, "2026-0903-01").unwrap();

        let r = journal.revert_session(&mut host);
        assert!(r.is_empty());
        assert_eq!(
            first_nameserver(&host.read(Path::new(TARGET)).unwrap()),
            "192.168.8.1"
        );

        host.alive.remove(&100);
        host.pid = 200;
        host.alive.insert(200);
        let mut j2 = Journal::load(journal_path(), &host);
        let recon = j2.reconcile(&mut host);
        assert!(recon.is_empty(), "{recon:?}");
        assert_eq!(
            first_nameserver(&host.read(Path::new(TARGET)).unwrap()),
            "192.168.8.1"
        );
    }

    #[test]
    fn another_live_instances_changes_are_left_alone() {
        let mut host = FakeHost::new(100);
        host.write(Path::new(TARGET), RESOLV).unwrap();
        let mut journal = Journal::new(journal_path());
        apply_resolver(&mut host, &mut journal, "192.168.8.1");

        // A second netwatch starts while the first is still running.
        host.pid = 200;
        host.alive.insert(200);
        let mut j2 = Journal::load(journal_path(), &host);
        let recon = j2.reconcile(&mut host);

        assert!(recon.is_empty(), "must not revert a live instance's change");
        assert_eq!(
            first_nameserver(&host.read(Path::new(TARGET)).unwrap()),
            "192.168.8.1"
        );
    }

    #[test]
    fn reconciliation_is_idempotent() {
        let mut host = FakeHost::new(100);
        host.write(Path::new(TARGET), RESOLV).unwrap();
        let mut journal = Journal::new(journal_path());
        apply_resolver(&mut host, &mut journal, "192.168.8.1");
        drop(journal);
        host.alive.remove(&100);
        host.pid = 200;
        host.alive.insert(200);

        let mut j2 = Journal::load(journal_path(), &host);
        assert_eq!(j2.reconcile(&mut host).reverted.len(), 1);

        let mut j3 = Journal::load(journal_path(), &host);
        assert!(
            j3.reconcile(&mut host).is_empty(),
            "second pass must be a no-op"
        );
        assert_eq!(host.read(Path::new(TARGET)).unwrap(), RESOLV);
    }

    fn try_apply(host: &mut FakeHost, journal: &mut Journal) -> std::io::Result<Applied> {
        journal.apply_file_edit(
            host,
            "fault-test",
            Action::SetResolver {
                addr: "1.1.1.1".into(),
            },
            Path::new(TARGET),
            &resolv_conf_with(RESOLV, "1.1.1.1"),
            first_nameserver,
        )
    }

    #[test]
    fn faults_before_target_write_do_not_change_target() {
        for stage in [1, 2] {
            let mut host = FakeHost::new(100);
            host.files.insert(TARGET.into(), RESOLV.into());
            host.fail_write = Some(stage);
            let mut journal = Journal::new(journal_path());
            assert!(try_apply(&mut host, &mut journal).is_err());
            assert_eq!(host.files[Path::new(TARGET)], RESOLV);
        }
    }

    #[test]
    fn target_write_and_completion_failures_record_recovery_required() {
        for stage in [3, 4] {
            for partial in [false, true] {
                let mut host = FakeHost::new(100);
                host.files.insert(TARGET.into(), RESOLV.into());
                host.fail_write = Some(stage);
                host.partial_write = partial;
                let mut journal = Journal::new(journal_path());
                let outcome = try_apply(&mut host, &mut journal).unwrap();
                let Applied::RecoveryRequired {
                    operation_id,
                    backup,
                    ..
                } = &outcome
                else {
                    panic!("expected recovery required: {outcome:?}");
                };
                assert_eq!(operation_id, "fault-test-1");
                assert_eq!(host.files[Path::new(backup)], RESOLV);
                assert!(outcome
                    .recovery_summary()
                    .unwrap()
                    .contains("recovery required"));
                if stage == 4 {
                    assert_eq!(
                        host.files[Path::new(TARGET)],
                        resolv_conf_with(RESOLV, "1.1.1.1")
                    );
                    assert!(journal.blocked_reason().is_some());
                }
                let writes = host.writes;
                assert!(try_apply(&mut host, &mut journal).is_err());
                assert_eq!(host.writes, writes, "retry must preserve the backup");
            }
        }
    }

    #[test]
    fn partial_pending_write_is_not_reported_as_reverted_after_restart() {
        let mut host = FakeHost::new(100);
        host.files.insert(TARGET.into(), RESOLV.into());
        host.fail_write = Some(3);
        host.partial_write = true;
        let mut journal = Journal::new(journal_path());
        try_apply(&mut host, &mut journal).unwrap();
        let partial = host.files[Path::new(TARGET)].clone();
        host.alive.remove(&100);
        host.pid = 200;
        let mut restarted = Journal::load(journal_path(), &host);
        let result = restarted.reconcile(&mut host);
        assert!(result.reverted.is_empty());
        assert_eq!(result.abandoned.len(), 1);
        assert_eq!(host.files[Path::new(TARGET)], partial);
        assert_eq!(restarted.entries()[0].state, EntryState::Pending);
    }

    #[test]
    fn pending_write_with_unchanged_target_and_backup_is_resolved() {
        let mut host = FakeHost::new(100);
        host.files.insert(TARGET.into(), RESOLV.into());
        host.fail_write = Some(3);
        let mut journal = Journal::new(journal_path());
        try_apply(&mut host, &mut journal).unwrap();
        let result = journal.revert_session(&mut host);
        assert_eq!(result.reverted.len(), 1);
        assert!(result.abandoned.is_empty());
        assert_eq!(host.files[Path::new(TARGET)], RESOLV);
    }

    #[test]
    fn invalid_and_unsupported_journals_are_preserved_by_every_write_path() {
        for original in ["[{truncated", r#"{"version":999,"entries":[]}"#] {
            let mut host = FakeHost::new(100);
            host.files.insert(journal_path(), original.into());
            host.files.insert(TARGET.into(), RESOLV.into());
            let mut journal = Journal::load(journal_path(), &host);
            assert!(journal.blocked_reason().is_some());
            assert!(try_apply(&mut host, &mut journal).is_err());
            assert!(journal.make_permanent(&mut host, "fault-test").is_err());
            assert!(!journal.reconcile(&mut host).abandoned.is_empty());
            assert!(!journal.revert_session(&mut host).abandoned.is_empty());
            assert_eq!(host.writes, 0);
            assert_eq!(host.files[&journal_path()], original);
        }
    }

    #[test]
    fn missing_journal_is_distinct_from_unreadable_journal() {
        let mut host = FakeHost::new(100);
        assert!(Journal::load(journal_path(), &host)
            .blocked_reason()
            .is_none());
        host.unreadable.insert(journal_path());
        let mut journal = Journal::load(journal_path(), &host);
        assert!(journal.blocked_reason().unwrap().contains("cannot read"));
        assert!(try_apply(&mut host, &mut journal).is_err());
        journal.revert_session(&mut host);
        assert_eq!(host.writes, 0);
    }

    #[test]
    fn missing_or_unreadable_target_is_never_replaced_with_empty_contents() {
        let mut host = FakeHost::new(100);
        let mut journal = Journal::new(journal_path());
        assert!(try_apply(&mut host, &mut journal).is_err());
        host.files.insert(TARGET.into(), RESOLV.into());
        host.unreadable.insert(TARGET.into());
        assert!(try_apply(&mut host, &mut journal).is_err());
        assert_eq!(host.writes, 0);
        assert!(journal.entries().is_empty());
    }

    #[test]
    fn unreadable_target_during_recovery_remains_unresolved() {
        let mut host = FakeHost::new(100);
        host.files.insert(TARGET.into(), RESOLV.into());
        let mut journal = Journal::new(journal_path());
        try_apply(&mut host, &mut journal).unwrap();
        host.unreadable.insert(TARGET.into());
        let result = journal.revert_session(&mut host);
        assert!(result.reverted.is_empty());
        assert_eq!(result.abandoned.len(), 1);
        assert_eq!(journal.entries()[0].state, EntryState::Applied);
    }

    #[test]
    fn recovery_flush_failure_is_visible_and_blocks_further_writes() {
        let mut host = FakeHost::new(100);
        host.files.insert(TARGET.into(), RESOLV.into());
        let mut journal = Journal::new(journal_path());
        try_apply(&mut host, &mut journal).unwrap();
        host.fail_write = Some(host.writes + 2); // restore succeeds; journal fails
        let result = journal.revert_session(&mut host);
        assert_eq!(host.files[Path::new(TARGET)], RESOLV);
        assert_eq!(result.reverted.len(), 1);
        assert_eq!(result.abandoned.len(), 1);
        assert!(journal.blocked_reason().is_some());
    }

    #[test]
    fn backup_path_sits_next_to_the_original() {
        let p = backup_path(Path::new("/etc/resolv.conf"), 4242);
        assert_eq!(p, PathBuf::from("/etc/resolv.conf.netwatch-4242.bak"));
    }
}

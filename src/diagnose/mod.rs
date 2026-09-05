//! Issue → probable cause → remediation → report.
//!
//! Everything in this module is deterministic and runs without an LLM. The
//! optional AI narrative adds a paragraph on top of these objects; it is never
//! a source of facts.
//!
//! ```text
//!   observations ──▶ detectors ──▶ Detection ──┐
//!   (dns, gateway,   (+ baselines,             │
//!    path, sockets,   thresholds)              ▼
//!    iface)                                 Engine ──▶ Vec<Issue>
//!                                              │           │
//!                                     suppression graph    ├─▶ Diagnose tab
//!                                     lifecycle/recurrence ├─▶ verdict line
//!                                                          ├─▶ timeline
//!                                                          └─▶ report.md/json
//! ```
//!
//! One `Vec<Issue>` feeds every surface, so the screen and the report cannot
//! disagree. See [`issue`] for why no rendered number is ever stored.

pub mod baseline;
pub mod demo;
pub mod detectors;
pub mod engine;
pub mod fixture;
pub mod issue;
pub mod live;
pub mod remediation;
pub mod report;
pub mod rules;

pub use engine::{Engine, Verdict};
pub use issue::{Issue, Severity};

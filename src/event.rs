use anyhow::Result;
use crossterm::event::{self, Event, KeyEvent, KeyEventKind, MouseEvent};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::mpsc;

pub enum AppEvent {
    Key(KeyEvent),
    Mouse(MouseEvent),
    Tick,
}

pub struct EventHandler {
    rx: mpsc::UnboundedReceiver<AppEvent>,
    /// Polling interval for the background thread, in milliseconds.
    /// Shared with the thread so settings changes apply within one
    /// poll cycle without requiring a restart.
    tick_rate_ms: Arc<AtomicU64>,
}

impl EventHandler {
    pub fn start(tick_rate_ms: u64) -> Self {
        let (tx, rx) = mpsc::unbounded_channel();
        let tick_rate_ms = Arc::new(AtomicU64::new(tick_rate_ms.clamp(100, 5000)));
        let tick_rate_thread = Arc::clone(&tick_rate_ms);

        // Use a dedicated OS thread instead of tokio::spawn, since
        // crossterm::event::poll() is a blocking call that would tie up
        // a tokio worker thread permanently.
        crate::sandbox::worker::spawn("terminal", move || {
            while !crate::sandbox::worker::stopping() {
                // Re-read the tick rate each iteration so the settings popup
                // can change refresh_rate_ms at runtime and have it take
                // effect on the next poll without a restart.
                let dur = Duration::from_millis(tick_rate_thread.load(Ordering::Relaxed));
                if event::poll(dur).unwrap_or(false) {
                    match event::read() {
                        Ok(Event::Key(key)) if key.kind == KeyEventKind::Press => {
                            if tx.send(AppEvent::Key(key)).is_err() {
                                return;
                            }
                        }
                        Ok(Event::Mouse(mouse)) => {
                            if tx.send(AppEvent::Mouse(mouse)).is_err() {
                                return;
                            }
                        }
                        _ => {}
                    }
                } else if tx.send(AppEvent::Tick).is_err() {
                    return;
                }
            }
        });

        Self { rx, tick_rate_ms }
    }

    /// Update the polling interval. Idempotent — calling with the current
    /// value is a no-op atomic store, so the run loop can call this every
    /// iteration without tracking previous state.
    pub fn set_tick_rate(&self, ms: u64) {
        self.tick_rate_ms
            .store(ms.clamp(100, 5000), Ordering::Relaxed);
    }

    pub async fn next(&mut self) -> Result<AppEvent> {
        self.rx
            .recv()
            .await
            .ok_or_else(|| anyhow::anyhow!("Event channel closed"))
    }
}

use std::io::{IsTerminal, Write};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

const DRAW_EVERY: usize = 256;
const DRAW_INTERVAL: Duration = Duration::from_millis(200);

#[derive(Clone)]
pub(super) struct ScanProgress {
    inner: Option<Arc<ProgressInner>>,
}

struct ProgressInner {
    completed: AtomicUsize,
    total: AtomicUsize,
    state: Mutex<ProgressState>,
}

struct ProgressState {
    phase: &'static str,
    width: usize,
    last_draw: Instant,
    active: bool,
}

impl ScanProgress {
    pub(super) fn for_stderr() -> Self {
        if !std::io::stderr().is_terminal() {
            return Self::disabled();
        }
        Self {
            inner: Some(Arc::new(ProgressInner {
                completed: AtomicUsize::new(0),
                total: AtomicUsize::new(0),
                state: Mutex::new(ProgressState {
                    phase: "walk",
                    width: 0,
                    last_draw: Instant::now(),
                    active: false,
                }),
            })),
        }
    }

    pub(super) fn disabled() -> Self {
        Self { inner: None }
    }

    pub(super) fn start(&self, phase: &'static str, total: Option<usize>) {
        let Some(inner) = &self.inner else {
            return;
        };
        inner.completed.store(0, Ordering::Relaxed);
        inner.total.store(total.unwrap_or(0), Ordering::Relaxed);
        let Ok(mut state) = inner.state.lock() else {
            return;
        };
        state.phase = phase;
        state.last_draw = Instant::now();
        state.active = true;
        draw(inner, &mut state);
    }

    pub(super) fn advance(&self) {
        let Some(inner) = &self.inner else {
            return;
        };
        let completed = inner.completed.fetch_add(1, Ordering::Relaxed) + 1;
        let total = inner.total.load(Ordering::Relaxed);
        if completed != total && !completed.is_multiple_of(DRAW_EVERY) {
            return;
        }
        let Ok(mut state) = inner.state.try_lock() else {
            return;
        };
        if completed != total && state.last_draw.elapsed() < DRAW_INTERVAL {
            return;
        }
        state.last_draw = Instant::now();
        draw(inner, &mut state);
    }

    pub(super) fn finish(&self) {
        let Some(inner) = &self.inner else {
            return;
        };
        let Ok(mut state) = inner.state.lock() else {
            return;
        };
        if state.active {
            eprintln!();
            state.active = false;
            state.width = 0;
        }
    }
}

fn draw(inner: &ProgressInner, state: &mut ProgressState) {
    let completed = inner.completed.load(Ordering::Relaxed);
    let total = inner.total.load(Ordering::Relaxed);
    let line = render_line(state.phase, completed, total);
    let padding = " ".repeat(state.width.saturating_sub(line.len()));
    eprint!("\r{line}{padding}");
    let _ = std::io::stderr().flush();
    state.width = line.len();
}

fn render_line(phase: &str, completed: usize, total: usize) -> String {
    if total == 0 {
        format!("[pentect] {phase}")
    } else {
        format!("[pentect] {phase} {completed}/{total}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn progress_line_is_compact() {
        assert_eq!(render_line("walk", 0, 0), "[pentect] walk");
        assert_eq!(render_line("scan", 42, 100), "[pentect] scan 42/100");
    }
}

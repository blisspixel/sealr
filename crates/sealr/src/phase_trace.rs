//! Supervisor phase timings for one diagnostic build.
//!
//! Samples are recorded only while a session is active. Starting a session is
//! explicit, so ordinary tests that happen to compile this module do not
//! accumulate traces. This module is not a shipped API.

use std::cell::RefCell;
use std::time::Instant;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Phase {
    SourceHash,
    PlanValidation,
    WorkerSetup,
    PayloadVerification,
}

impl Phase {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::SourceHash => "source_hash",
            Self::PlanValidation => "plan_validation",
            Self::WorkerSetup => "worker_setup",
            Self::PayloadVerification => "payload_verification",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Sample {
    pub phase: Phase,
    pub nanos: u128,
}

thread_local! {
    static SAMPLES: RefCell<Option<Vec<Sample>>> = const { RefCell::new(None) };
    static OPEN: RefCell<Option<Span>> = const { RefCell::new(None) };
}

pub struct Span {
    phase: Phase,
    start: Instant,
    open: bool,
}

impl Span {
    pub fn start(phase: Phase) -> Self {
        Self {
            phase,
            start: Instant::now(),
            open: true,
        }
    }

    pub fn switch(&mut self, phase: Phase) {
        self.finish();
        self.phase = phase;
        self.start = Instant::now();
        self.open = true;
    }

    pub fn close(&mut self) {
        self.finish();
    }

    fn finish(&mut self) {
        if !self.open {
            return;
        }
        self.open = false;
        let nanos = self.start.elapsed().as_nanos();
        SAMPLES.with(|slot| {
            if let Some(samples) = slot.borrow_mut().as_mut() {
                samples.push(Sample {
                    phase: self.phase,
                    nanos,
                });
            }
        });
    }
}

impl Drop for Span {
    fn drop(&mut self) {
        self.finish();
    }
}

/// Closes the thread-local phase when dropped, including on an early return.
#[must_use = "dropping the guard closes the phase immediately"]
pub struct OpenGuard;

impl Drop for OpenGuard {
    fn drop(&mut self) {
        close_open();
    }
}

pub fn open(phase: Phase) -> OpenGuard {
    OPEN.with(|slot| {
        let mut open = slot.borrow_mut();
        if let Some(span) = open.as_mut() {
            span.close();
        }
        *open = Some(Span::start(phase));
    });
    OpenGuard
}

pub fn switch(phase: Phase) {
    OPEN.with(|slot| {
        if let Some(span) = slot.borrow_mut().as_mut() {
            span.switch(phase);
        }
    });
}

pub fn close_open() {
    OPEN.with(|slot| {
        if let Some(span) = slot.borrow_mut().as_mut() {
            span.close();
        }
    });
}

pub fn begin() {
    SAMPLES.with(|slot| *slot.borrow_mut() = Some(Vec::new()));
}

pub fn take() -> Vec<Sample> {
    SAMPLES.with(|slot| {
        slot.borrow_mut()
            .as_mut()
            .map(std::mem::take)
            .unwrap_or_default()
    })
}

pub fn end() {
    close_open();
    OPEN.with(|slot| *slot.borrow_mut() = None);
    SAMPLES.with(|slot| *slot.borrow_mut() = None);
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Reset;

    impl Drop for Reset {
        fn drop(&mut self) {
            end();
        }
    }

    #[test]
    fn an_idle_trace_discards_samples() {
        let _reset = Reset;
        let mut span = Span::start(Phase::SourceHash);
        span.close();
        assert!(take().is_empty());
    }

    #[test]
    fn a_session_keeps_each_closed_phase() {
        let _reset = Reset;
        begin();
        let mut span = Span::start(Phase::WorkerSetup);
        span.switch(Phase::PayloadVerification);
        span.close();
        let samples = take();
        assert_eq!(samples.len(), 2);
        assert_eq!(samples[0].phase, Phase::WorkerSetup);
        assert_eq!(samples[1].phase, Phase::PayloadVerification);
        assert!(take().is_empty());
    }

    #[test]
    fn an_idle_open_discards_samples() {
        let _reset = Reset;
        let guard = open(Phase::WorkerSetup);
        switch(Phase::PayloadVerification);
        drop(guard);
        assert!(take().is_empty());
    }

    #[test]
    fn a_guard_closes_an_early_return() {
        let _reset = Reset;
        begin();
        let samples = {
            let _guard = open(Phase::WorkerSetup);
            switch(Phase::PayloadVerification);
            take()
        };
        assert_eq!(samples.len(), 1);
        assert_eq!(samples[0].phase, Phase::WorkerSetup);
        let closed = take();
        assert_eq!(closed.len(), 1);
        assert_eq!(closed[0].phase, Phase::PayloadVerification);
    }

    #[test]
    fn close_open_ends_payload_before_a_later_span() {
        let _reset = Reset;
        begin();
        let guard = open(Phase::WorkerSetup);
        switch(Phase::PayloadVerification);
        close_open();
        let later = Span::start(Phase::SourceHash);
        drop(later);
        drop(guard);
        let samples = take();
        assert_eq!(samples.len(), 3);
        assert_eq!(samples[0].phase, Phase::WorkerSetup);
        assert_eq!(samples[1].phase, Phase::PayloadVerification);
        assert_eq!(samples[2].phase, Phase::SourceHash);
    }
}

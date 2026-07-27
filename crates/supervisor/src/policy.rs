//! When to restart a service, and how long to wait first.
//!
//! This is the part of a supervisor that is easy to get subtly wrong and hard to
//! notice: a restart loop that hammers, or a backoff that never resets so a
//! service which has been healthy for a week is still treated as if it just
//! crashed. Both bugs are invisible until the day they matter, so the decision is
//! a pure function over explicit inputs and is tested directly, rather than being
//! spread through the code that spawns processes.

use selfhost_config::RestartPolicy;
use std::time::Duration;

/// The longest a restart is ever delayed.
///
/// Without a ceiling, exponential backoff on a service that has been failing
/// overnight reaches delays measured in days, and the operator's fix appears not
/// to work because nothing tries again for a very long time.
pub const MAX_BACKOFF: Duration = Duration::from_secs(300);

/// The shortest window of uptime that counts as "it worked".
///
/// Below this, a service that starts, crashes, and starts again could reset its
/// own failure counter every cycle and loop forever at the base delay.
pub const MIN_HEALTHY_WINDOW: Duration = Duration::from_secs(30);

/// What the supervisor should do after a service exits.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome {
    /// Leave it stopped. Either the policy says so, or it exited cleanly.
    Stay,
    /// Start it again after waiting.
    RestartAfter(Duration),
    /// Stop trying: it has failed more times in a row than the budget allows.
    GaveUp,
}

/// How a process finished.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Exit {
    /// Exited zero, having been asked to stop or having finished its work.
    Clean,
    /// Exited non-zero, or was killed by a signal.
    Failed,
}

impl Exit {
    /// Classifies a process exit status.
    ///
    /// A signal death reports `success() == false`, so being killed counts as a
    /// failure — which is what an operator means by it.
    pub fn of(status: std::process::ExitStatus) -> Self {
        if status.success() { Self::Clean } else { Self::Failed }
    }
}

/// How long a service must stay up before its failure counter resets.
///
/// Scaled to the service's own settings so a program with a long start-up gets a
/// proportionally longer window, and floored at [`MIN_HEALTHY_WINDOW`] so an
/// aggressive configuration cannot make the reset meaningless.
pub fn healthy_window(base_delay: Duration, max_restarts: u32) -> Duration {
    let scaled = base_delay.saturating_mul(max_restarts.max(1));
    scaled.max(MIN_HEALTHY_WINDOW)
}

/// Decides what to do about a service that has just exited.
///
/// `consecutive_failures` counts restarts already performed since the last reset,
/// so it is zero the first time a service dies. `max_restarts` of zero means an
/// unlimited budget.
pub fn decide(
    policy: RestartPolicy,
    exit: Exit,
    consecutive_failures: u32,
    max_restarts: u32,
    base_delay: Duration,
) -> Outcome {
    let wants_restart = match policy {
        RestartPolicy::Never => false,
        RestartPolicy::OnFailure => exit == Exit::Failed,
        RestartPolicy::Always => true,
    };

    if !wants_restart {
        return Outcome::Stay;
    }

    if max_restarts != 0 && consecutive_failures >= max_restarts {
        return Outcome::GaveUp;
    }

    Outcome::RestartAfter(backoff(base_delay, consecutive_failures))
}

/// The delay before restart number `attempt`, counting from zero.
///
/// Doubles each time and stops at [`MAX_BACKOFF`]. The shift is guarded because
/// `1u32 << 32` is undefined rather than saturating, and a service that has
/// failed thirty-two times is exactly the case that reaches it.
pub fn backoff(base: Duration, attempt: u32) -> Duration {
    let multiplier = 1u64.checked_shl(attempt.min(32)).unwrap_or(u64::MAX);
    base.saturating_mul(multiplier.min(u32::MAX as u64) as u32).min(MAX_BACKOFF)
}

/// Tracks consecutive failures for one service.
#[derive(Debug, Clone, Copy, Default)]
pub struct FailureCounter {
    consecutive: u32,
}

impl FailureCounter {
    /// How many restarts have happened since the last reset.
    pub fn consecutive(&self) -> u32 {
        self.consecutive
    }

    /// Records that a restart is being attempted.
    pub fn record_restart(&mut self) {
        self.consecutive = self.consecutive.saturating_add(1);
    }

    /// Clears the counter after the service proved it can stay up.
    ///
    /// Called with the uptime the service actually achieved; short-lived runs do
    /// not count, or a crash loop would reset itself on every cycle.
    pub fn note_uptime(&mut self, uptime: Duration, window: Duration) {
        if uptime >= window {
            self.consecutive = 0;
        }
    }

    /// Clears the counter unconditionally, for an operator-requested start.
    ///
    /// Pressing Start is a statement that the operator has dealt with whatever was
    /// wrong, so it must not inherit the old backoff and appear to do nothing.
    pub fn reset(&mut self) {
        self.consecutive = 0;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const BASE: Duration = Duration::from_secs(5);

    #[test]
    fn a_clean_exit_is_left_alone_under_the_default_policy() {
        // The common case: the operator stopped it, or it finished. Restarting
        // here fights whoever asked for the stop.
        assert_eq!(
            decide(RestartPolicy::OnFailure, Exit::Clean, 0, 5, BASE),
            Outcome::Stay
        );
    }

    #[test]
    fn a_failure_restarts_under_the_default_policy() {
        assert_eq!(
            decide(RestartPolicy::OnFailure, Exit::Failed, 0, 5, BASE),
            Outcome::RestartAfter(BASE)
        );
    }

    #[test]
    fn always_restarts_even_a_clean_exit() {
        assert_eq!(
            decide(RestartPolicy::Always, Exit::Clean, 0, 5, BASE),
            Outcome::RestartAfter(BASE)
        );
    }

    #[test]
    fn never_stays_stopped_however_it_died() {
        assert_eq!(decide(RestartPolicy::Never, Exit::Failed, 0, 5, BASE), Outcome::Stay);
        assert_eq!(decide(RestartPolicy::Never, Exit::Clean, 0, 5, BASE), Outcome::Stay);
    }

    #[test]
    fn gives_up_once_the_budget_is_spent() {
        assert_eq!(
            decide(RestartPolicy::Always, Exit::Failed, 5, 5, BASE),
            Outcome::GaveUp
        );
        // One below the budget still tries.
        assert!(matches!(
            decide(RestartPolicy::Always, Exit::Failed, 4, 5, BASE),
            Outcome::RestartAfter(_)
        ));
    }

    #[test]
    fn a_zero_budget_means_unlimited() {
        assert!(matches!(
            decide(RestartPolicy::Always, Exit::Failed, 10_000, 0, BASE),
            Outcome::RestartAfter(_)
        ));
    }

    #[test]
    fn backoff_doubles_then_stops_at_the_ceiling() {
        assert_eq!(backoff(BASE, 0), Duration::from_secs(5));
        assert_eq!(backoff(BASE, 1), Duration::from_secs(10));
        assert_eq!(backoff(BASE, 2), Duration::from_secs(20));
        assert_eq!(backoff(BASE, 3), Duration::from_secs(40));
        assert_eq!(backoff(BASE, 100), MAX_BACKOFF);
    }

    #[test]
    fn backoff_does_not_overflow_at_an_absurd_attempt_count() {
        // 1u32 << 32 is undefined rather than saturating, and a service failing
        // for long enough gets there. Must clamp, not panic or wrap to zero.
        for attempt in [31, 32, 33, u32::MAX] {
            assert_eq!(backoff(BASE, attempt), MAX_BACKOFF, "attempt {attempt}");
        }
    }

    #[test]
    fn the_counter_resets_only_after_a_real_stretch_of_uptime() {
        let window = healthy_window(BASE, 5);
        let mut counter = FailureCounter::default();
        counter.record_restart();
        counter.record_restart();
        assert_eq!(counter.consecutive(), 2);

        // A service that crashes immediately must not clear its own history, or
        // it loops forever at the base delay and the budget never runs out.
        counter.note_uptime(Duration::from_secs(1), window);
        assert_eq!(counter.consecutive(), 2);

        counter.note_uptime(window, window);
        assert_eq!(counter.consecutive(), 0);
    }

    #[test]
    fn the_healthy_window_is_never_shorter_than_the_floor() {
        // Unlimited restarts with a one-second delay would otherwise give a
        // one-second window, which any crash loop clears trivially.
        assert_eq!(healthy_window(Duration::from_secs(1), 0), MIN_HEALTHY_WINDOW);
        assert_eq!(healthy_window(Duration::from_secs(1), 5), MIN_HEALTHY_WINDOW);
        // A long delay scales past the floor.
        assert_eq!(healthy_window(Duration::from_secs(20), 5), Duration::from_secs(100));
    }

    #[test]
    fn an_operator_start_clears_the_backoff() {
        let mut counter = FailureCounter::default();
        for _ in 0..4 {
            counter.record_restart();
        }
        counter.reset();
        assert_eq!(counter.consecutive(), 0);
    }
}

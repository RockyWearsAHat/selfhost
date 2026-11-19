//! Keeping every armed relay answering, for as long as the daemon runs.
//!
//! The supervisor restarts a relay whose process exits. That alone left three
//! ways for the only door to stay shut with nobody acting, all seen live on
//! the box:
//!
//! - a relay that could not start at boot (its preflight refused, or another
//!   program held the port) was never tried again;
//! - a relay in any stopped-with-a-reason state stayed there until somebody
//!   restarted the whole daemon;
//! - a relay whose process lived on but stopped answering looked `Up`.
//!
//! [`Memory::judge`] is the whole decision, pure over what was seen and when;
//! [`crate::Relays::heal`] observes, asks it, and acts. A relay an operator
//! stopped on purpose is left stopped: that is a decision, not a fault.

use crate::probe::ProbeFailure;
use selfhost_supervisor::policy::backoff;
use std::time::{Duration, Instant};

/// How often the daemon looks at every relay.
pub const HEAL_INTERVAL: Duration = Duration::from_secs(15);

/// How long a freshly started relay has to bind before it is probed.
pub const STARTUP_GRACE: Duration = Duration::from_secs(5);

/// Consecutive unanswered probes before a running relay is restarted.
///
/// One miss can be a busy moment; three in a row, a probe interval apart, is a
/// relay that has stopped working.
pub const MISSES_BEFORE_RESTART: u32 = 3;

/// The first wait between two remedies for the same relay, doubled per
/// remedy up to the supervisor's own ceiling and cleared by one good answer.
pub const REMEDY_BACKOFF: Duration = Duration::from_secs(5);

/// What one look at a relay found.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Seen {
    /// Running past its start-up grace and it answered the hello.
    Answering,
    /// Running past its start-up grace and it did not answer.
    Unanswered(ProbeFailure),
    /// Starting, stopping, waiting out the supervisor's backoff, or too young
    /// to probe: the supervisor is already acting.
    Settling,
    /// Stopped by an operator.
    Stopped,
    /// Armed and not running, with the reason in the supervisor's words.
    Dead(String),
}

/// What to do about a relay.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Remedy {
    /// Stop the running process and start it again.
    Restart(String),
    /// Bring the relay up from nothing: preflight, install, start.
    Start(String),
}

impl Remedy {
    /// Why this remedy was chosen.
    pub fn reason(&self) -> &str {
        match self {
            Self::Restart(reason) | Self::Start(reason) => reason,
        }
    }
}

/// What the healer remembers about one relay between looks.
#[derive(Debug, Clone, Default)]
pub struct Memory {
    misses: u32,
    remedies: u32,
    quiet_until: Option<Instant>,
}

impl Memory {
    /// Decides what, if anything, to do about what was just seen at `now`.
    ///
    /// Remedies for one relay back off ([`REMEDY_BACKOFF`], doubling) so a
    /// cause that has not cleared is retried, never hammered and never given
    /// up on. One good answer clears the slate.
    pub fn judge(&mut self, seen: Seen, now: Instant) -> Option<Remedy> {
        let remedy = match seen {
            Seen::Answering => {
                *self = Self::default();
                return None;
            }
            Seen::Settling | Seen::Stopped => return None,
            Seen::Unanswered(failure) => {
                self.misses += 1;
                if self.misses < MISSES_BEFORE_RESTART {
                    return None;
                }
                Remedy::Restart(format!(
                    "no answer to {} hellos in a row: {failure}",
                    self.misses
                ))
            }
            Seen::Dead(reason) => Remedy::Start(reason),
        };
        if self.quiet_until.is_some_and(|until| now < until) {
            return None;
        }
        self.misses = 0;
        self.quiet_until = Some(now + backoff(REMEDY_BACKOFF, self.remedies));
        self.remedies += 1;
        Some(remedy)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn silent() -> Seen {
        Seen::Unanswered(ProbeFailure::Silent)
    }

    #[test]
    fn a_relay_that_answers_is_left_alone() {
        let mut memory = Memory::default();
        assert_eq!(memory.judge(Seen::Answering, Instant::now()), None);
    }

    #[test]
    fn a_running_relay_that_stops_answering_is_restarted_on_the_third_miss() {
        let mut memory = Memory::default();
        let now = Instant::now();
        assert_eq!(memory.judge(silent(), now), None);
        assert_eq!(memory.judge(silent(), now), None);
        let remedy = memory.judge(silent(), now).expect("restarted");
        assert!(matches!(remedy, Remedy::Restart(_)), "{remedy:?}");
        assert!(remedy.reason().contains("never answers"), "the log names why: {remedy:?}");
    }

    #[test]
    fn one_good_answer_clears_the_misses() {
        let mut memory = Memory::default();
        let now = Instant::now();
        memory.judge(silent(), now);
        memory.judge(silent(), now);
        memory.judge(Seen::Answering, now);
        assert_eq!(memory.judge(silent(), now), None, "the count started over");
    }

    #[test]
    fn a_dead_relay_is_started_again_with_its_reason() {
        let mut memory = Memory::default();
        let remedy = memory.judge(Seen::Dead("gave up after 5 restarts".into()), Instant::now());
        assert_eq!(remedy, Some(Remedy::Start("gave up after 5 restarts".into())));
    }

    #[test]
    fn remedies_back_off_and_never_give_up() {
        let mut memory = Memory::default();
        let dead = || Seen::Dead("exited with code 1".into());
        let mut now = Instant::now();
        let mut wait = REMEDY_BACKOFF;
        assert!(memory.judge(dead(), now).is_some(), "the first remedy is immediate");
        for _ in 0..20 {
            assert_eq!(memory.judge(dead(), now + wait / 2), None, "inside the backoff");
            now += wait;
            assert!(memory.judge(dead(), now).is_some(), "retried once the backoff ends");
            wait = (wait * 2).min(selfhost_supervisor::policy::MAX_BACKOFF);
        }
    }

    #[test]
    fn a_relay_stopped_on_purpose_or_already_recovering_is_not_touched() {
        let mut memory = Memory::default();
        let now = Instant::now();
        assert_eq!(memory.judge(Seen::Stopped, now), None);
        assert_eq!(memory.judge(Seen::Settling, now), None);
    }
}

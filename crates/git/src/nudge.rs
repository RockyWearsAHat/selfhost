//! Asking a poll to happen now.
//!
//! A [`Nudge`] is the one-way signal between whoever *learns* that a branch
//! moved and whoever *acts* on it. The webhook route on the public listener
//! learns; the self-update watcher acts. Neither needs to know the other
//! exists, which is what keeps the webhook out of the deployment logic
//! entirely: a nudge carries no commit, no branch, and no payload, only the
//! request to stop waiting.
//!
//! # Why it carries nothing
//!
//! The obvious design hands the pushed commit along with the signal, and it is
//! wrong. The body of a webhook request is attacker-controlled — the signature
//! proves who sent it, not that its contents describe reality — so a deployment
//! that read the commit from the request would be deploying whatever the
//! request said. Carrying nothing forces the watcher down the path it already
//! takes on a timer: read the real branch tip with `git ls-remote`, compare,
//! and act on what the remote actually says. A forged nudge therefore costs one
//! early `ls-remote` and can change nothing else.
//!
//! # Why a missed nudge is not a lost deployment
//!
//! Nudges are edge-triggered and unbuffered: two arriving while a deployment is
//! already running collapse into one, and one arriving with nobody waiting is
//! dropped. Both are safe, because the nudge is never the only trigger — the
//! poll interval underneath it ([`selfhost_config::git`]) is what guarantees a
//! push is eventually noticed. A nudge only ever moves that moment earlier.

use std::sync::Arc;
use tokio::sync::Notify;

/// A request that a waiting poller run its check immediately.
///
/// Cheap to clone, like [`Watches`](crate::Watches): the webhook route and the
/// watcher hold the same signal rather than two that could disagree about
/// whether a push has been announced.
#[derive(Debug, Clone, Default)]
pub struct Nudge(Arc<Notify>);

impl Nudge {
    /// A nudge nobody is waiting on yet.
    pub fn new() -> Self {
        Self::default()
    }

    /// Asks whoever is waiting to check now.
    ///
    /// Never blocks and never fails, including when nothing is listening: a
    /// deployment whose watcher is mid-build has no waiter, and the push that
    /// arrives then is already covered by the build in flight.
    pub fn poke(&self) {
        self.0.notify_one();
    }

    /// Waits for the next [`poke`](Self::poke).
    ///
    /// One poke that arrives before this is called is remembered, so a nudge
    /// racing the start of a wait is not lost; further pokes before the wait
    /// resumes collapse into that one.
    pub async fn poked(&self) {
        self.0.notified().await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[tokio::test]
    async fn a_poke_wakes_a_waiter() {
        let nudge = Nudge::new();
        let waiting = nudge.clone();
        let task = tokio::spawn(async move { waiting.poked().await });

        // Yield until the task has actually reached the wait, so this asserts
        // the wake-up and not the remembered-poke path below.
        tokio::time::sleep(Duration::from_millis(20)).await;
        nudge.poke();

        tokio::time::timeout(Duration::from_secs(5), task)
            .await
            .expect("the waiter should have woken")
            .expect("the task should not have panicked");
    }

    #[tokio::test]
    async fn a_poke_that_arrives_before_the_wait_is_remembered() {
        // The race a webhook actually loses otherwise: the push arrives while
        // the watcher is between two ticks and not yet parked on `poked`.
        let nudge = Nudge::new();
        nudge.poke();

        tokio::time::timeout(Duration::from_secs(5), nudge.poked())
            .await
            .expect("the earlier poke should still have counted");
    }

    #[tokio::test]
    async fn nothing_waiting_is_not_an_error() {
        // A push landing mid-build has no waiter. It must not panic, and the
        // build already in flight is what covers it.
        let nudge = Nudge::new();
        nudge.poke();
        nudge.poke();

        // Both collapse into the single remembered permit: the first wait is
        // satisfied, the second finds nothing.
        tokio::time::timeout(Duration::from_secs(5), nudge.poked())
            .await
            .expect("the remembered poke satisfies one wait");
        let second = tokio::time::timeout(Duration::from_millis(100), nudge.poked()).await;
        assert!(second.is_err(), "two pokes must not queue two checks");
    }

    #[tokio::test]
    async fn clones_share_one_signal() {
        let nudge = Nudge::new();
        let other = nudge.clone();
        other.poke();

        tokio::time::timeout(Duration::from_secs(5), nudge.poked())
            .await
            .expect("a clone's poke must reach the original");
    }
}

//! Every platform this build has no screen source for.
//!
//! The alternative — leaving the traits unimplemented outside Windows and macOS —
//! would mean the crate does not compile on Linux, which would mean the
//! *workspace* does not compile on Linux, which would mean `cargo test` on a
//! contributor's machine fails for a reason that has nothing to do with what they
//! changed. `crates/firewall` already made this argument and answered it the same
//! way, with an explicit `unsupported` backend rather than a `cfg` hole.
//!
//! It also keeps the honest answer honest. A build that cannot capture a screen
//! says so in one sentence the console renders, naming the platform. It does not
//! report an I/O error, and it does not hand back a black frame — a black frame
//! is indistinguishable from a screen that is genuinely off, and that is exactly
//! the kind of ambiguity this crate's error type exists to remove.

use crate::input::InjectedEvent;
use crate::{Capture, CaptureError, CursorSource, CursorState, Frame, InjectError, Injector};
use selfhost_desk::wire::Monitor;
use std::time::Duration;

/// A screen source, cursor source and injector for a platform that has none.
///
/// Deliberately constructible everywhere, including on Windows and macOS, so a
/// test can assert what the console does with a machine that cannot be viewed
/// without needing such a machine.
#[derive(Debug, Clone, Copy, Default)]
pub struct Unavailable;

impl Unavailable {
    /// The platform this build is running on, as the refusal names it.
    pub const fn platform() -> &'static str {
        std::env::consts::OS
    }
}

impl Capture for Unavailable {
    fn monitors(&self) -> &[Monitor] {
        &[]
    }

    fn next_frame(&mut self, _timeout: Duration) -> Result<Option<Frame<'_>>, CaptureError> {
        Err(CaptureError::Unsupported { platform: Self::platform() })
    }
}

impl CursorSource for Unavailable {
    fn cursor(&mut self) -> Result<CursorState, CaptureError> {
        Err(CaptureError::Unsupported { platform: Self::platform() })
    }
}

impl Injector for Unavailable {
    fn inject(&mut self, _events: &[InjectedEvent]) -> Result<(), InjectError> {
        Err(InjectError::Unsupported { platform: Self::platform() })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_three_traits_are_object_safe() {
        // The session driver holds these behind `dyn`, chosen at run time from
        // config. A trait that stops being object-safe breaks that at the far end
        // of the crate graph, so it is asserted here where the traits are.
        let mut stub = Unavailable;
        let capture: &mut dyn Capture = &mut stub;
        assert!(capture.monitors().is_empty());
        let mut stub = Unavailable;
        let _cursor: &mut dyn CursorSource = &mut stub;
        let mut stub = Unavailable;
        let _injector: &mut dyn Injector = &mut stub;
    }

    #[test]
    fn an_unsupported_platform_is_a_sentence_naming_it_rather_than_an_io_error() {
        let mut stub = Unavailable;
        let refusal = stub.next_frame(Duration::from_millis(1)).unwrap_err();
        assert!(refusal.is_fatal());
        assert!(refusal.sentence().contains(std::env::consts::OS));
    }

    #[test]
    fn injection_is_refused_without_being_reported_to_the_client() {
        let mut stub = Unavailable;
        let refusal = stub.inject(&[]).unwrap_err();
        assert_eq!(refusal.refusal(), None, "a build fault is not the client's business");
    }
}

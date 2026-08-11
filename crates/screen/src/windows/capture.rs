//! Which screen source this machine gets, and why.
//!
//! There are two implementations of [`Capture`] on Windows and they are not
//! interchangeable in quality: [`dxgi::DxgiCapture`] reads the composited output
//! and therefore sees Direct3D, and [`gdi::GdiCapture`] reads the GDI desktop and
//! therefore does not. A full-screen game under GDI is a black rectangle — a real
//! frame, honestly encoded, of nothing.
//!
//! So duplication is tried first and GDI is the fallback, and this module is the
//! one place that decision is made. It is a *decision*, not an error path: the
//! conditions that send a machine to GDI are ordinary properties of that machine —
//! no Direct3D 11, a display on another adapter, an output already duplicated by
//! somebody else, a remote session. Each is reported once, in a sentence naming
//! what the operator loses, and then the session runs.
//!
//! # Why the choice is made once, at startup, and revisited on rebuild
//!
//! A duplication that fails mid-session answers `DXGI_ERROR_ACCESS_LOST`, which the
//! state machine turns into a rebuild — and a rebuild comes back through
//! [`WindowsCapture::open`], so a machine that loses duplication for a reason that
//! passes (a driver restart, a fast user switch) gets it back without a restart,
//! and one that loses it for a reason that does not falls to GDI and keeps working.
//! Neither outcome is a session that dies.

use super::dxgi::DxgiCapture;
use super::gdi::GdiCapture;
use crate::fault::Fault;
use crate::{Capture, CaptureError, Frame, Monitor};
use std::time::Duration;

/// Which of the two sources a session is running on.
///
/// Reported to the console, because "the screen is black" and "the screen is black
/// *and this machine cannot capture Direct3D*" are the same picture and completely
/// different problems.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Backend {
    /// DXGI Desktop Duplication: the composited output, games included.
    Duplication,
    /// GDI `BitBlt`: the desktop, without anything Direct3D drew.
    Gdi,
}

impl Backend {
    /// The one word the diagnostics plate prints.
    pub fn word(self) -> &'static str {
        match self {
            Self::Duplication => "duplication",
            Self::Gdi => "GDI",
        }
    }

    /// What this backend cannot show, or `None` when it can show everything.
    ///
    /// The sentence exists because the failure it describes is invisible: GDI does
    /// not report that it could not see the game, it reports a frame of black. An
    /// operator looking at that needs this sentence and no other.
    pub fn caveat(self) -> Option<&'static str> {
        match self {
            Self::Duplication => None,
            Self::Gdi => Some(
                "full-screen Direct3D — games, and some video players — capture as black on this \
                 source",
            ),
        }
    }
}

/// The screen source this machine actually has.
#[derive(Debug)]
pub enum WindowsCapture {
    /// Desktop Duplication, which is what a machine gets when it can.
    Duplication(Box<DxgiCapture>),
    /// GDI, and the condition that sent this machine to it.
    Gdi(Box<GdiCapture>, Option<Fault>),
}

impl WindowsCapture {
    /// Opens the best source this machine can provide.
    ///
    /// # Errors
    ///
    /// Only the conditions that stop *both* sources: no displays in this session,
    /// or a GDI failure. A machine that cannot duplicate is not an error here — it
    /// is a machine on [`Backend::Gdi`].
    pub fn open() -> Result<Self, CaptureError> {
        match DxgiCapture::new() {
            Ok(capture) => Ok(Self::Duplication(Box::new(capture))),
            // The session has no screen at all. Duplication is not the problem and
            // GDI would answer exactly the same thing, so the condition is passed
            // straight up rather than hidden behind a fallback that also fails.
            Err(condition @ (CaptureError::SessionDisconnected | CaptureError::NoSession)) => {
                Err(condition)
            }
            Err(condition) => {
                let fault = match condition {
                    CaptureError::Fatal(fault) => Some(fault),
                    other => {
                        Some(Fault::refused("IDXGIOutput1::DuplicateOutput", other.sentence()))
                    }
                };
                GdiCapture::new().map(|capture| Self::Gdi(Box::new(capture), fault))
            }
        }
    }

    /// Which source this is.
    pub fn backend(&self) -> Backend {
        match self {
            Self::Duplication(_) => Backend::Duplication,
            Self::Gdi(_, _) => Backend::Gdi,
        }
    }

    /// Which display is being captured.
    pub fn target(&self) -> u8 {
        match self {
            Self::Duplication(capture) => capture.target(),
            Self::Gdi(capture, _) => capture.target(),
        }
    }

    /// Captures a different display from the next frame on.
    pub fn select(&mut self, monitor: u8) -> bool {
        match self {
            Self::Duplication(capture) => capture.select(monitor),
            Self::Gdi(capture, _) => capture.select(monitor),
        }
    }

    /// The last platform failure, for the diagnostics plate.
    ///
    /// On a GDI session this is the reason duplication was not available, which is
    /// the most useful thing the plate can carry: it is the answer to "why is the
    /// game black".
    pub fn last_fault(&self) -> Option<&Fault> {
        match self {
            Self::Duplication(capture) => capture.last_fault(),
            Self::Gdi(capture, refused) => capture.last_fault().or(refused.as_ref()),
        }
    }
}

impl Capture for WindowsCapture {
    fn monitors(&self) -> &[Monitor] {
        match self {
            Self::Duplication(capture) => capture.monitors(),
            Self::Gdi(capture, _) => capture.monitors(),
        }
    }

    fn next_frame(&mut self, timeout: Duration) -> Result<Option<Frame<'_>>, CaptureError> {
        match self {
            Self::Duplication(capture) => capture.next_frame(timeout),
            Self::Gdi(capture, _) => capture.next_frame(timeout),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_the_gdi_source_carries_a_caveat() {
        // The sentence is the whole point of the type: a black rectangle explains
        // itself nowhere else.
        assert!(Backend::Duplication.caveat().is_none());
        assert!(Backend::Gdi.caveat().is_some_and(|caveat| caveat.contains("Direct3D")));
    }

    #[test]
    fn each_backend_has_a_word_for_the_plate() {
        assert_eq!(Backend::Duplication.word(), "duplication");
        assert_eq!(Backend::Gdi.word(), "GDI");
    }
}

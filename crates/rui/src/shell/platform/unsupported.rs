//! The backend for platforms that have none.
//!
//! Compiled where macOS, Windows, and X11 all fail to apply. It exists so that
//! such a target still *builds*, and fails with a sentence naming what is
//! missing rather than with a linker error about an absent module — which is
//! what someone porting this would otherwise meet first.

use crate::accessibility::AccessUpdate;
use crate::geom::Rect;
use crate::theme::Appearance;
use crate::{Canvas, Event};
use std::time::Duration;

use crate::shell::{Backend, Error, WindowOptions};

/// A window that cannot be opened here.
pub(crate) struct Window;

impl Backend for Window {
    fn open(_options: &WindowOptions) -> Result<Self, Error> {
        Err(Error::Unsupported)
    }

    fn pump(
        &mut self,
        _timeout: Duration,
        _events: &mut Vec<Event>,
        _redraw: &mut dyn FnMut(&Self),
    ) -> Result<(), Error> {
        Err(Error::Unsupported)
    }

    fn surface(&self) -> (u32, u32, f32) {
        (1, 1, 1.0)
    }

    fn appearance(&self) -> Appearance {
        Appearance::Light
    }

    fn present(&self, _canvas: &Canvas) -> Result<(), Error> {
        Err(Error::Unsupported)
    }

    fn is_open(&self) -> bool {
        false
    }

    fn clipboard_text(&self) -> Result<Option<String>, Error> {
        Err(Error::Unsupported)
    }

    fn set_clipboard_text(&self, _text: &str) -> Result<(), Error> {
        Err(Error::Unsupported)
    }

    fn set_composition_area(&self, _area: Option<Rect>) -> Result<(), Error> {
        Err(Error::Unsupported)
    }

    fn update_accessibility(&self, _update: &AccessUpdate) -> Result<(), Error> {
        Err(Error::Unsupported)
    }
}

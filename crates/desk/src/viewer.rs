//! The server-side session driver — **not built yet, and deliberately so**.
//!
//! This module is the one impure file this crate will ever contain: the task
//! that owns a desktop session, holds the mux channel, drives [`crate::state`]
//! with whatever the capture layer reports, performs the [`Action`] the state
//! machine returns, encodes tiles through [`crate::tiles`], and re-checks
//! [`Capabilities::CONTROL`] on every single input message rather than
//! remembering the handshake's answer.
//!
//! # Why it is a stub rather than a half-implementation
//!
//! It cannot be written honestly yet, and a half-written version of it would be
//! worse than nothing.
//!
//! The driver's whole job is to sit between three things that do not exist in
//! this branch yet: the mux channel from `selfhost-mesh`, the `Capture` /
//! `CursorSource` / `Injector` traits from `selfhost-screen`, and the socket the
//! admin API hands over on a successful upgrade. Writing it now would mean
//! inventing local stand-ins for all three, and every one of those stand-ins
//! would have to be deleted and re-argued when the real thing lands — with the
//! usual result that one of them survives, becomes an adapter nobody can explain,
//! and the seam ends up in the wrong place forever.
//!
//! There is a second reason, specific to this crate. Everything else here is
//! pure and exhaustively tested precisely *because* it is pure; that is the
//! property the crate exists to have, and it is what lets the whole recovery
//! path be exercised on a laptop with no display attached. Putting a socket in
//! this crate before the pure half is finished would make the finished half
//! harder to test, not easier to use.
//!
//! # What it will be
//!
//! When `selfhost-mesh` and `selfhost-screen` land, this module gains one type —
//! roughly `Viewer::run(channel, capture, injector, grant, limits)` — and the
//! following responsibilities, none of which belong anywhere else:
//!
//! 1. **Drive the state machine.** Each capture result becomes an
//!    [`Observation`]; each returned [`Action`] becomes a sleep, a rebuild, a
//!    respawn request, or a close. It never invents a delay of its own — the
//!    delays are decided in [`crate::state`] so they can be tested.
//! 2. **Encode and send.** [`crate::tiles::diff`] against the previous frame,
//!    each update as a [`Message::Tile`], bracketed by
//!    [`Message::FrameBegin`] and [`Message::FrameEnd`]. At zero credit it
//!    **drops frames and merges damage** rather than queueing: a remote desktop
//!    must show the present, not a backlog.
//! 3. **Send the cursor separately**, through [`crate::cursor::CursorPolicy`],
//!    so the pointer moves at the viewer's frame rate.
//! 4. **Refuse input, per message.** [`Capabilities::CONTROL`] is re-checked
//!    every time, never inferred from the handshake, so a viewer can be
//!    downgraded mid-session; and input is refused outright unless
//!    [`Session::input_permitted`] is true, which it is not on the secure
//!    desktop.
//! 5. **Release everything on close.** [`crate::keys::HeldKeys::drain`] is
//!    applied when the channel closes, without waiting to be asked. A tunnelled
//!    link dropping mid-drag is the most likely real-world failure this
//!    subsystem has, and a modifier left held on the far machine is the worst
//!    ordinary outcome of it.
//! 6. **Re-validate the session on a timer** using the admin API's
//!    `Sessions::identity` and never `validate` — `validate` refreshes
//!    `last_seen`, so a long-lived stream re-validating on a timer would keep
//!    its own session alive forever and defeat the idle expiry that exists so
//!    that a console left open on an unlocked machine stops being a way in.
//!
//! [`Action`]: crate::state::Action
//! [`Capabilities::CONTROL`]: crate::grant::Capabilities::CONTROL
//! [`Message::FrameBegin`]: crate::wire::Message::FrameBegin
//! [`Message::FrameEnd`]: crate::wire::Message::FrameEnd
//! [`Message::Tile`]: crate::wire::Message::Tile
//! [`Observation`]: crate::state::Observation
//! [`Session::input_permitted`]: crate::state::Session::input_permitted

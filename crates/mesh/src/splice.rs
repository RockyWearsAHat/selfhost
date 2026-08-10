//! Joining two channels so a browser can drive a machine it has no link to.
//!
//! **Not implemented yet.** A documented placeholder for phase 9 of the build
//! plan, for the reasons [`crate::dial`] gives.
//!
//! # What it will do, and what it must refuse to do
//!
//! When the console asks for a desktop on a peer, the owner ends up holding two
//! channels: one to the browser and one on the worker's link. A splice joins them.
//!
//! The whole design of [`crate::mux`] exists to make that join trivial and safe:
//! the owner rewrites **only the two-byte channel id** in each frame's header and
//! forwards the payload untouched. Nothing is re-encoded, nothing is buffered
//! beyond a single frame, and — the property that matters most — **the daemon
//! never parses a byte a hostile peer chose**. Under `panic = "abort"` a parser in
//! this process is a way to take down the reverse proxy, the DNS server, the mail
//! server and the self-updater at a moment of the attacker's choosing. See the
//! [`crate::mux`] module documentation, which is where that argument is made in
//! full; this module is the place where breaking it would be most tempting.
//!
//! `CREDIT` frames are forwarded too, and this is the second load-bearing rule.
//! The splice must not invent credit of its own, because a middle box that grants
//! credit it cannot honour becomes the queue: backpressure has to run end-to-end
//! from the browser, through the owner, to the worker's capture loop, or the
//! owner's memory absorbs the difference between how fast a screen changes and
//! how fast a link can carry it. [`crate::credit`] holds the accounting the
//! forwarding will be checked against.

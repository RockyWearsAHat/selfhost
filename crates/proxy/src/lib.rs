//! The proxy: TLS termination, static serving, reverse proxying, and
//! health-checked load balancing.
//!
//! Written here rather than delegated to an external server binary. The reason
//! is not purity: an external binary brings its own release cadence, platform
//! matrix, and download-and-verify layer, and on Windows and macOS a container
//! runtime additionally demands a logged-in desktop session — disqualifying for
//! a machine whose job is to stay up unattended.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod upstream;

pub use upstream::{Lease, Pool, Upstream};

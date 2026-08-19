//! The house: every controllable device on the local network, held in one
//! state, driven through one loopback API.
//!
//! # The problem
//!
//! A household's devices do not agree on anything. A Sonos speaker answers
//! UPnP/SOAP on port 1400 and pushes its own state changes; a Fire TV answers
//! a binary protocol on 5555 and only if somebody enabled it on the device; a
//! Wyze bulb answers nothing at all on the local network and must be reached
//! through a company's servers. The one thing a person wants — a page that
//! shows the house and drives it — has to survive all three, and survive one
//! of them being unplugged.
//!
//! So the model here is **capabilities, not brands**. A device advertises what
//! it can be asked to do; the interface renders those and nothing else; a
//! driver's job is to turn one protocol into that vocabulary. A bulb bought
//! next year adds a driver and no page change, and a device that goes away
//! stops advertising rather than throwing.
//!
//! # Modules
//!
//! | Module | Pure? | What it is the authority on |
//! |---|---|---|
//! | [`xml`] | yes | reading what a UPnP device says, including doubly-escaped payloads |
//! | [`soap`] | yes | building a SOAP call and telling a fault from a result |
//! | [`color`] | yes | translating a screen colour into LED duty, calibrated by eye |
//! | [`device`] | yes | what a device is, what it can do, and what may be asked of it |
//! | [`registry`] | no | the names and rooms a person gave things, across restarts |
//! | [`sonos`] | mixed | the Sonos protocol: topology, transport, volume, events |
//! | [`wiz`] | mixed | the WiZ light protocol: JSON over UDP, discovery by broadcast |
//! | [`discovery`] | no | finding what is on the network, by SSDP and a debug-bridge probe |
//! | [`hub`] | no | the live state of the house, and the one place it is mutated |
//! | [`api`] | yes | the JSON shape the browser sees, and the command vocabulary |
//! | [`server`] | no | the loopback HTTP server the proxy forwards to |
//! | [`mcp`] | no | the same surface as MCP tools on stdio, for an agent |
//!
//! # What this crate never does
//!
//! It never binds a public interface. The server binds loopback and the
//! reverse proxy is the only thing in front of it, which is what keeps the
//! deployment's single-front-door rule intact — see `docs/SECURITY.md`. It
//! also never authenticates: the LAN gate on the site is the security model,
//! stated as such in `docs/labs/home-lab.dx`, and nothing here may be written
//! as though a caller reaching it has proved anything.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod api;
pub mod color;
pub mod device;
pub mod discovery;
pub mod hub;
pub mod mcp;
pub mod registry;
pub mod server;
pub mod soap;
pub mod sonos;
pub mod wiz;
pub mod xml;

pub use device::{Capability, Command, Device, DeviceId, Key, Kind, Power, State, Transport};
pub use hub::Hub;
pub use registry::Registry;
pub use server::serve;

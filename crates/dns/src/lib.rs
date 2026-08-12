//! DNS: wire format and a stub resolver, written from RFC 1035.
//!
//! Shared by three parts of the platform, which is why it exists as its own
//! crate rather than living inside whichever one needed it first:
//!
//! - **`selfhost doctor`** — checking A, MX, TXT, PTR, NS, and blocklists.
//! - **Direct mail delivery** — MX lookup for the recipient's domain.
//! - **The authoritative server** — the same encoding, in the other direction.
//!
//! Two details here cause more confusion than the rest of the protocol
//! combined, and both are handled explicitly:
//!
//! **Compression pointers can loop.** A name may end in a pointer to an earlier
//! offset, and a packet can point a name at itself. A decoder that follows
//! pointers naively spins forever on one packet. See [`wire::decode_response`].
//!
//! **Blocklists answer errors in the same address space as verdicts.** A reply
//! in `127.255.255.0/24` means the query was refused — often because it arrived
//! through a large public resolver, which Spamhaus rejects — not that the
//! address is listed. See [`resolver::is_real_listing`].

#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod authority;
pub mod resolver;
pub mod updater;
pub mod wire;
pub mod zone;

pub use authority::{Authority, DnsError};
pub use resolver::{
    ResolveError, Resolver, ResolverSource, blocklist_name, is_real_listing, reverse_name,
};
pub use updater::{ApexWriter, DEFAULT_INTERVAL, Movement, assess, next_serial, track_wan_ip};
pub use wire::{Record, RecordData, RecordType, Response, ResponseCode, WireError};
pub use zone::{Soa, Zone, default_zone};

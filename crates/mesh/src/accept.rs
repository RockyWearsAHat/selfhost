//! The owner side of a link: admitting a worker that dialled in.
//!
//! **Not implemented yet.** A documented placeholder for phase 9 of the build
//! plan, for the reasons [`crate::dial`] gives. The decision logic it will need is
//! already written and tested: [`crate::enroll`] for the proof and the replay
//! ledger, [`crate::registry`] for whether the node is declared at all, and
//! [`crate::channel`] for the channel table it will hold once the link is up.
//!
//! # What it will do
//!
//! The owner's admin API answers the upgrade on `/api/mesh/link`, and this module
//! takes it from the 101 onward: read the link-control `OPEN` on channel 0, look
//! the node up in the registry, verify the proof constant-time against that node's
//! token, admit the handshake through the replay ledger, and mark the peer linked.
//!
//! # The refusals, and how they are worded
//!
//! Every refusal on this path closes with **a bare code, one log line, and a
//! per-node failure counter**. Not a message telling the peer which check it
//! failed — an unenrolled node and a node with a stale token must be
//! indistinguishable from the outside, or the refusal becomes an oracle for
//! enumerating which names the owner knows.
//!
//! And the counter is **per node**, in [`crate::registry`], never the console's
//! global failure gate. Twenty failed peer attempts must not lock the operator out
//! of their own login door; that is the specific outcome the plan's verification
//! step checks for.

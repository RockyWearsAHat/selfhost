//! Close codes, close bodies, and the mapping from a refusal to a code.
//!
//! Closing is the only part of this protocol that is a *conversation*: either
//! side may start it, the other is expected to answer with a close of its own,
//! and only then does the TCP connection go away. That politeness is worth
//! keeping, because it is the difference between a console that says *the
//! session ended* and one that says *the connection dropped* — the same event to
//! a socket, and completely different information to the person reading it.
//!
//! # Why the code matters more than it looks
//!
//! Everything above this crate learns why a stream ended from the number in the
//! close frame. A parser refusal, a ceiling, and a peer that stopped answering
//! pings are three very different operational stories — a bug, an attack, and a
//! flaky link — and they arrive at the same place. [`code_for`] is the single
//! function that maps a [`ProtocolError`] to the code the peer will see, so the
//! mapping is one table that can be read in one sitting rather than a `1002`
//! written by hand at each of a dozen error sites, one of which will eventually
//! be wrong.
//!
//! # Why the reason is not validated as UTF-8
//!
//! RFC 6455 says a close reason is UTF-8. We refuse text frames precisely so that
//! no UTF-8 validator has to exist in this stack, and re-introducing one here for
//! a string that is only ever written to a log would give the peer a way to
//! escalate *bad text* into *closed connection with a different code* — for a
//! field that carries no meaning to us at all. So an incoming reason is converted
//! lossily, which cannot fail, and is treated as what it is: a hint from a
//! stranger, suitable for display beside the code and for nothing else.

use crate::frame::ProtocolError;

/// The largest reason a close frame may carry, in bytes.
///
/// A control frame's payload is capped at 125 bytes and the code takes two of
/// them, so 123 remain. Reasons we generate are truncated to fit rather than
/// refused, because a close that fails to send because its explanation was long
/// is the worst possible trade.
pub const MAX_REASON_BYTES: usize = 123;

/// A close code, as it appears on the wire.
///
/// The named variants are the ones this stack sends or expects to receive;
/// [`CloseCode::Other`] carries anything else the peer is entitled to send,
/// which includes the whole application range 4000–4999 that a future protocol
/// above this one may use for its own vocabulary.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CloseCode {
    /// 1000 — the purpose of the connection has been fulfilled.
    Normal,
    /// 1001 — the endpoint is going away (a page navigating, a server stopping).
    GoingAway,
    /// 1002 — a protocol error. The parser's verdict, in one number.
    ProtocolError,
    /// 1003 — data of a type this endpoint cannot accept, which for us means a
    /// text frame.
    UnacceptableData,
    /// 1008 — the message violated a policy. Reserved here for authorisation
    /// failures discovered mid-stream, which are policy and not framing.
    PolicyViolation,
    /// 1009 — a message was too large to process, which is our ceilings.
    MessageTooBig,
    /// 1011 — the server hit an unexpected condition. Ours, never the peer's.
    InternalError,
    /// Any other code the peer is permitted to send.
    Other(u16),
}

impl CloseCode {
    /// The numeric code.
    pub fn value(self) -> u16 {
        match self {
            Self::Normal => 1000,
            Self::GoingAway => 1001,
            Self::ProtocolError => 1002,
            Self::UnacceptableData => 1003,
            Self::PolicyViolation => 1008,
            Self::MessageTooBig => 1009,
            Self::InternalError => 1011,
            Self::Other(code) => code,
        }
    }

    /// Interprets a code received from a peer, refusing the ones that may not
    /// appear on the wire.
    ///
    /// Three of the reserved codes — 1005 *no status*, 1006 *abnormal closure*
    /// and 1015 *TLS failure* — are values an *implementation* reports to its own
    /// caller and that no endpoint may ever transmit. A peer that sends one is
    /// either buggy or deliberately trying to make our bookkeeping say something
    /// that did not happen, and either way the answer is the same: refuse it, and
    /// close with a protocol error. Everything below 1000 and the unassigned
    /// 1016–2999 band are refused for the same reason — a code we cannot mean is
    /// a code we should not record.
    pub fn from_wire(code: u16) -> Result<Self, ProtocolError> {
        match code {
            1000 => Ok(Self::Normal),
            1001 => Ok(Self::GoingAway),
            1002 => Ok(Self::ProtocolError),
            1003 => Ok(Self::UnacceptableData),
            1008 => Ok(Self::PolicyViolation),
            1009 => Ok(Self::MessageTooBig),
            1011 => Ok(Self::InternalError),
            1007 | 1010 | 1012..=1014 => Ok(Self::Other(code)),
            3000..=4999 => Ok(Self::Other(code)),
            other => Err(ProtocolError::ReservedCloseCode(other)),
        }
    }
}

/// A close frame's contents: why the peer is leaving, if it said.
///
/// `code` is `None` when the close frame carried no body at all, which is legal
/// and means *no status was given*. Modelling that as `None` rather than as the
/// reserved code 1005 keeps the reserved code unrepresentable, so no code path
/// can accidentally put it back on the wire.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CloseFrame {
    /// The code, if the peer sent one.
    pub code: Option<CloseCode>,
    /// The reason, lossily decoded and suitable only for display.
    pub reason: String,
}

impl CloseFrame {
    /// A close with a code and a reason.
    pub fn new(code: CloseCode, reason: impl Into<String>) -> Self {
        Self { code: Some(code), reason: reason.into() }
    }

    /// A close with no body, meaning no status was given.
    pub fn empty() -> Self {
        Self { code: None, reason: String::new() }
    }
}

/// Decodes the payload of a close frame.
///
/// The payload has already been bounded to 125 bytes by the frame parser's
/// control-frame rule, so the only lengths this must reason about are zero, one,
/// and two-or-more. One byte is refused: it is neither a code nor an absence, and
/// silently treating it as either would be a guess about a message that is
/// malformed by construction.
pub fn parse_body(payload: &[u8]) -> Result<CloseFrame, ProtocolError> {
    match payload {
        [] => Ok(CloseFrame::empty()),
        [_] => Err(ProtocolError::TruncatedCloseBody),
        [high, low, reason @ ..] => Ok(CloseFrame {
            code: Some(CloseCode::from_wire(u16::from_be_bytes([*high, *low]))?),
            reason: String::from_utf8_lossy(reason).into_owned(),
        }),
    }
}

/// Encodes a close frame's payload.
///
/// The reason is truncated to [`MAX_REASON_BYTES`] on a character boundary, so
/// the result is always a legal control payload and always still valid UTF-8 —
/// truncating a multi-byte character in half would produce exactly the malformed
/// text we refuse to send.
pub fn encode_body(code: CloseCode, reason: &str) -> Vec<u8> {
    let mut out = Vec::with_capacity(2 + reason.len().min(MAX_REASON_BYTES));
    out.extend_from_slice(&code.value().to_be_bytes());
    out.extend_from_slice(truncate_on_boundary(reason, MAX_REASON_BYTES).as_bytes());
    out
}

/// The longest prefix of `text` that fits in `limit` bytes without splitting a
/// character.
fn truncate_on_boundary(text: &str, limit: usize) -> &str {
    if text.len() <= limit {
        return text;
    }
    let mut end = limit;
    while end > 0 && !text.is_char_boundary(end) {
        end -= 1;
    }
    &text[..end]
}

/// The close code to send when a [`ProtocolError`] ends a stream.
///
/// The distinction the table draws is the one an operator cares about: *you sent
/// something I cannot parse* (1002), *you sent more than I will hold* (1009), and
/// *you sent a kind of data I do not accept* (1003). Anything a peer could not
/// have caused reports 1011, because blaming the peer for our own bug makes the
/// log actively misleading.
///
/// [`ProtocolError::Incomplete`] maps to 1011 and is expected never to reach
/// here: it is not a failure but a request for more bytes, and a caller that
/// treats it as fatal has a bug in its read loop. Mapping it rather than
/// panicking is the deliberate choice — under `panic = "abort"` a total function
/// that returns a slightly wrong number is infinitely preferable to one that
/// takes the box down to make a point.
pub fn code_for(error: &ProtocolError) -> CloseCode {
    match error {
        ProtocolError::TextFrame => CloseCode::UnacceptableData,
        ProtocolError::FrameTooLarge(_)
        | ProtocolError::MessageTooLarge(_)
        | ProtocolError::TooManyFragments(_)
        | ProtocolError::ControlFrameTooLarge(_) => CloseCode::MessageTooBig,
        ProtocolError::ReservedBitSet
        | ProtocolError::ReservedOpcode(_)
        | ProtocolError::UnmaskedClientFrame
        | ProtocolError::MaskedServerFrame
        | ProtocolError::FragmentedControlFrame
        | ProtocolError::NonMinimalLength
        | ProtocolError::LengthHighBitSet
        | ProtocolError::UnexpectedContinuation
        | ProtocolError::InterleavedDataFrame
        | ProtocolError::TruncatedCloseBody
        | ProtocolError::ReservedCloseCode(_) => CloseCode::ProtocolError,
        ProtocolError::ControlFrameNotAMessage | ProtocolError::Incomplete => CloseCode::InternalError,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_empty_body_means_no_status_was_given() {
        assert_eq!(parse_body(&[]).expect("parse"), CloseFrame::empty());
    }

    #[test]
    fn a_one_byte_body_is_refused() {
        assert_eq!(parse_body(&[0x03]), Err(ProtocolError::TruncatedCloseBody));
    }

    #[test]
    fn a_code_alone_parses_with_an_empty_reason() {
        let close = parse_body(&1000u16.to_be_bytes()).expect("parse");
        assert_eq!(close.code, Some(CloseCode::Normal));
        assert!(close.reason.is_empty());
    }

    #[test]
    fn a_code_and_reason_round_trip() {
        let body = encode_body(CloseCode::PolicyViolation, "not permitted");
        let close = parse_body(&body).expect("parse");
        assert_eq!(close.code, Some(CloseCode::PolicyViolation));
        assert_eq!(close.reason, "not permitted");
    }

    #[test]
    fn the_wire_reserved_codes_are_refused() {
        for code in [0u16, 999, 1004, 1005, 1006, 1015, 1016, 2999] {
            assert_eq!(
                parse_body(&code.to_be_bytes()),
                Err(ProtocolError::ReservedCloseCode(code)),
                "code {code} must not appear on the wire"
            );
        }
    }

    #[test]
    fn the_application_range_is_the_peers_to_use() {
        for code in [3000u16, 4000, 4999] {
            let close = parse_body(&code.to_be_bytes()).expect("parse");
            assert_eq!(close.code, Some(CloseCode::Other(code)));
        }
    }

    #[test]
    fn every_named_code_survives_a_wire_round_trip() {
        for code in [
            CloseCode::Normal,
            CloseCode::GoingAway,
            CloseCode::ProtocolError,
            CloseCode::UnacceptableData,
            CloseCode::PolicyViolation,
            CloseCode::MessageTooBig,
            CloseCode::InternalError,
        ] {
            assert_eq!(CloseCode::from_wire(code.value()), Ok(code));
        }
    }

    #[test]
    fn a_long_reason_is_truncated_to_a_legal_control_payload() {
        let body = encode_body(CloseCode::Normal, &"x".repeat(500));
        assert_eq!(body.len(), 2 + MAX_REASON_BYTES);
        assert!(body.len() <= 125, "a close body must fit a control frame");
    }

    #[test]
    fn truncation_never_splits_a_character() {
        // Each 'é' is two bytes, so 123 bytes lands mid-character.
        let reason = "é".repeat(200);
        let body = encode_body(CloseCode::Normal, &reason);
        let close = parse_body(&body).expect("parse");
        assert!(!close.reason.contains('\u{fffd}'), "no replacement characters");
        assert_eq!(close.reason.len(), 122, "the last whole character that fits");
    }

    #[test]
    fn a_reason_that_is_not_utf8_is_read_lossily_rather_than_refused() {
        let mut body = 1000u16.to_be_bytes().to_vec();
        body.extend_from_slice(&[0xff, 0xfe]);
        let close = parse_body(&body).expect("parse");
        assert!(close.reason.contains('\u{fffd}'));
    }

    #[test]
    fn refusals_map_to_the_code_that_explains_them() {
        use ProtocolError as E;
        assert_eq!(code_for(&E::TextFrame), CloseCode::UnacceptableData);
        assert_eq!(code_for(&E::ReservedBitSet), CloseCode::ProtocolError);
        assert_eq!(code_for(&E::LengthHighBitSet), CloseCode::ProtocolError);
        assert_eq!(code_for(&E::FrameTooLarge(1 << 30)), CloseCode::MessageTooBig);
        assert_eq!(code_for(&E::MessageTooLarge(1 << 30)), CloseCode::MessageTooBig);
        assert_eq!(code_for(&E::TooManyFragments(99)), CloseCode::MessageTooBig);
        assert_eq!(code_for(&E::ControlFrameNotAMessage), CloseCode::InternalError);
    }

    #[test]
    fn parse_body_never_panics_on_arbitrary_payloads() {
        // Control payloads are at most 125 bytes, so this is the whole space of
        // lengths, over a spread of byte patterns.
        for length in 0..=125usize {
            for fill in [0u8, 1, 0x7f, 0x80, 0xff] {
                let payload = vec![fill; length];
                let _ = parse_body(&payload);
            }
        }
    }
}

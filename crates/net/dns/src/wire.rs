//! DNS message encoding and decoding (RFC 1035 §4).
//!
//! Written from the specification rather than pulled from a resolver library,
//! because the same wire format is needed in three places: the diagnostics,
//! MX lookup for direct mail delivery, and eventually the authoritative server.
//!
//! The one genuinely tricky part is **name compression**. A name in a message
//! may end in a two-byte pointer to an earlier offset, so decoding a name means
//! jumping around the buffer. A malicious or corrupt message can point a name at
//! itself, and a decoder that follows pointers naively loops forever — which is
//! a denial of service triggered by a single packet. [`read_name`] bounds the
//! jumps and refuses backward-only pointers.

use std::fmt;
use std::net::{Ipv4Addr, Ipv6Addr};

/// Maximum length of an encoded domain name.
pub const MAX_NAME: usize = 255;
/// Maximum length of a single label.
pub const MAX_LABEL: usize = 63;
/// Ceiling on compression pointer jumps while decoding one name.
const MAX_JUMPS: usize = 16;

/// A resource record type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RecordType {
    /// IPv4 address.
    A,
    /// IPv6 address.
    Aaaa,
    /// Authoritative nameserver.
    Ns,
    /// Canonical name.
    Cname,
    /// Start of authority.
    Soa,
    /// Pointer, used for reverse lookups.
    Ptr,
    /// Mail exchanger.
    Mx,
    /// Text, which carries SPF, DKIM, DMARC, and DNSBL explanations.
    Txt,
    /// Service locator (RFC 2782) — how a mail client discovers the IMAP and
    /// submission servers for a domain (RFC 6186) without guessing hostnames.
    Srv,
    /// Certification authority authorisation.
    Caa,
    /// Any other type, kept numerically so unknown records survive a round trip.
    Other(u16),
}

impl RecordType {
    /// The numeric code used on the wire.
    pub fn code(self) -> u16 {
        match self {
            Self::A => 1,
            Self::Ns => 2,
            Self::Cname => 5,
            Self::Soa => 6,
            Self::Ptr => 12,
            Self::Mx => 15,
            Self::Txt => 16,
            Self::Aaaa => 28,
            Self::Srv => 33,
            Self::Caa => 257,
            Self::Other(code) => code,
        }
    }

    /// Interprets a numeric type code.
    pub fn from_code(code: u16) -> Self {
        match code {
            1 => Self::A,
            2 => Self::Ns,
            5 => Self::Cname,
            6 => Self::Soa,
            12 => Self::Ptr,
            15 => Self::Mx,
            16 => Self::Txt,
            28 => Self::Aaaa,
            33 => Self::Srv,
            257 => Self::Caa,
            other => Self::Other(other),
        }
    }
}

impl fmt::Display for RecordType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::A => write!(f, "A"),
            Self::Aaaa => write!(f, "AAAA"),
            Self::Ns => write!(f, "NS"),
            Self::Cname => write!(f, "CNAME"),
            Self::Soa => write!(f, "SOA"),
            Self::Ptr => write!(f, "PTR"),
            Self::Mx => write!(f, "MX"),
            Self::Txt => write!(f, "TXT"),
            Self::Srv => write!(f, "SRV"),
            Self::Caa => write!(f, "CAA"),
            Self::Other(code) => write!(f, "TYPE{code}"),
        }
    }
}

/// The response code from a server.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResponseCode {
    /// Success.
    NoError,
    /// The query was malformed.
    FormatError,
    /// The server failed.
    ServerFailure,
    /// The name does not exist. Distinct from "exists but has no such record".
    NameError,
    /// The server does not support the requested operation.
    NotImplemented,
    /// The server refused to answer.
    Refused,
    /// Any other code.
    Other(u8),
}

impl ResponseCode {
    /// Interprets the four-bit RCODE field.
    pub fn from_bits(bits: u8) -> Self {
        match bits {
            0 => Self::NoError,
            1 => Self::FormatError,
            2 => Self::ServerFailure,
            3 => Self::NameError,
            4 => Self::NotImplemented,
            5 => Self::Refused,
            other => Self::Other(other),
        }
    }

    /// The four-bit RCODE field this code writes into a response header — the
    /// reverse of [`from_bits`](Self::from_bits), needed by the authoritative
    /// encoder. An `Other` code is masked to its low four bits.
    pub fn to_bits(self) -> u8 {
        match self {
            Self::NoError => 0,
            Self::FormatError => 1,
            Self::ServerFailure => 2,
            Self::NameError => 3,
            Self::NotImplemented => 4,
            Self::Refused => 5,
            Self::Other(code) => code & 0x0F,
        }
    }
}

impl fmt::Display for ResponseCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoError => write!(f, "NOERROR"),
            Self::FormatError => write!(f, "FORMERR"),
            Self::ServerFailure => write!(f, "SERVFAIL"),
            Self::NameError => write!(f, "NXDOMAIN"),
            Self::NotImplemented => write!(f, "NOTIMP"),
            Self::Refused => write!(f, "REFUSED"),
            Self::Other(code) => write!(f, "RCODE{code}"),
        }
    }
}

/// The decoded payload of a resource record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RecordData {
    /// An IPv4 address.
    A(Ipv4Addr),
    /// An IPv6 address.
    Aaaa(Ipv6Addr),
    /// A domain name, for `NS`, `CNAME`, and `PTR`.
    Name(String),
    /// A mail exchanger and its preference. Lower preference is tried first.
    Mx {
        /// Preference value.
        preference: u16,
        /// Exchange hostname.
        exchange: String,
    },
    /// Text strings, joined. `TXT` records arrive as length-prefixed chunks and
    /// a long SPF or DKIM value is split across several — joining them is
    /// required, not cosmetic.
    Txt(String),
    /// Start of authority. Names who runs a zone, which is how you find out who
    /// to ask about a reverse-DNS record you cannot change yourself.
    ///
    /// The numeric fields matter only when this record is *served* rather than
    /// merely read for its contact: an authoritative SOA answer, the authority
    /// section of an NXDOMAIN, and an AXFR all carry the serial and the timers on
    /// the wire. The stub resolver ignores them, but they must survive a decode so
    /// the authoritative server can re-emit them and the updater can bump `serial`.
    Soa {
        /// Primary nameserver for the zone.
        primary: String,
        /// Responsible party, in DNS form — the first label is the local part
        /// of an email address, so `ipadmin.example.com` means
        /// `ipadmin@example.com`.
        responsible: String,
        /// Version number of the zone, bumped on every change so a secondary
        /// knows to re-transfer. The updater only ever increases it.
        serial: u32,
        /// Seconds a secondary waits before checking for a new `serial`.
        refresh: u32,
        /// Seconds a secondary waits before retrying a failed refresh.
        retry: u32,
        /// Seconds a secondary keeps serving the zone with no successful refresh
        /// before it stops answering for it.
        expire: u32,
        /// Also the negative-caching TTL: how long a resolver may remember that a
        /// name in this zone does not exist.
        minimum: u32,
    },
    /// A service locator (RFC 2782): which host and port carry a service for
    /// this name. Served for `_imaps._tcp` and `_submission._tcp` (RFC 6186) and
    /// `_submissions._tcp` (RFC 8314) so a mail client discovers its servers
    /// instead of guessing hostnames.
    Srv {
        /// Lower values are tried first.
        priority: u16,
        /// Relative weight among records of equal priority.
        weight: u16,
        /// The port the service listens on.
        port: u16,
        /// The host providing the service. Never compressed on the wire (RFC 2782).
        target: String,
    },
    /// A record type this decoder does not interpret.
    Unknown {
        /// The record type.
        record_type: RecordType,
        /// The raw payload.
        data: Vec<u8>,
    },
}

/// One resource record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Record {
    /// The owner name.
    pub name: String,
    /// Seconds this record may be cached.
    pub ttl: u32,
    /// The decoded payload.
    pub data: RecordData,
}

/// A decoded response.
#[derive(Debug, Clone)]
pub struct Response {
    /// Result code from the server.
    pub code: ResponseCode,
    /// Records answering the question.
    pub answers: Vec<Record>,
    /// Records delegating or describing authority.
    pub authority: Vec<Record>,
    /// Additional records — the glue addresses a referral carries for the
    /// nameservers it names. Read by the delegation checker, which must see the
    /// parent's glue to verify it points at this machine.
    pub additional: Vec<Record>,
}

impl Response {
    /// Every answer of a given type, with `CNAME` chains ignored.
    pub fn records_of(&self, record_type: RecordType) -> Vec<&RecordData> {
        self.answers
            .iter()
            .filter(|record| data_type(&record.data) == record_type)
            .map(|record| &record.data)
            .collect()
    }

    /// The first IPv4 address in the answer, if any.
    pub fn first_a(&self) -> Option<Ipv4Addr> {
        self.answers.iter().find_map(|record| match record.data {
            RecordData::A(address) => Some(address),
            _ => None,
        })
    }

    /// Every text record, joined per record.
    pub fn texts(&self) -> Vec<String> {
        self.answers
            .iter()
            .filter_map(|record| match &record.data {
                RecordData::Txt(text) => Some(text.clone()),
                _ => None,
            })
            .collect()
    }

    /// Mail exchangers, sorted by preference — the order they should be tried.
    pub fn mail_exchangers(&self) -> Vec<(u16, String)> {
        let mut hosts: Vec<(u16, String)> = self
            .answers
            .iter()
            .filter_map(|record| match &record.data {
                RecordData::Mx { preference, exchange } => Some((*preference, exchange.clone())),
                _ => None,
            })
            .collect();
        hosts.sort_by_key(|(preference, _)| *preference);
        hosts
    }

    /// The zone's responsible-party address, from an `SOA` in either section.
    ///
    /// Looked for in the authority section as well as the answer, because a
    /// query for a name that does not exist still returns the enclosing zone's
    /// `SOA` there — which is exactly the case when asking who runs a reverse
    /// zone you have no records in.
    pub fn soa_contact(&self) -> Option<String> {
        self.answers
            .iter()
            .chain(self.authority.iter())
            .find_map(|record| match &record.data {
                RecordData::Soa { responsible, .. } => Some(email_from_rname(responsible)),
                _ => None,
            })
    }

    /// Domain names in the answer, for `NS`, `PTR`, and `CNAME` queries.
    pub fn names(&self) -> Vec<String> {
        self.answers
            .iter()
            .filter_map(|record| match &record.data {
                RecordData::Name(name) => Some(name.clone()),
                _ => None,
            })
            .collect()
    }
}

/// Converts a DNS responsible-party name into an email address.
///
/// The first label is the local part, so `ipadmin.firstdigital.com` means
/// `ipadmin@firstdigital.com`. An escaped dot (`\\.`) inside the local part is
/// literal, which is why this splits on the first *unescaped* separator rather
/// than the first character.
pub fn email_from_rname(rname: &str) -> String {
    let bytes = rname.as_bytes();
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'\\' {
            index += 2;
            continue;
        }
        if bytes[index] == b'.' {
            let local = rname[..index].replace("\\.", ".");
            return format!("{local}@{}", &rname[index + 1..]);
        }
        index += 1;
    }
    rname.to_owned()
}

/// The record type a payload corresponds to.
fn data_type(data: &RecordData) -> RecordType {
    match data {
        RecordData::A(_) => RecordType::A,
        RecordData::Aaaa(_) => RecordType::Aaaa,
        RecordData::Name(_) => RecordType::Cname,
        RecordData::Mx { .. } => RecordType::Mx,
        RecordData::Txt(_) => RecordType::Txt,
        RecordData::Soa { .. } => RecordType::Soa,
        RecordData::Srv { .. } => RecordType::Srv,
        RecordData::Unknown { record_type, .. } => *record_type,
    }
}

/// Why a message could not be decoded.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WireError {
    /// The buffer ended mid-structure.
    Truncated,
    /// A name exceeded [`MAX_NAME`] or a label exceeded [`MAX_LABEL`].
    NameTooLong,
    /// Compression pointers looped or nested too deeply.
    CompressionLoop,
    /// A name contained bytes that are not valid UTF-8.
    BadName,
}

impl fmt::Display for WireError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Truncated => write!(f, "message ended unexpectedly"),
            Self::NameTooLong => write!(f, "encoded name exceeds the maximum length"),
            Self::CompressionLoop => write!(f, "compression pointers loop"),
            Self::BadName => write!(f, "name is not valid UTF-8"),
        }
    }
}

impl std::error::Error for WireError {}

/// Encodes a query message.
///
/// The recursion-desired bit is set because this is a stub resolver: it asks a
/// full resolver to do the work rather than walking the delegation chain itself.
pub fn encode_query(id: u16, name: &str, record_type: RecordType) -> Result<Vec<u8>, WireError> {
    let mut out = Vec::with_capacity(64);
    out.extend_from_slice(&id.to_be_bytes());
    // QR=0 OPCODE=0 AA=0 TC=0 RD=1, then RA=0 Z=0 RCODE=0.
    out.extend_from_slice(&[0x01, 0x00]);
    out.extend_from_slice(&1_u16.to_be_bytes()); // one question
    out.extend_from_slice(&[0, 0, 0, 0, 0, 0]); // no answer, authority, additional

    write_name(&mut out, name)?;
    out.extend_from_slice(&record_type.code().to_be_bytes());
    out.extend_from_slice(&1_u16.to_be_bytes()); // class IN

    Ok(out)
}

/// Writes a domain name in label form.
fn write_name(out: &mut Vec<u8>, name: &str) -> Result<(), WireError> {
    let trimmed = name.trim_end_matches('.');
    if !trimmed.is_empty() {
        if trimmed.len() > MAX_NAME {
            return Err(WireError::NameTooLong);
        }
        for label in trimmed.split('.') {
            if label.is_empty() || label.len() > MAX_LABEL {
                return Err(WireError::NameTooLong);
            }
            out.push(label.len() as u8);
            out.extend_from_slice(label.as_bytes());
        }
    }
    out.push(0);
    Ok(())
}

/// Reads a name, following compression pointers safely.
///
/// Returns the name and the offset just past the name *in the original stream* —
/// which is not where decoding finished if a pointer was followed.
fn read_name(buffer: &[u8], start: usize) -> Result<(String, usize), WireError> {
    let mut labels: Vec<String> = Vec::new();
    let mut position = start;
    let mut jumps = 0;
    let mut after_pointer: Option<usize> = None;
    let mut total = 0;

    loop {
        let length = *buffer.get(position).ok_or(WireError::Truncated)?;

        // The top two bits mark a compression pointer.
        if length & 0xC0 == 0xC0 {
            let second = *buffer.get(position + 1).ok_or(WireError::Truncated)?;
            let target = (((length & 0x3F) as usize) << 8) | second as usize;

            // A pointer must go backwards. Allowing a forward or self-referential
            // pointer is what lets one packet spin a decoder forever.
            if target >= position {
                return Err(WireError::CompressionLoop);
            }
            jumps += 1;
            if jumps > MAX_JUMPS {
                return Err(WireError::CompressionLoop);
            }
            after_pointer.get_or_insert(position + 2);
            position = target;
            continue;
        }

        if length == 0 {
            position += 1;
            break;
        }

        if length as usize > MAX_LABEL {
            return Err(WireError::NameTooLong);
        }
        total += length as usize + 1;
        if total > MAX_NAME {
            return Err(WireError::NameTooLong);
        }

        let from = position + 1;
        let to = from + length as usize;
        let bytes = buffer.get(from..to).ok_or(WireError::Truncated)?;
        labels.push(String::from_utf8(bytes.to_vec()).map_err(|_| WireError::BadName)?);
        position = to;
    }

    Ok((labels.join("."), after_pointer.unwrap_or(position)))
}

/// Reads the question a message is asking, without decoding the rest of it.
///
/// Exists for the forwarding side of DNS rather than the resolving side: a
/// server that relays a query onward still needs to know what was asked, and
/// decoding the whole message to find out would mean parsing attacker-supplied
/// records it has no reason to look at.
///
/// Returns `None` for a message carrying no question, which is malformed for a
/// query but not worth an error — it is forwarded unchanged either way.
pub fn question_of(buffer: &[u8]) -> Result<Option<(String, RecordType)>, WireError> {
    if buffer.len() < 12 {
        return Err(WireError::Truncated);
    }
    if u16::from_be_bytes([buffer[4], buffer[5]]) == 0 {
        return Ok(None);
    }

    let (name, next) = read_name(buffer, 12)?;
    let record_type = buffer
        .get(next..next + 2)
        .map(|bytes| RecordType::from_code(u16::from_be_bytes([bytes[0], bytes[1]])))
        .ok_or(WireError::Truncated)?;
    Ok(Some((name, record_type)))
}

/// Decodes a response message.
pub fn decode_response(buffer: &[u8]) -> Result<Response, WireError> {
    if buffer.len() < 12 {
        return Err(WireError::Truncated);
    }

    let code = ResponseCode::from_bits(buffer[3] & 0x0F);
    let questions = u16::from_be_bytes([buffer[4], buffer[5]]);
    let answer_count = u16::from_be_bytes([buffer[6], buffer[7]]);
    let authority_count = u16::from_be_bytes([buffer[8], buffer[9]]);
    let additional_count = u16::from_be_bytes([buffer[10], buffer[11]]);

    let mut position = 12;
    for _ in 0..questions {
        let (_, next) = read_name(buffer, position)?;
        // Skip QTYPE and QCLASS.
        position = next + 4;
    }

    let mut answers = Vec::with_capacity(answer_count as usize);
    for _ in 0..answer_count {
        let (record, next) = read_record(buffer, position)?;
        answers.push(record);
        position = next;
    }

    let mut authority = Vec::with_capacity(authority_count as usize);
    for _ in 0..authority_count {
        match read_record(buffer, position) {
            Ok((record, next)) => {
                authority.push(record);
                position = next;
            }
            // The authority section is informational here; a malformed one must
            // not discard answers that already decoded cleanly.
            Err(_) => return Ok(Response { code, answers, authority, additional: Vec::new() }),
        }
    }

    // Same posture as authority: additional records (a referral's glue) are
    // informational, so a malformed tail keeps what decoded cleanly. An OPT
    // pseudo-record (EDNS0, type 41) lands here too and is simply carried.
    let mut additional = Vec::with_capacity(additional_count as usize);
    for _ in 0..additional_count {
        match read_record(buffer, position) {
            Ok((record, next)) => {
                additional.push(record);
                position = next;
            }
            Err(_) => break,
        }
    }

    Ok(Response { code, answers, authority, additional })
}

/// Reads one resource record.
fn read_record(buffer: &[u8], start: usize) -> Result<(Record, usize), WireError> {
    let (name, mut position) = read_name(buffer, start)?;

    let header = buffer.get(position..position + 10).ok_or(WireError::Truncated)?;
    let record_type = RecordType::from_code(u16::from_be_bytes([header[0], header[1]]));
    let ttl = u32::from_be_bytes([header[4], header[5], header[6], header[7]]);
    let length = u16::from_be_bytes([header[8], header[9]]) as usize;
    position += 10;

    let payload = buffer.get(position..position + length).ok_or(WireError::Truncated)?;
    let end = position + length;

    let data = match record_type {
        RecordType::A if length == 4 => {
            RecordData::A(Ipv4Addr::new(payload[0], payload[1], payload[2], payload[3]))
        }
        RecordType::Aaaa if length == 16 => {
            let mut octets = [0_u8; 16];
            octets.copy_from_slice(payload);
            RecordData::Aaaa(Ipv6Addr::from(octets))
        }
        RecordType::Ns | RecordType::Cname | RecordType::Ptr => {
            RecordData::Name(read_name(buffer, position)?.0)
        }
        RecordType::Soa if length >= 2 => {
            let (primary, next) = read_name(buffer, position)?;
            let (responsible, after) = read_name(buffer, next)?;
            // The two names are followed by five 32-bit fields. A message that
            // stops short of them is truncated rather than a zero-timer zone.
            let nums = buffer.get(after..after + 20).ok_or(WireError::Truncated)?;
            RecordData::Soa {
                primary,
                responsible,
                serial: u32::from_be_bytes([nums[0], nums[1], nums[2], nums[3]]),
                refresh: u32::from_be_bytes([nums[4], nums[5], nums[6], nums[7]]),
                retry: u32::from_be_bytes([nums[8], nums[9], nums[10], nums[11]]),
                expire: u32::from_be_bytes([nums[12], nums[13], nums[14], nums[15]]),
                minimum: u32::from_be_bytes([nums[16], nums[17], nums[18], nums[19]]),
            }
        }
        RecordType::Mx if length >= 3 => {
            let preference = u16::from_be_bytes([payload[0], payload[1]]);
            let exchange = read_name(buffer, position + 2)?.0;
            RecordData::Mx { preference, exchange }
        }
        RecordType::Srv if length >= 7 => {
            let target = read_name(buffer, position + 6)?.0;
            RecordData::Srv {
                priority: u16::from_be_bytes([payload[0], payload[1]]),
                weight: u16::from_be_bytes([payload[2], payload[3]]),
                port: u16::from_be_bytes([payload[4], payload[5]]),
                target,
            }
        }
        RecordType::Txt => {
            // TXT arrives as length-prefixed chunks; a long SPF or DKIM value is
            // split across several and must be rejoined to be meaningful.
            let mut text = String::new();
            let mut cursor = 0;
            while cursor < payload.len() {
                let chunk = payload[cursor] as usize;
                cursor += 1;
                let Some(bytes) = payload.get(cursor..cursor + chunk) else { break };
                text.push_str(&String::from_utf8_lossy(bytes));
                cursor += chunk;
            }
            RecordData::Txt(text)
        }
        other => RecordData::Unknown { record_type: other, data: payload.to_vec() },
    };

    Ok((Record { name, ttl, data }, end))
}

/// A decoded inbound query: the fields an authoritative server must echo and
/// honour.
///
/// The stub-resolver path decodes *responses* (see [`decode_response`]); an
/// authoritative server decodes the *question* a client asks and echoes its id,
/// name, and RD bit back. [`question_of`] drops the id and flags; this keeps
/// them because a reply that does not echo the id cannot be matched to its query.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Query {
    /// Message id, echoed verbatim in the response.
    pub id: u16,
    /// The single question's owner name (no trailing dot).
    pub name: String,
    /// The question's type.
    pub record_type: RecordType,
    /// Whether the client set RD. An authoritative-only server does not recurse,
    /// but it echoes RD per RFC 1035 §4.1.1.
    pub recursion_desired: bool,
}

/// Decodes the header and first question of an inbound query.
///
/// Rejects a message with no question ([`WireError::Truncated`]) rather than
/// guessing — an authoritative server answers a question or it answers nothing.
pub fn decode_query(buffer: &[u8]) -> Result<Query, WireError> {
    if buffer.len() < 12 {
        return Err(WireError::Truncated);
    }
    if u16::from_be_bytes([buffer[4], buffer[5]]) == 0 {
        return Err(WireError::Truncated);
    }
    let id = u16::from_be_bytes([buffer[0], buffer[1]]);
    // RD is the low bit of the first flags byte.
    let recursion_desired = buffer[2] & 0x01 != 0;

    let (name, next) = read_name(buffer, 12)?;
    let record_type = buffer
        .get(next..next + 2)
        .map(|bytes| RecordType::from_code(u16::from_be_bytes([bytes[0], bytes[1]])))
        .ok_or(WireError::Truncated)?;
    Ok(Query { id, name, record_type, recursion_desired })
}

/// How an authoritative response is framed.
///
/// Kept as two named intents rather than a raw bitfield so a caller states what
/// it means (`authoritative`, `truncated`) instead of remembering which header
/// bit is which.
#[derive(Debug, Clone, Copy)]
pub struct ResponseFlags {
    /// Sets AA. True whenever the answer comes from a zone this server owns.
    pub authoritative: bool,
    /// Sets TC. Set when a UDP answer was cut to fit; tells the client to retry
    /// over TCP.
    pub truncated: bool,
}

/// Builds a response message for `query`: echoes the question, sets QR=1, applies
/// `flags` and `code`, and serialises the record sections.
///
/// Names are written uncompressed — RFC 1035 §4.1.4 makes compression optional
/// on write, so the encoder is a straight walk with no offset bookkeeping, and
/// [`read_name`] already tolerates both forms on the way back in.
pub fn encode_response(
    query: &Query,
    code: ResponseCode,
    flags: ResponseFlags,
    answers: &[Record],
    authority: &[Record],
    additional: &[Record],
) -> Vec<u8> {
    let mut out = Vec::with_capacity(128);
    out.extend_from_slice(&query.id.to_be_bytes());

    // Flags byte 1: QR=1, OPCODE=0, then AA, TC, and the echoed RD.
    let mut flags_high = 0x80;
    if flags.authoritative {
        flags_high |= 0x04;
    }
    if flags.truncated {
        flags_high |= 0x02;
    }
    if query.recursion_desired {
        flags_high |= 0x01;
    }
    out.push(flags_high);
    // Flags byte 2: RA=0, Z=0, then RCODE.
    out.push(code.to_bits() & 0x0F);

    out.extend_from_slice(&1_u16.to_be_bytes()); // the one question, echoed
    out.extend_from_slice(&(answers.len() as u16).to_be_bytes());
    out.extend_from_slice(&(authority.len() as u16).to_be_bytes());
    out.extend_from_slice(&(additional.len() as u16).to_be_bytes());

    // The question, uncompressed: name, QTYPE, QCLASS=IN.
    let _ = write_name(&mut out, &query.name);
    out.extend_from_slice(&query.record_type.code().to_be_bytes());
    out.extend_from_slice(&1_u16.to_be_bytes());

    // A served `RecordData::Name` is either a CNAME or an NS, and the payload
    // alone cannot say which. The section and the question resolve it: in the
    // answer section a `Name` is a CNAME (the alias chase) unless the client
    // asked for NS; in the authority and additional sections a `Name` is always
    // an NS RRset. Getting this wrong makes a resolver reject the delegation.
    let answer_name_type =
        if query.record_type == RecordType::Ns { RecordType::Ns } else { RecordType::Cname };
    for record in answers {
        write_record(&mut out, record, answer_name_type);
    }
    for record in authority.iter().chain(additional) {
        write_record(&mut out, record, RecordType::Ns);
    }
    out
}

/// Writes one resource record: owner name, type, class IN, ttl, then the rdata
/// framed by its two-byte length. `name_type` disambiguates a
/// [`RecordData::Name`] payload (CNAME vs NS); it is ignored for every other
/// payload, whose type is unambiguous.
fn write_record(out: &mut Vec<u8>, record: &Record, name_type: RecordType) {
    let wire_type = match &record.data {
        RecordData::Name(_) => name_type,
        other => record_type_of(other),
    };
    let _ = write_name(out, &record.name);
    out.extend_from_slice(&wire_type.code().to_be_bytes());
    out.extend_from_slice(&1_u16.to_be_bytes()); // class IN
    out.extend_from_slice(&record.ttl.to_be_bytes());

    // RDLENGTH is only known after the rdata is written, so reserve it and fill
    // it in once the payload length is measured.
    let length_at = out.len();
    out.extend_from_slice(&[0, 0]);
    let start = out.len();
    write_rdata(out, &record.data);
    let length = (out.len() - start) as u16;
    out[length_at..length_at + 2].copy_from_slice(&length.to_be_bytes());
}

/// Writes the rdata payload for one record.
fn write_rdata(out: &mut Vec<u8>, data: &RecordData) {
    match data {
        RecordData::A(address) => out.extend_from_slice(&address.octets()),
        RecordData::Aaaa(address) => out.extend_from_slice(&address.octets()),
        RecordData::Name(name) => {
            let _ = write_name(out, name);
        }
        RecordData::Mx { preference, exchange } => {
            out.extend_from_slice(&preference.to_be_bytes());
            let _ = write_name(out, exchange);
        }
        RecordData::Txt(text) => {
            // TXT on the wire is a run of length-prefixed chunks, each at most
            // 255 bytes — the inverse of how `read_record` rejoins them.
            for chunk in text.as_bytes().chunks(u8::MAX as usize) {
                out.push(chunk.len() as u8);
                out.extend_from_slice(chunk);
            }
        }
        RecordData::Soa { primary, responsible, serial, refresh, retry, expire, minimum } => {
            let _ = write_name(out, primary);
            let _ = write_name(out, responsible);
            out.extend_from_slice(&serial.to_be_bytes());
            out.extend_from_slice(&refresh.to_be_bytes());
            out.extend_from_slice(&retry.to_be_bytes());
            out.extend_from_slice(&expire.to_be_bytes());
            out.extend_from_slice(&minimum.to_be_bytes());
        }
        RecordData::Srv { priority, weight, port, target } => {
            out.extend_from_slice(&priority.to_be_bytes());
            out.extend_from_slice(&weight.to_be_bytes());
            out.extend_from_slice(&port.to_be_bytes());
            let _ = write_name(out, target);
        }
        RecordData::Unknown { data, .. } => out.extend_from_slice(data),
    }
}

/// The wire type code for an unambiguous payload. A [`RecordData::Name`] is
/// resolved by the caller (see [`write_record`]) since it may be CNAME or NS;
/// the arm here is a safe fallback only.
fn record_type_of(data: &RecordData) -> RecordType {
    match data {
        RecordData::A(_) => RecordType::A,
        RecordData::Aaaa(_) => RecordType::Aaaa,
        RecordData::Name(_) => RecordType::Cname,
        RecordData::Mx { .. } => RecordType::Mx,
        RecordData::Txt(_) => RecordType::Txt,
        RecordData::Soa { .. } => RecordType::Soa,
        RecordData::Srv { .. } => RecordType::Srv,
        RecordData::Unknown { record_type, .. } => *record_type,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encodes_a_query() {
        let query = encode_query(0x1234, "example.com", RecordType::A).unwrap();
        assert_eq!(&query[0..2], &[0x12, 0x34], "id");
        assert_eq!(&query[2..4], &[0x01, 0x00], "recursion desired");
        assert_eq!(&query[4..6], &[0x00, 0x01], "one question");
        // 7"example" 3"com" 0
        assert_eq!(&query[12..], b"\x07example\x03com\x00\x00\x01\x00\x01");
    }

    #[test]
    fn reads_the_question_out_of_a_query() {
        // What a forwarding resolver needs: the name asked, without decoding
        // records it has no reason to look at.
        let query = encode_query(0x1234, "pawns.app", RecordType::A).unwrap();
        assert_eq!(
            question_of(&query).unwrap(),
            Some(("pawns.app".to_owned(), RecordType::A))
        );
    }

    #[test]
    fn a_message_with_no_question_is_not_an_error() {
        // Malformed for a query, but a forwarder passes it on either way, so
        // failing here would turn a curiosity into an outage.
        let mut header = vec![0_u8; 12];
        header[0] = 0xab;
        assert_eq!(question_of(&header).unwrap(), None);
    }

    #[test]
    fn a_truncated_question_is_refused_rather_than_guessed() {
        let query = encode_query(1, "example.com", RecordType::A).unwrap();
        // Cut the type off the end: the name reads, the type cannot.
        assert!(matches!(question_of(&query[..query.len() - 3]), Err(WireError::Truncated)));
        assert!(matches!(question_of(&[0, 1, 2]), Err(WireError::Truncated)));
    }

    #[test]
    fn encodes_a_trailing_dot_the_same_as_without() {
        let with = encode_query(1, "example.com.", RecordType::A).unwrap();
        let without = encode_query(1, "example.com", RecordType::A).unwrap();
        assert_eq!(with, without);
    }

    #[test]
    fn rejects_oversized_labels() {
        let long = "a".repeat(MAX_LABEL + 1);
        assert_eq!(
            encode_query(1, &format!("{long}.com"), RecordType::A).unwrap_err(),
            WireError::NameTooLong
        );
    }

    /// Builds a response: header, one question, then the given answer bytes.
    fn response_with(answers: u16, question: &[u8], body: &[u8]) -> Vec<u8> {
        let mut message = vec![0x12, 0x34, 0x81, 0x80];
        message.extend_from_slice(&1_u16.to_be_bytes());
        message.extend_from_slice(&answers.to_be_bytes());
        message.extend_from_slice(&[0, 0, 0, 0]);
        message.extend_from_slice(question);
        message.extend_from_slice(&[0, 1, 0, 1]);
        message.extend_from_slice(body);
        message
    }

    #[test]
    fn decodes_an_a_record() {
        let body = b"\xc0\x0c\x00\x01\x00\x01\x00\x00\x01\x2c\x00\x04\x5d\xb8\xd8\x22";
        let message = response_with(1, b"\x07example\x03com\x00", body);

        let response = decode_response(&message).unwrap();
        assert_eq!(response.code, ResponseCode::NoError);
        assert_eq!(response.first_a(), Some(Ipv4Addr::new(93, 184, 216, 34)));
        assert_eq!(response.answers[0].ttl, 300);
        // The compression pointer resolved to the question's name.
        assert_eq!(response.answers[0].name, "example.com");
    }

    #[test]
    fn decodes_mx_records_in_preference_order() {
        let mut body = Vec::new();
        for (preference, host) in [(20_u16, b"\x03alt\x00".as_slice()), (10, b"\x04main\x00")] {
            body.extend_from_slice(b"\xc0\x0c\x00\x0f\x00\x01\x00\x00\x01\x2c");
            body.extend_from_slice(&((2 + host.len()) as u16).to_be_bytes());
            body.extend_from_slice(&preference.to_be_bytes());
            body.extend_from_slice(host);
        }
        let message = response_with(2, b"\x07example\x03com\x00", &body);

        let response = decode_response(&message).unwrap();
        // Lower preference is tried first, so sorting is behaviour, not polish.
        assert_eq!(
            response.mail_exchangers(),
            vec![(10, "main".to_owned()), (20, "alt".to_owned())]
        );
    }

    #[test]
    fn rejoins_split_txt_chunks() {
        // A long SPF or DKIM value arrives as several length-prefixed chunks;
        // reading only the first would silently truncate the policy.
        let payload = b"\x05v=spf\x0a1 -all abc";
        let mut body = Vec::from(b"\xc0\x0c\x00\x10\x00\x01\x00\x00\x01\x2c".as_slice());
        body.extend_from_slice(&(payload.len() as u16).to_be_bytes());
        body.extend_from_slice(payload);

        let response = decode_response(&response_with(1, b"\x07example\x03com\x00", &body)).unwrap();
        assert_eq!(response.texts(), vec!["v=spf1 -all abc".to_owned()]);
    }

    #[test]
    fn reports_nxdomain_distinctly_from_an_empty_answer() {
        // "does not exist" and "exists with no such record" are different
        // diagnoses and must not be conflated.
        let mut message = response_with(0, b"\x04nope\x00", &[]);
        message[3] = 0x83; // RCODE 3
        let response = decode_response(&message).unwrap();
        assert_eq!(response.code, ResponseCode::NameError);
        assert!(response.answers.is_empty());

        let empty = decode_response(&response_with(0, b"\x03yes\x00", &[])).unwrap();
        assert_eq!(empty.code, ResponseCode::NoError);
        assert!(empty.answers.is_empty());
    }

    #[test]
    fn refuses_a_self_referential_compression_pointer() {
        // One packet must not be able to spin the decoder forever.
        let mut message = vec![0x12, 0x34, 0x81, 0x80, 0, 1, 0, 0, 0, 0, 0, 0];
        // A pointer at offset 12 aiming at offset 12.
        message.extend_from_slice(&[0xC0, 0x0C]);
        assert_eq!(decode_response(&message).unwrap_err(), WireError::CompressionLoop);
    }

    #[test]
    fn refuses_a_forward_compression_pointer() {
        let mut message = vec![0x12, 0x34, 0x81, 0x80, 0, 1, 0, 0, 0, 0, 0, 0];
        message.extend_from_slice(&[0xC0, 0x20]);
        message.extend_from_slice(&[0; 32]);
        assert_eq!(decode_response(&message).unwrap_err(), WireError::CompressionLoop);
    }

    #[test]
    fn refuses_a_truncated_message() {
        assert_eq!(decode_response(&[0, 1, 2]).unwrap_err(), WireError::Truncated);
    }

    #[test]
    fn decodes_an_soa_with_its_numeric_fields() {
        // An authoritative SOA carries the serial and timers on the wire; a
        // decoder that stopped at the two names would drop exactly the fields a
        // secondary needs to know whether the zone changed.
        let mut rdata = Vec::from(b"\x03ns1\x00".as_slice());
        rdata.extend_from_slice(b"\x0ahostmaster\x00");
        rdata.extend_from_slice(&2026080700_u32.to_be_bytes()); // serial
        rdata.extend_from_slice(&7200_u32.to_be_bytes()); // refresh
        rdata.extend_from_slice(&3600_u32.to_be_bytes()); // retry
        rdata.extend_from_slice(&1209600_u32.to_be_bytes()); // expire
        rdata.extend_from_slice(&3600_u32.to_be_bytes()); // minimum

        let mut body = Vec::from(b"\xc0\x0c\x00\x06\x00\x01\x00\x00\x01\x2c".as_slice());
        body.extend_from_slice(&(rdata.len() as u16).to_be_bytes());
        body.extend_from_slice(&rdata);

        let response = decode_response(&response_with(1, b"\x07example\x03com\x00", &body)).unwrap();
        assert_eq!(
            response.answers[0].data,
            RecordData::Soa {
                primary: "ns1".to_owned(),
                responsible: "hostmaster".to_owned(),
                serial: 2026080700,
                refresh: 7200,
                retry: 3600,
                expire: 1209600,
                minimum: 3600,
            }
        );
        // The responsible-party contact still reads the same field.
        assert_eq!(response.soa_contact().as_deref(), Some("hostmaster"));
    }

    #[test]
    fn type_codes_round_trip() {
        for record_type in [
            RecordType::A,
            RecordType::Aaaa,
            RecordType::Ns,
            RecordType::Cname,
            RecordType::Soa,
            RecordType::Ptr,
            RecordType::Mx,
            RecordType::Txt,
            RecordType::Caa,
        ] {
            assert_eq!(RecordType::from_code(record_type.code()), record_type);
        }
    }
}

#[cfg(test)]
mod soa_tests {
    use super::*;

    #[test]
    fn converts_a_responsible_name_into_an_address() {
        // This is how you find out who to email about a reverse-DNS record you
        // cannot change yourself.
        assert_eq!(email_from_rname("ipadmin.firstdigital.com"), "ipadmin@firstdigital.com");
        assert_eq!(email_from_rname("hostmaster.example.com"), "hostmaster@example.com");
    }

    #[test]
    fn an_escaped_dot_stays_inside_the_local_part() {
        // "first\.last.example.com" is first.last@example.com, not
        // first@last.example.com.
        assert_eq!(email_from_rname(r"first\.last.example.com"), "first.last@example.com");
    }

    #[test]
    fn a_name_without_a_separator_is_returned_unchanged() {
        assert_eq!(email_from_rname("hostmaster"), "hostmaster");
    }
}

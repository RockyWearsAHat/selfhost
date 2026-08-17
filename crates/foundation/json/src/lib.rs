//! JSON, written from the specification rather than pulled from a dependency.
//!
//! JSON is what the daemon and the console speak to each other, which by this
//! project's own rule — if a protocol is on the wire, we own it — puts it in the
//! same category as the HTTP parser next door. It is also, unlike TLS, small
//! enough that owning it is honest rather than reckless.
//!
//! Like [`selfhost_http`](../selfhost_http/index.html) this crate is pure: text
//! in, values out, values in, text out, and no I/O anywhere. That is what lets
//! the parsing edge cases be tested exhaustively.
//!
//! # What is enforced here
//!
//! - **Escaping is total.** Every control character below `0x20` is escaped on
//!   output, so a service that logs a raw byte cannot terminate a string early
//!   and inject structure into the response.
//! - **Depth is bounded.** Deeply nested input is refused rather than recursing
//!   until the stack runs out — a hostile payload should get an error, not a crash.
//! - **Trailing input is refused.** A document with anything after its top-level
//!   value is rejected, so two concatenated payloads cannot be read as one.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use std::collections::BTreeMap;
use std::fmt::Write as _;

/// The deepest nesting accepted while parsing.
///
/// Recursive descent costs stack per level, and a document nested thousands deep
/// is never legitimate. Refusing it is the difference between an error response
/// and a stack overflow, which is not catchable.
pub const MAX_DEPTH: usize = 128;

/// A JSON value.
#[derive(Debug, Clone, PartialEq)]
pub enum Json {
    /// `null`.
    Null,
    /// `true` or `false`.
    Bool(bool),
    /// Any JSON number, held as a double.
    Number(f64),
    /// A string.
    String(String),
    /// An array.
    Array(Vec<Json>),
    /// An object. Ordered by key so output is stable and diffable.
    Object(BTreeMap<String, Json>),
}

impl Json {
    /// Builds an object from key–value pairs.
    pub fn object<K: Into<String>>(entries: impl IntoIterator<Item = (K, Json)>) -> Self {
        Self::Object(entries.into_iter().map(|(k, v)| (k.into(), v)).collect())
    }

    /// Builds an array.
    pub fn array(items: impl IntoIterator<Item = Json>) -> Self {
        Self::Array(items.into_iter().collect())
    }

    /// Builds a string value.
    pub fn string(text: impl Into<String>) -> Self {
        Self::String(text.into())
    }

    /// Looks up a key, if this is an object.
    pub fn get(&self, key: &str) -> Option<&Json> {
        match self {
            Self::Object(map) => map.get(key),
            _ => None,
        }
    }

    /// The string contents, if this is a string.
    pub fn as_str(&self) -> Option<&str> {
        match self {
            Self::String(s) => Some(s),
            _ => None,
        }
    }

    /// The numeric value, if this is a number.
    pub fn as_f64(&self) -> Option<f64> {
        match self {
            Self::Number(n) => Some(*n),
            _ => None,
        }
    }

    /// The value as an unsigned integer, if it is a non-negative whole number.
    pub fn as_u64(&self) -> Option<u64> {
        match self {
            Self::Number(n) if n.is_finite() && *n >= 0.0 && n.fract() == 0.0 => Some(*n as u64),
            _ => None,
        }
    }

    /// The value as a signed integer, if it is a whole number.
    pub fn as_i64(&self) -> Option<i64> {
        match self {
            Self::Number(n) if n.is_finite() && n.fract() == 0.0 => Some(*n as i64),
            _ => None,
        }
    }

    /// The boolean value, if this is a boolean.
    pub fn as_bool(&self) -> Option<bool> {
        match self {
            Self::Bool(b) => Some(*b),
            _ => None,
        }
    }

    /// The elements, if this is an array.
    pub fn as_array(&self) -> Option<&[Json]> {
        match self {
            Self::Array(items) => Some(items),
            _ => None,
        }
    }

    /// Whether this is `null`.
    pub fn is_null(&self) -> bool {
        matches!(self, Self::Null)
    }

    /// Serialises to compact JSON text.
    pub fn to_text(&self) -> String {
        let mut out = String::new();
        self.write(&mut out);
        out
    }

    fn write(&self, out: &mut String) {
        match self {
            Self::Null => out.push_str("null"),
            Self::Bool(true) => out.push_str("true"),
            Self::Bool(false) => out.push_str("false"),
            Self::Number(n) => {
                // JSON has no way to spell infinity or NaN. Emitting a bare
                // `NaN` would produce a document no parser accepts, so a
                // non-finite number becomes null rather than invalid output.
                if n.is_finite() {
                    if n.fract() == 0.0 && n.abs() < 1e15 {
                        let _ = write!(out, "{}", *n as i64);
                    } else {
                        let _ = write!(out, "{n}");
                    }
                } else {
                    out.push_str("null");
                }
            }
            Self::String(s) => write_string(s, out),
            Self::Array(items) => {
                out.push('[');
                for (i, item) in items.iter().enumerate() {
                    if i > 0 {
                        out.push(',');
                    }
                    item.write(out);
                }
                out.push(']');
            }
            Self::Object(map) => {
                out.push('{');
                for (i, (key, value)) in map.iter().enumerate() {
                    if i > 0 {
                        out.push(',');
                    }
                    write_string(key, out);
                    out.push(':');
                    value.write(out);
                }
                out.push('}');
            }
        }
    }
}

/// Writes a JSON string literal, escaping everything that must be escaped.
///
/// Control characters are escaped by number rather than passed through. A log
/// line containing a raw `0x01` would otherwise be emitted literally inside a
/// string, producing a document that strict parsers reject and lenient ones
/// disagree about — the same class of ambiguity the HTTP crate refuses.
fn write_string(text: &str, out: &mut String) {
    out.push('"');
    for c in text.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\u{08}' => out.push_str("\\b"),
            '\u{0c}' => out.push_str("\\f"),
            c if (c as u32) < 0x20 => {
                let _ = write!(out, "\\u{:04x}", c as u32);
            }
            c => out.push(c),
        }
    }
    out.push('"');
}

/// Why a document could not be parsed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParseError {
    /// Byte offset where parsing stopped.
    pub at: usize,
    /// What went wrong.
    pub message: String,
}

impl std::fmt::Display for ParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "invalid JSON at byte {}: {}", self.at, self.message)
    }
}

impl std::error::Error for ParseError {}

/// Parses a complete JSON document.
///
/// Anything after the top-level value is an error, so two concatenated documents
/// are refused rather than silently read as the first one.
pub fn parse(text: &str) -> Result<Json, ParseError> {
    let mut parser = Parser { bytes: text.as_bytes(), at: 0 };
    parser.skip_whitespace();
    let value = parser.value(0)?;
    parser.skip_whitespace();
    if parser.at != parser.bytes.len() {
        return Err(parser.error("unexpected trailing input after the top-level value"));
    }
    Ok(value)
}

struct Parser<'a> {
    bytes: &'a [u8],
    at: usize,
}

impl<'a> Parser<'a> {
    fn error(&self, message: &str) -> ParseError {
        ParseError { at: self.at, message: message.to_owned() }
    }

    fn peek(&self) -> Option<u8> {
        self.bytes.get(self.at).copied()
    }

    fn skip_whitespace(&mut self) {
        while matches!(self.peek(), Some(b' ' | b'\t' | b'\n' | b'\r')) {
            self.at += 1;
        }
    }

    fn expect(&mut self, byte: u8) -> Result<(), ParseError> {
        if self.peek() == Some(byte) {
            self.at += 1;
            Ok(())
        } else {
            Err(self.error(&format!("expected {:?}", byte as char)))
        }
    }

    fn literal(&mut self, word: &str, value: Json) -> Result<Json, ParseError> {
        if self.bytes[self.at..].starts_with(word.as_bytes()) {
            self.at += word.len();
            Ok(value)
        } else {
            Err(self.error(&format!("expected {word}")))
        }
    }

    fn value(&mut self, depth: usize) -> Result<Json, ParseError> {
        if depth > MAX_DEPTH {
            return Err(self.error("nested too deeply"));
        }
        match self.peek() {
            None => Err(self.error("unexpected end of input")),
            Some(b'n') => self.literal("null", Json::Null),
            Some(b't') => self.literal("true", Json::Bool(true)),
            Some(b'f') => self.literal("false", Json::Bool(false)),
            Some(b'"') => self.string().map(Json::String),
            Some(b'[') => self.array(depth),
            Some(b'{') => self.object(depth),
            Some(b'-' | b'0'..=b'9') => self.number(),
            Some(other) => Err(self.error(&format!("unexpected {:?}", other as char))),
        }
    }

    fn array(&mut self, depth: usize) -> Result<Json, ParseError> {
        self.expect(b'[')?;
        let mut items = Vec::new();
        self.skip_whitespace();
        if self.peek() == Some(b']') {
            self.at += 1;
            return Ok(Json::Array(items));
        }
        loop {
            self.skip_whitespace();
            items.push(self.value(depth + 1)?);
            self.skip_whitespace();
            match self.peek() {
                Some(b',') => self.at += 1,
                Some(b']') => {
                    self.at += 1;
                    return Ok(Json::Array(items));
                }
                _ => return Err(self.error("expected ',' or ']'")),
            }
        }
    }

    fn object(&mut self, depth: usize) -> Result<Json, ParseError> {
        self.expect(b'{')?;
        let mut map = BTreeMap::new();
        self.skip_whitespace();
        if self.peek() == Some(b'}') {
            self.at += 1;
            return Ok(Json::Object(map));
        }
        loop {
            self.skip_whitespace();
            let key = self.string()?;
            self.skip_whitespace();
            self.expect(b':')?;
            self.skip_whitespace();
            let value = self.value(depth + 1)?;
            map.insert(key, value);
            self.skip_whitespace();
            match self.peek() {
                Some(b',') => self.at += 1,
                Some(b'}') => {
                    self.at += 1;
                    return Ok(Json::Object(map));
                }
                _ => return Err(self.error("expected ',' or '}'")),
            }
        }
    }

    fn number(&mut self) -> Result<Json, ParseError> {
        let start = self.at;
        if self.peek() == Some(b'-') {
            self.at += 1;
        }
        while matches!(self.peek(), Some(b'0'..=b'9' | b'.' | b'e' | b'E' | b'+' | b'-')) {
            self.at += 1;
        }
        let text = std::str::from_utf8(&self.bytes[start..self.at])
            .map_err(|_| self.error("number is not valid UTF-8"))?;
        text.parse::<f64>()
            .map(Json::Number)
            .map_err(|_| ParseError { at: start, message: format!("invalid number {text:?}") })
    }

    fn string(&mut self) -> Result<String, ParseError> {
        self.expect(b'"')?;
        let mut out = String::new();
        loop {
            let byte = self.peek().ok_or_else(|| self.error("unterminated string"))?;
            match byte {
                b'"' => {
                    self.at += 1;
                    return Ok(out);
                }
                b'\\' => {
                    self.at += 1;
                    let escape = self.peek().ok_or_else(|| self.error("unterminated escape"))?;
                    self.at += 1;
                    match escape {
                        b'"' => out.push('"'),
                        b'\\' => out.push('\\'),
                        b'/' => out.push('/'),
                        b'b' => out.push('\u{08}'),
                        b'f' => out.push('\u{0c}'),
                        b'n' => out.push('\n'),
                        b'r' => out.push('\r'),
                        b't' => out.push('\t'),
                        b'u' => out.push(self.unicode_escape()?),
                        other => {
                            return Err(self.error(&format!("unknown escape \\{}", other as char)));
                        }
                    }
                }
                // A raw control character inside a string is invalid JSON. Some
                // parsers accept it; accepting it here would mean our reader and
                // some other reader disagree about where the string ends.
                b if b < 0x20 => return Err(self.error("raw control character in string")),
                _ => {
                    let rest = std::str::from_utf8(&self.bytes[self.at..])
                        .map_err(|_| self.error("string is not valid UTF-8"))?;
                    let c = rest.chars().next().expect("non-empty by construction");
                    out.push(c);
                    self.at += c.len_utf8();
                }
            }
        }
    }

    /// Reads a `\uXXXX` escape, joining a surrogate pair if one follows.
    fn unicode_escape(&mut self) -> Result<char, ParseError> {
        let high = self.hex4()?;
        // Characters outside the basic plane are written as two escapes. Decoding
        // the halves independently yields two unpaired surrogates, which are not
        // characters, so the pair has to be recombined here.
        if (0xD800..0xDC00).contains(&high) {
            if self.peek() == Some(b'\\') && self.bytes.get(self.at + 1) == Some(&b'u') {
                self.at += 2;
                let low = self.hex4()?;
                if (0xDC00..0xE000).contains(&low) {
                    let combined = 0x10000 + ((high - 0xD800) << 10) + (low - 0xDC00);
                    return char::from_u32(combined)
                        .ok_or_else(|| self.error("invalid surrogate pair"));
                }
                return Err(self.error("high surrogate not followed by a low surrogate"));
            }
            return Err(self.error("unpaired high surrogate"));
        }
        char::from_u32(high).ok_or_else(|| self.error("invalid \\u escape"))
    }

    fn hex4(&mut self) -> Result<u32, ParseError> {
        let end = self.at + 4;
        if end > self.bytes.len() {
            return Err(self.error("truncated \\u escape"));
        }
        let text = std::str::from_utf8(&self.bytes[self.at..end])
            .map_err(|_| self.error("invalid \\u escape"))?;
        let value =
            u32::from_str_radix(text, 16).map_err(|_| self.error("invalid \\u escape"))?;
        self.at = end;
        Ok(value)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips_every_kind_of_value() {
        let value = Json::object([
            ("null", Json::Null),
            ("yes", Json::Bool(true)),
            ("count", Json::Number(42.0)),
            ("name", Json::string("selfhost")),
            ("list", Json::array([Json::Number(1.0), Json::string("two")])),
        ]);
        let text = value.to_text();
        assert_eq!(parse(&text).expect("round trip"), value);
    }

    #[test]
    fn whole_numbers_do_not_grow_a_decimal_point() {
        // "pid": 4412.0 is legal JSON but reads as a mistake in a console.
        assert_eq!(Json::Number(4412.0).to_text(), "4412");
        assert_eq!(Json::Number(-1.0).to_text(), "-1");
        assert_eq!(Json::Number(1.5).to_text(), "1.5");
    }

    #[test]
    fn control_characters_are_escaped_rather_than_emitted_raw() {
        // A service logging a raw byte must not be able to end the string early
        // and inject structure into the response around it.
        let text = Json::string("a\u{1}b\"c\\d\ne").to_text();
        assert_eq!(text, r#""a\u0001b\"c\\d\ne""#);
        assert_eq!(parse(&text).unwrap().as_str().unwrap(), "a\u{1}b\"c\\d\ne");
    }

    #[test]
    fn a_raw_control_character_in_input_is_refused() {
        assert!(parse("\"a\u{1}b\"").is_err());
    }

    #[test]
    fn trailing_input_is_refused() {
        // Two concatenated documents must not be read as the first one.
        assert!(parse("{} {}").is_err());
        assert!(parse("1 2").is_err());
        // Trailing whitespace alone is fine.
        assert!(parse(" 1 \n").is_ok());
    }

    #[test]
    fn deep_nesting_is_refused_rather_than_overflowing_the_stack() {
        let deep = format!("{}1{}", "[".repeat(5000), "]".repeat(5000));
        let error = parse(&deep).expect_err("should refuse");
        assert!(error.message.contains("deeply"), "{error}");
    }

    #[test]
    fn parses_escapes_including_astral_surrogate_pairs() {
        assert_eq!(parse(r#""A""#).unwrap().as_str().unwrap(), "A");
        assert_eq!(parse(r#""\n\t\\""#).unwrap().as_str().unwrap(), "\n\t\\");
        // U+1F600, written as a surrogate pair, must come back as one character.
        assert_eq!(parse(r#""😀""#).unwrap().as_str().unwrap(), "\u{1F600}");
    }

    #[test]
    fn an_unpaired_surrogate_is_refused() {
        assert!(parse(r#""\ud83d""#).is_err());
        assert!(parse(r#""\ud83dA""#).is_err());
    }

    #[test]
    fn rejects_the_usual_malformed_documents() {
        for bad in [
            "",
            "{",
            "[1,",
            "{\"a\"}",
            "{\"a\":}",
            "tru",
            "\"unterminated",
            "[1 2]",
            "{'a':1}",
        ] {
            assert!(parse(bad).is_err(), "expected {bad:?} to be refused");
        }
    }

    #[test]
    fn object_keys_come_back_in_a_stable_order() {
        // Stable output means a response diff shows what changed, not a reshuffle.
        let value = parse(r#"{"z":1,"a":2,"m":3}"#).unwrap();
        assert_eq!(value.to_text(), r#"{"a":2,"m":3,"z":1}"#);
    }

    #[test]
    fn non_finite_numbers_become_null_rather_than_invalid_output() {
        // NaN and Infinity cannot be spelled in JSON; emitting them literally
        // would produce a document nothing can parse.
        assert_eq!(Json::Number(f64::NAN).to_text(), "null");
        assert_eq!(Json::Number(f64::INFINITY).to_text(), "null");
    }

    #[test]
    fn integer_accessors_refuse_values_that_are_not_whole() {
        assert_eq!(Json::Number(7.0).as_u64(), Some(7));
        assert_eq!(Json::Number(7.5).as_u64(), None);
        assert_eq!(Json::Number(-1.0).as_u64(), None);
        assert_eq!(Json::Number(-1.0).as_i64(), Some(-1));
    }

    #[test]
    fn unicode_outside_ascii_survives_a_round_trip_unescaped() {
        let value = Json::string("café — 日本語");
        assert_eq!(parse(&value.to_text()).unwrap(), value);
    }
}

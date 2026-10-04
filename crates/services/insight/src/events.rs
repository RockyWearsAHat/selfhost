//! The Windows event-log entries that explain an outage, read incrementally.
//!
//! `wevtutil qe <log> /f:RenderedXml` prints each event as one `<Event>`
//! element, message included. Each poll asks only for records after the
//! newest `EventRecordID` already seen, kept per log in
//! `insight/events-cursor`, so nothing is read twice, across restarts too.
//! The first poll on a machine reaches back an hour: the crash that caused a
//! restart is the event most worth having.

use crate::Event;
use crate::json::{num, text};
use selfhost_json::Json;

/// One entry from a Windows event log.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WindowsEvent {
    /// Which log it came from (`System`, `Application`).
    pub log: String,
    /// The log's own sequence number: the read cursor.
    pub record_id: u64,
    /// Who wrote it (`Microsoft-Windows-Kernel-Power`).
    pub provider: String,
    /// The provider's event number (41 is "rebooted without a clean shutdown").
    pub id: u32,
    /// 1 critical, 2 error, 3 warning.
    pub level: u8,
    /// Unix seconds when it was written.
    pub at_unix: u64,
    /// The first line of its rendered message.
    pub message: String,
}

/// Which entries each log contributes. System warnings are included because
/// that is where adapter link loss, resource exhaustion, TCP port exhaustion
/// and DNS-client timeouts are recorded; Application contributes crashes.
#[cfg_attr(not(windows), allow(dead_code))]
pub(crate) const LOGS: [(&str, &str); 2] =
    [("System", "Level=1 or Level=2 or Level=3"), ("Application", "Level=1 or Level=2")];

/// The most entries one poll takes from one log; the cursor resumes the rest.
#[cfg_attr(not(windows), allow(dead_code))]
pub(crate) const BATCH: u32 = 100;

/// The `wevtutil` query: entries after `cursor`, or from the last hour when
/// there is no cursor yet.
#[cfg_attr(not(windows), allow(dead_code))]
pub(crate) fn query(levels: &str, cursor: Option<u64>) -> String {
    match cursor {
        Some(after) => format!("*[System[({levels}) and EventRecordID>{after}]]"),
        None => format!("*[System[({levels}) and TimeCreated[timediff(@SystemTime) <= 3600000]]]"),
    }
}

/// Every `<Event>` in `wevtutil` RenderedXml output. Entries missing a field
/// the timeline needs are skipped.
pub fn parse_rendered_events(log: &str, xml: &str) -> Vec<WindowsEvent> {
    xml.split("<Event ").skip(1).filter_map(|event| parse_one(log, event)).collect()
}

fn parse_one(log: &str, event: &str) -> Option<WindowsEvent> {
    let message = element(event, "Message").map(|raw| first_line(&unescape(raw))).unwrap_or_default();
    Some(WindowsEvent {
        log: log.to_owned(),
        record_id: element(event, "EventRecordID")?.trim().parse().ok()?,
        provider: attribute(event, "<Provider ", "Name")?.to_owned(),
        id: element(event, "EventID")?.trim().parse().ok()?,
        level: element(event, "Level")?.trim().parse().ok()?,
        at_unix: parse_system_time(attribute(event, "<TimeCreated ", "SystemTime")?)?,
        message,
    })
}

/// The text of the first `<name ...>text</name>`.
fn element<'a>(xml: &'a str, name: &str) -> Option<&'a str> {
    let open = xml.find(&format!("<{name}"))?;
    let after_name = &xml[open + 1 + name.len()..];
    // Reject a longer tag that merely starts with `name` (`<EventIDx`).
    if !after_name.starts_with(['>', ' ']) {
        return None;
    }
    let body = &after_name[after_name.find('>')? + 1..];
    Some(&body[..body.find(&format!("</{name}>"))?])
}

/// The value of `key='...'` (or `key="..."`) inside the first tag starting `tag`.
fn attribute<'a>(xml: &'a str, tag: &str, key: &str) -> Option<&'a str> {
    let start = xml.find(tag)?;
    let element = &xml[start..start + xml[start..].find('>')?];
    let value = &element[element.find(&format!("{key}="))? + key.len() + 1..];
    let quote = value.chars().next()?;
    let value = &value[1..];
    Some(&value[..value.find(quote)?])
}

/// `2026-10-03T04:31:02.1234567Z` (always UTC in the XML) to Unix seconds.
fn parse_system_time(stamp: &str) -> Option<u64> {
    let number = |range: std::ops::Range<usize>| stamp.get(range)?.parse::<u64>().ok();
    let days = crate::store::days_from_civil(number(0..4)?, number(5..7)?, number(8..10)?)?;
    Some(days * 86_400 + number(11..13)? * 3600 + number(14..16)? * 60 + number(17..19)?)
}

fn unescape(text: &str) -> String {
    text.replace("&#xD;", "")
        .replace("&#xA;", "\n")
        .replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&quot;", "\"")
        .replace("&apos;", "'")
        .replace("&amp;", "&")
}

/// The first non-empty line, at most 200 characters.
fn first_line(message: &str) -> String {
    let line = message.lines().map(str::trim).find(|line| !line.is_empty()).unwrap_or_default();
    line.chars().take(200).collect()
}

impl WindowsEvent {
    /// The timeline entry for this event.
    pub fn to_event(&self) -> Event {
        let title = if self.message.is_empty() {
            format!("{} event {}", self.provider, self.id)
        } else {
            self.message.clone()
        };
        Event {
            at_unix: self.at_unix,
            kind: "windows".to_owned(),
            source: self.provider.clone(),
            title,
            evidence: Json::object([
                ("log", text(&self.log)),
                ("record_id", num(self.record_id)),
                ("event_id", num(u64::from(self.id))),
                ("level", text(level_name(self.level))),
            ]),
        }
    }
}

fn level_name(level: u8) -> &'static str {
    match level {
        1 => "critical",
        2 => "error",
        3 => "warning",
        _ => "information",
    }
}

/// The per-log cursor file: `System=1234` lines.
#[cfg_attr(not(windows), allow(dead_code))]
pub(crate) fn parse_cursors(contents: &str) -> Vec<(String, u64)> {
    contents
        .lines()
        .filter_map(|line| {
            let (log, id) = line.split_once('=')?;
            Some((log.trim().to_owned(), id.trim().parse().ok()?))
        })
        .collect()
}

/// Reads one log after `cursor`. Runs `wevtutil` (part of every Windows) with
/// a deadline, off the async runtime's threads.
#[cfg(windows)]
pub(crate) async fn read_log(log: &str, levels: &str, cursor: Option<u64>) -> std::io::Result<Vec<WindowsEvent>> {
    let query = query(levels, cursor);
    let run = tokio::process::Command::new("wevtutil")
        .args(["qe", log, &format!("/q:{query}"), "/f:RenderedXml", &format!("/c:{BATCH}")])
        .kill_on_drop(true)
        .output();
    let output = tokio::time::timeout(std::time::Duration::from_secs(30), run)
        .await
        .map_err(|_| std::io::Error::new(std::io::ErrorKind::TimedOut, "wevtutil took over 30 s"))??;
    if !output.status.success() {
        return Err(std::io::Error::other(format!(
            "wevtutil {log}: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        )));
    }
    Ok(parse_rendered_events(log, &String::from_utf8_lossy(&output.stdout)))
}

#[cfg(test)]
mod tests {
    use super::*;

    const RENDERED: &str = "<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System>\
<Provider Name='Microsoft-Windows-Kernel-Power' Guid='{331c3b3a-2005-44c2-ac5e-77220c37d6b4}'/>\
<EventID>41</EventID><Version>8</Version><Level>1</Level>\
<TimeCreated SystemTime='2026-10-03T04:31:02.1234567Z'/><EventRecordID>98765</EventRecordID>\
</System><EventData><Data Name='BugcheckCode'>0</Data></EventData>\
<RenderingInfo Culture='en-US'><Message>The system has rebooted without cleanly shutting down first. This error could be caused if the system stopped responding.&#xD;&#xA;Second line</Message><Level>Critical</Level></RenderingInfo></Event>\
<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System>\
<Provider Name=\"Microsoft-Windows-DNS-Client\"/><EventID Qualifiers='16384'>1014</EventID><Level>3</Level>\
<TimeCreated SystemTime='2026-10-03T12:00:00.0000000Z'/><EventRecordID>98770</EventRecordID></System>\
<RenderingInfo Culture='en-US'><Message>Name resolution for the name x.example timed out &amp; gave up.</Message></RenderingInfo></Event>";

    #[test]
    fn rendered_events_parse_with_ids_times_and_first_lines() {
        let events = parse_rendered_events("System", RENDERED);
        assert_eq!(events.len(), 2);
        let power = &events[0];
        assert_eq!(power.provider, "Microsoft-Windows-Kernel-Power");
        assert_eq!((power.id, power.level, power.record_id), (41, 1, 98765));
        assert_eq!(power.at_unix, 1_791_001_862);
        assert!(power.message.starts_with("The system has rebooted"));
        assert!(!power.message.contains("Second line"));

        let dns = &events[1];
        assert_eq!((dns.provider.as_str(), dns.id, dns.level), ("Microsoft-Windows-DNS-Client", 1014, 3));
        assert_eq!(dns.message, "Name resolution for the name x.example timed out & gave up.");
    }

    #[test]
    fn a_timeline_entry_names_the_log_and_level() {
        let event = parse_rendered_events("System", RENDERED).remove(0).to_event();
        assert_eq!(event.kind, "windows");
        assert_eq!(event.evidence.get("level").and_then(Json::as_str), Some("critical"));
        assert_eq!(event.evidence.get("record_id").and_then(Json::as_u64), Some(98765));
    }

    #[test]
    fn queries_resume_from_the_cursor_or_reach_back_an_hour() {
        assert_eq!(query("Level=1", Some(7)), "*[System[(Level=1) and EventRecordID>7]]");
        assert!(query("Level=1", None).contains("timediff(@SystemTime) <= 3600000"));
        assert_eq!(parse_cursors("System=12\nApplication=34\njunk\n"), vec![("System".into(), 12), ("Application".into(), 34)]);
    }

    #[test]
    fn malformed_events_are_skipped() {
        assert!(parse_rendered_events("System", "<Event ><System><EventID>x</EventID></System></Event>").is_empty());
        assert!(parse_rendered_events("System", "").is_empty());
    }
}

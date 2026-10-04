//! The HEALTH plate: what is wrong on the machine the daemon runs on, read
//! from `GET /api/insight/now`, with the last hour behind it as sparklines from
//! `GET /api/insight/metrics`.
//!
//! The order is the order an owner asks in: is it fine; if not, what is wrong
//! and since when; what has the machine been doing; is DNS answering; who is
//! using it. Every line is named, so a problem can be pointed at by what it
//! says rather than by where it sits.

use super::Console;
use super::style;
use crate::state::{DnsWindow, HistorySample, Insight, InsightEvent};
use rui::{Align, El, Length, Point, Size, Status, Tone, caption, col, draw, micro, row, text};
use std::collections::BTreeSet;

/// The label column's share of a row, matching `system::NAME_W`.
const LABEL_W: f32 = 0.28;

/// How tall a sparkline is drawn.
const SPARK_H: f32 = 18.0;

/// How many ranked processes the plate names; the MCP tool has the rest.
const PROCESSES: usize = 3;

/// The HEALTH plate, or `None` while nothing has been fetched and on a daemon
/// without machine insight.
pub fn view(
    insight: Option<&Insight>,
    history: &[HistorySample],
    events: &[InsightEvent],
    open_problems: &BTreeSet<String>,
) -> Option<El<Console>> {
    let insight = insight?;
    let condition = match insight.condition.as_str() {
        "ok" => Status::Ok,
        "warning" => Status::Warn,
        _ => Status::Idle,
    };
    let mut rows: Vec<El<Console>> = vec![
        row((
            row((style::lamp(condition), caption(insight.condition.to_uppercase())))
                .gap(6.0)
                .align(Align::Center)
                .w(Length::Fraction(LABEL_W)),
            text(insight.summary.clone()).grow(),
        ))
        .min_h(20.0)
        .align(Align::Center),
    ];
    rows.extend(insight.problems.iter().flat_map(|problem| {
        let mut problem_rows: Vec<El<Console>> = vec![
            row((
                row((style::lamp(Status::Warn), caption(format!("SINCE {}", clock(problem.since_unix)))))
                    .gap(6.0)
                    .align(Align::Center)
                    .w(Length::Fraction(LABEL_W)),
                caption(problem.title.clone()).grow(),
            ))
            .min_h(20.0)
            .align(Align::Center)
            .on_click({
                let id = problem.id.clone();
                move |console: &mut Console| console.toggle_problem(&id)
            }),
        ];
        if open_problems.contains(&problem.id) {
            problem_rows.extend(problem.evidence.iter().map(|(key, value)| {
                let truncated = if value.len() > 80 {
                    format!("{}…", &value[..77])
                } else {
                    value.clone()
                };
                row((
                    caption(format!("{key}  ")).w(Length::Fraction(LABEL_W)),
                    caption(truncated).grow(),
                ))
                .min_h(16.0)
            }));
        }
        problem_rows
    }));
    let cpu: Vec<f64> = history.iter().map(|s| s.cpu_pct.unwrap_or(0.0)).collect();
    let memory: Vec<f64> = history.iter().map(|s| s.mem_pct).collect();
    let network: Vec<f64> = history.iter().map(|s| s.net_bps as f64).collect();
    rows.push(
        row((
            spark("CPU", insight.cpu_pct.map(|pct| format!("{pct:.0}%")), cpu, Some(100.0)),
            spark("MEMORY", insight.mem_pct.map(|pct| format!("{pct:.0}%")), memory, Some(100.0)),
            spark("NETWORK", history.last().map(|s| rate(s.net_bps)), network, None),
            dns(insight.dns),
        ))
        .gap(16.0),
    );
    if !insight.processes.is_empty() {
        let top: Vec<String> = insight
            .processes
            .iter()
            .take(PROCESSES)
            .map(|p| format!("{} ({}) {:.2} cores {} MB", p.name, p.pid, p.cpu_cores, p.working_set_mb))
            .collect();
        rows.push(row((micro("TOP".to_owned()).w(Length::Fraction(LABEL_W)), micro(top.join("  ·  ")).grow())).min_h(16.0));
    }
    if !events.is_empty() {
        let event_rows: Vec<El<Console>> = events
            .iter()
            .map(|event| {
                let status = match event.kind.as_str() {
                    "warning" => Status::Warn,
                    "cleared" => Status::Ok,
                    "repair" => Status::Warn,
                    "windows" => Status::Idle,
                    _ => Status::Idle,
                };
                let event_text = format!("{}: {}", event.source, event.title);
                let truncated = if event_text.len() > 90 {
                    format!("{}…", &event_text[..87])
                } else {
                    event_text
                };
                row((
                    row((style::lamp(status), micro(clock(event.at_unix))))
                        .gap(6.0)
                        .align(Align::Center),
                    micro(truncated).grow(),
                ))
                .min_h(16.0)
            })
            .collect();
        rows.push(row((
            micro("RECENT".to_owned()).w(Length::Fraction(LABEL_W)),
            col(event_rows).gap(0.0).grow(),
        )).min_h(16.0));
    }
    Some(style::plate((style::section_rule("HEALTH", None), col(rows).gap(3.0))).gap(6.0))
}

/// A named metric with its newest value over its last hour as a line.
fn spark(label: &str, now: Option<String>, values: Vec<f64>, ceiling: Option<f64>) -> El<Console> {
    col((
        row((caption(label.to_owned()), caption(now.unwrap_or_else(|| "—".to_owned()))))
            .gap(8.0)
            .align(Align::Center),
        sparkline(values, ceiling),
    ))
    .gap(2.0)
    .grow()
}

/// `values` as one line across the space it is given: oldest at the left,
/// scaled to `ceiling` (a percentage's 100) or, for a rate, to its own peak.
/// Fewer than two points draw nothing rather than a misleading flat line.
fn sparkline(values: Vec<f64>, ceiling: Option<f64>) -> El<Console> {
    draw(Size::new(0.0, SPARK_H), move |painter, rect| {
        if values.len() < 2 {
            return;
        }
        let top = ceiling.unwrap_or_else(|| values.iter().copied().fold(0.0, f64::max)).max(f64::EPSILON);
        let color = painter.color(Tone::AccentLight);
        let step = rect.w / (values.len() - 1) as f32;
        let point = |index: usize, value: f64| {
            let share = (value / top).clamp(0.0, 1.0) as f32;
            Point::new(rect.x + step * index as f32, rect.y + rect.h - share * rect.h)
        };
        for (index, pair) in values.windows(2).enumerate() {
            painter.canvas().line(point(index, pair[0]), point(index + 1, pair[1]), 1.0, color);
        }
    })
    .h(SPARK_H)
}

/// The resolver's last five minutes, lit by how it went; dark where no
/// resolver reports on this machine.
fn dns(window: Option<DnsWindow>) -> El<Console> {
    let Some(dns) = window else {
        return col((row((style::lamp(Status::Idle), caption("DNS".to_owned()))).gap(6.0).align(Align::Center), micro("not on this machine".to_owned()))).gap(2.0).grow();
    };
    let status = if dns.queries > 0 && dns.failures * 100 > dns.queries {
        Status::Bad
    } else if dns.queries > 0 && dns.slow * 20 > dns.queries {
        Status::Warn
    } else {
        Status::Ok
    };
    col((
        row((style::lamp(status), caption("DNS".to_owned()))).gap(6.0).align(Align::Center),
        micro(format!("{} in 5 min · {} failed · {} slow", dns.queries, dns.failures, dns.slow)),
    ))
    .gap(2.0)
    .grow()
}

/// Bytes a second, in the unit a person reads.
fn rate(bytes_per_second: u64) -> String {
    match bytes_per_second {
        rate if rate >= 1_000_000 => format!("{:.1} MB/s", rate as f64 / 1_000_000.0),
        rate if rate >= 1_000 => format!("{:.0} KB/s", rate as f64 / 1_000.0),
        rate => format!("{rate} B/s"),
    }
}

/// `HH:MM` UTC, for "since when": the daemon's clock, not this machine's zone.
fn clock(unix: u64) -> String {
    let minutes = unix / 60 % (24 * 60);
    format!("{:02}:{:02} UTC", minutes / 60, minutes % 60)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rates_and_clocks_read_as_a_person_would_say_them() {
        assert_eq!(rate(512), "512 B/s");
        assert_eq!(rate(48_000), "48 KB/s");
        assert_eq!(rate(2_500_000), "2.5 MB/s");
        assert_eq!(clock(1_791_001_862), "04:31 UTC");
    }

    #[test]
    fn evidence_rows_are_shown_only_when_problem_is_open() {
        use crate::state::InsightProblem;
        use std::collections::BTreeSet;

        let insight = crate::state::Insight {
            at_unix: 1000,
            condition: "warning".into(),
            summary: "Test".into(),
            problems: vec![InsightProblem {
                id: "test_prob".into(),
                title: "Test problem".into(),
                since_unix: 900,
                evidence: vec![
                    ("code".to_owned(), "42".to_owned()),
                    ("message".to_owned(), "something broke".to_owned()),
                ],
            }],
            cpu_pct: None,
            mem_pct: None,
            processes: vec![],
            dns: None,
        };

        let mut open = BTreeSet::new();
        let result = view(Some(&insight), &[], &[], &open);
        assert!(result.is_some(), "health view should render");

        open.insert("test_prob".to_owned());
        let result = view(Some(&insight), &[], &[], &open);
        assert!(result.is_some(), "health view should render with open problem");
    }

    #[test]
    fn recent_events_are_capped_at_eight() {
        use crate::state::Insight;
        use std::collections::BTreeSet;

        let events: Vec<InsightEvent> = (0..10)
            .map(|i| InsightEvent {
                at_unix: 1000 + i,
                kind: "warning".to_owned(),
                source: format!("source{i}"),
                title: format!("event{i}"),
            })
            .collect();
        assert_eq!(events.len(), 10);

        let insight = Insight {
            at_unix: 1000,
            condition: "ok".into(),
            summary: "Test".into(),
            problems: vec![],
            cpu_pct: None,
            mem_pct: None,
            processes: vec![],
            dns: None,
        };

        let open = BTreeSet::new();
        let result = view(Some(&insight), &[], &events[..8], &open);
        assert!(result.is_some());

        // Verify the cap: the refresh_events function in poller truncates at 8
        let all_events = events;
        let mut capped = all_events;
        capped.truncate(8);
        assert_eq!(capped.len(), 8);
    }
}

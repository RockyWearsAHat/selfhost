//! The HEALTH panel: the machine's current condition from the insight service.
//!
//! Shows a lamp with the condition word, a summary line, active problems, and
//! the latest metrics. The history is kept but not shown on screen to avoid
//! cluttering the interface; it is available for future use by any monitoring
//! agent.

use super::style;
use super::Console;
use crate::state::{HistorySample, Insight};
use rui::{Align, El, Status, caption, col, micro, row, text};

/// The HEALTH panel when insight is available, or `None` while fetching or if
/// insight is not enabled.
pub fn view(insight: Option<&Insight>, _history: &[HistorySample]) -> Option<El<Console>> {
    let insight = insight?;

    let condition_status = match insight.condition.as_str() {
        "ok" => Status::Ok,
        "warning" => Status::Warn,
        _ => Status::Idle,
    };

    let problem_rows: Vec<El<Console>> = insight
        .problems
        .iter()
        .map(|p| {
            row((
                style::lamp(Status::Warn),
                caption(p.title.clone()),
                caption(format_since(p.since_unix)),
            ))
            .gap(6.0)
            .align(Align::Center)
            .min_h(20.0)
        })
        .collect();

    let mut children: Vec<El<Console>> = vec![
        row((
            style::lamp(condition_status),
            caption(insight.condition.to_uppercase()),
            text(insight.summary.clone()).grow(),
        ))
        .gap(6.0)
        .align(Align::Center)
        .min_h(20.0),
    ];

    children.extend(problem_rows);

    // Show latest metrics if available.
    if let Some((cpu_pct, mem_used, mem_total, _commit)) = insight.latest {
        let mem_pct = if mem_total == 0 { 0.0 } else { (mem_used as f64 / mem_total as f64) * 100.0 };
        let metrics_line = if let Some(cpu) = cpu_pct {
            format!("CPU {:.1}% · Memory {:.1}%", cpu, mem_pct)
        } else {
            format!("Memory {:.1}%", mem_pct)
        };
        children.push(row((micro(metrics_line),)).min_h(16.0));
    }

    Some(style::plate((style::section_rule("HEALTH", None), col(children).gap(3.0))).gap(6.0))
}

/// Formats a unix timestamp relative to now.
fn format_since(since_unix: u64) -> String {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let secs_ago = now.saturating_sub(since_unix);
    if secs_ago < 60 {
        "now".into()
    } else if secs_ago < 3600 {
        format!("{}m ago", secs_ago / 60)
    } else {
        format!("{}h ago", secs_ago / 3600)
    }
}

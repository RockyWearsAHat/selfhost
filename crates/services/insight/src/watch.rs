//! The watcher the daemon runs: sample, judge, record, forever.
//!
//! It runs on its own task, and every OS read happens on the blocking pool,
//! so a slow read can never hold up the daemon's other work, DNS included.
//! Failures are logged when they change, not on every tick: a full disk must
//! not turn the watcher into the log flood it exists to catch.

use crate::assess::{problems_path, read_dns_stats};
use crate::store::{self, Store};
use crate::{Assessor, SAMPLE_EVERY, Sampler, unix_now};
use selfhost_json::Json;
use std::io;
use std::path::{Path, PathBuf};
use tokio::time::{MissedTickBehavior, interval};

/// Watches the machine until the process exits. Spawn it; it never returns.
pub async fn run(data_dir: PathBuf) {
    tokio::join!(sample_forever(data_dir.clone()), windows_events_forever(data_dir));
}

struct Watch {
    data_dir: PathBuf,
    sampler: Sampler,
    assessor: Assessor,
    store: Store,
    log: ErrorLog,
}

impl Watch {
    fn new(data_dir: &Path) -> Self {
        let mut watch = Self {
            data_dir: data_dir.to_owned(),
            sampler: Sampler::new(),
            assessor: Assessor::new(),
            store: Store::new(data_dir),
            log: ErrorLog::default(),
        };
        // A fresh assessor knows of no problems yet; say so, rather than
        // leave the last run's list standing.
        let cleared = std::fs::create_dir_all(store::dir(data_dir)).and_then(|()| watch.write_problems());
        watch.log.report("writing problems.json", cleared);
        watch
    }

    fn tick(&mut self, at: u64) {
        let sample = self.sampler.sample(at);
        let timeline = self.assessor.observe(&sample, read_dns_stats(&self.data_dir).as_ref());
        let mut recorded = self.store.append_sample(&sample);
        for event in &timeline {
            recorded = recorded.and_then(|()| self.store.append_event(event));
            eprintln!("[insight] {}: {}", event.kind, event.title);
        }
        if !timeline.is_empty() {
            recorded = recorded.and_then(|()| self.write_problems());
        }
        self.log.report("recording a sample", recorded);
    }

    fn write_problems(&self) -> io::Result<()> {
        let problems = Json::array(self.assessor.problems().iter().map(crate::Problem::to_json));
        store::replace(&problems_path(&self.data_dir), &problems.to_text())
    }
}

async fn sample_forever(data_dir: PathBuf) {
    let mut ticks = interval(SAMPLE_EVERY);
    ticks.set_missed_tick_behavior(MissedTickBehavior::Delay);
    let mut watch = None;
    loop {
        ticks.tick().await;
        let mut current = watch.take().unwrap_or_else(|| Watch::new(&data_dir));
        match tokio::task::spawn_blocking(move || {
            current.tick(unix_now());
            current
        })
        .await
        {
            Ok(current) => watch = Some(current),
            // A panic loses the history the next sample would difference
            // against, nothing more: the next tick starts a fresh watcher.
            Err(error) => eprintln!("[insight] sampling failed, starting over: {error}"),
        }
    }
}

#[cfg(windows)]
async fn windows_events_forever(data_dir: PathBuf) {
    use crate::events::{LOGS, parse_cursors, read_log};
    let cursor_path = store::dir(&data_dir).join("events-cursor");
    let mut cursors = std::fs::read_to_string(&cursor_path).map(|text| parse_cursors(&text)).unwrap_or_default();
    let mut store = Store::new(&data_dir);
    let mut log = ErrorLog::default();
    let mut polls = interval(crate::EVENTS_EVERY);
    polls.set_missed_tick_behavior(MissedTickBehavior::Delay);
    loop {
        polls.tick().await;
        for (name, levels) in LOGS {
            let cursor = cursors.iter().find(|(log, _)| log == name).map(|(_, id)| *id);
            let read = read_log(name, levels, cursor).await;
            let Some(newest) = read.as_ref().ok().and_then(|events| events.iter().map(|e| e.record_id).max()) else {
                log.report(name, read.map(drop));
                continue;
            };
            let mut recorded = Ok(());
            for event in read.iter().flatten() {
                recorded = recorded.and_then(|()| store.append_event(&event.to_event()));
            }
            cursors.retain(|(log, _)| log != name);
            cursors.push((name.to_owned(), newest));
            let text: String = cursors.iter().map(|(log, id)| format!("{log}={id}\n")).collect();
            log.report(name, recorded.and_then(|()| store::replace(&cursor_path, &text)));
        }
    }
}

/// Elsewhere there are no Windows event logs to read.
#[cfg(not(windows))]
async fn windows_events_forever(_data_dir: PathBuf) {}

/// Logs a failure when it starts or changes, and its recovery once.
#[derive(Default)]
struct ErrorLog {
    last: Option<String>,
}

impl ErrorLog {
    fn report(&mut self, doing: &str, result: io::Result<()>) {
        match result {
            Ok(()) if self.last.take().is_some() => eprintln!("[insight] {doing}: working again"),
            Ok(()) => {}
            Err(error) => {
                let message = format!("{doing}: {error}");
                if self.last.as_deref() != Some(message.as_str()) {
                    eprintln!("[insight] {message}");
                    self.last = Some(message);
                }
            }
        }
    }
}

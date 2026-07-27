//! A bounded, sequence-numbered tail of a service's output.
//!
//! The console polls for new output rather than holding a stream open, so every
//! line carries a sequence number and a reader asks for "everything after N".
//! The buffer is bounded, which means a reader that falls behind will have lines
//! evicted from under it — so [`LogSlice`] reports how many were lost instead of
//! handing back a shorter answer that looks complete. A silent gap in a log is
//! worse than no log, because it is read as evidence that nothing happened.

use selfhost_json::Json;
use std::collections::VecDeque;

/// Which of the process's two output streams a line came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Stream {
    /// Standard output.
    Stdout,
    /// Standard error. Shown distinctly, since most programs report trouble here.
    Stderr,
}

impl Stream {
    /// The wire name used in the admin API.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Stdout => "stdout",
            Self::Stderr => "stderr",
        }
    }
}

/// One captured line.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LogLine {
    /// Monotonic position in this service's output, never reused.
    pub seq: u64,
    /// Which stream produced it.
    pub stream: Stream,
    /// The text, with any trailing newline removed.
    pub text: String,
}

impl LogLine {
    /// The line as it goes over the wire.
    pub fn to_json(&self) -> Json {
        Json::object([
            ("seq", Json::Number(self.seq as f64)),
            ("stream", Json::string(self.stream.as_str())),
            ("text", Json::string(&self.text)),
        ])
    }
}

/// The answer to "give me everything after sequence N".
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LogSlice {
    /// Lines in order, oldest first.
    pub lines: Vec<LogLine>,
    /// Sequence to ask for next time.
    pub next_seq: u64,
    /// How many lines were evicted before the reader got to them.
    ///
    /// Non-zero means the console fell behind and the output it is about to show
    /// is not continuous. It says so rather than pretending.
    pub missed: u64,
}

impl LogSlice {
    /// The slice as it goes over the wire.
    pub fn to_json(&self) -> Json {
        Json::object([
            ("lines", Json::array(self.lines.iter().map(LogLine::to_json))),
            ("nextSeq", Json::Number(self.next_seq as f64)),
            ("missed", Json::Number(self.missed as f64)),
        ])
    }
}

/// A fixed-size ring of recent output lines.
#[derive(Debug)]
pub struct LogRing {
    lines: VecDeque<LogLine>,
    capacity: usize,
    next_seq: u64,
}

impl LogRing {
    /// A ring holding at most `capacity` lines.
    ///
    /// A capacity of zero is raised to one; a ring that cannot hold anything is
    /// never what the caller meant, and silently discarding every line would be
    /// indistinguishable from a service that produces no output.
    pub fn new(capacity: usize) -> Self {
        let capacity = capacity.max(1);
        Self { lines: VecDeque::with_capacity(capacity), capacity, next_seq: 0 }
    }

    /// Appends a line, evicting the oldest if the ring is full.
    pub fn push(&mut self, stream: Stream, text: impl Into<String>) {
        if self.lines.len() == self.capacity {
            self.lines.pop_front();
        }
        self.lines.push_back(LogLine { seq: self.next_seq, stream, text: text.into() });
        self.next_seq += 1;
    }

    /// The sequence a future line will be given.
    pub fn next_seq(&self) -> u64 {
        self.next_seq
    }

    /// The oldest sequence still held, or `next_seq` when the ring is empty.
    pub fn oldest_seq(&self) -> u64 {
        self.lines.front().map(|l| l.seq).unwrap_or(self.next_seq)
    }

    /// How many lines are currently held.
    pub fn len(&self) -> usize {
        self.lines.len()
    }

    /// Whether no output has been captured.
    pub fn is_empty(&self) -> bool {
        self.lines.is_empty()
    }

    /// Every line from `from` onwards, capped at `limit` lines.
    ///
    /// `missed` counts lines that were evicted before `from` could be served.
    pub fn since(&self, from: u64, limit: usize) -> LogSlice {
        let oldest = self.oldest_seq();
        let missed = oldest.saturating_sub(from);

        let lines: Vec<LogLine> = self
            .lines
            .iter()
            .filter(|line| line.seq >= from)
            .take(limit)
            .cloned()
            .collect();

        // Resume from the last line handed out, not from the ring's head, or a
        // reader hitting the limit would skip everything it did not receive.
        let next_seq = lines.last().map(|l| l.seq + 1).unwrap_or(self.next_seq);

        LogSlice { lines, next_seq, missed }
    }

    /// Discards all captured output, keeping sequence numbers moving forward.
    ///
    /// Sequences are deliberately not rewound: a console holding an old position
    /// would otherwise be handed unrelated lines under numbers it thinks it has
    /// already seen.
    pub fn clear(&mut self) {
        self.lines.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ring_of(capacity: usize, count: u64) -> LogRing {
        let mut ring = LogRing::new(capacity);
        for i in 0..count {
            ring.push(Stream::Stdout, format!("line {i}"));
        }
        ring
    }

    #[test]
    fn reads_back_everything_it_was_given() {
        let ring = ring_of(10, 3);
        let slice = ring.since(0, 100);
        assert_eq!(slice.lines.len(), 3);
        assert_eq!(slice.lines[0].text, "line 0");
        assert_eq!(slice.next_seq, 3);
        assert_eq!(slice.missed, 0);
    }

    #[test]
    fn an_incremental_reader_sees_only_what_is_new() {
        let mut ring = ring_of(10, 3);
        let first = ring.since(0, 100);
        assert_eq!(first.next_seq, 3);

        ring.push(Stream::Stderr, "fresh");
        let second = ring.since(first.next_seq, 100);
        assert_eq!(second.lines.len(), 1);
        assert_eq!(second.lines[0].text, "fresh");
        assert_eq!(second.lines[0].stream, Stream::Stderr);
    }

    #[test]
    fn a_reader_that_fell_behind_is_told_how_much_it_lost() {
        // The bug this guards: returning the surviving lines with no signal, so a
        // gap in the output reads as a period where the service said nothing.
        let ring = ring_of(4, 10);
        let slice = ring.since(0, 100);
        assert_eq!(slice.lines.len(), 4);
        assert_eq!(slice.missed, 6, "six lines were evicted before the reader arrived");
        assert_eq!(slice.lines[0].text, "line 6");
    }

    #[test]
    fn a_caught_up_reader_is_never_told_it_missed_anything() {
        let ring = ring_of(4, 10);
        let slice = ring.since(ring.oldest_seq(), 100);
        assert_eq!(slice.missed, 0);
    }

    #[test]
    fn hitting_the_limit_resumes_from_the_last_line_delivered() {
        // The bug this guards: advancing next_seq past lines that were not
        // returned, which drops them permanently for that reader.
        let ring = ring_of(100, 10);
        let slice = ring.since(0, 3);
        assert_eq!(slice.lines.len(), 3);
        assert_eq!(slice.next_seq, 3);

        let rest = ring.since(slice.next_seq, 100);
        assert_eq!(rest.lines.len(), 7);
        assert_eq!(rest.lines[0].text, "line 3");
    }

    #[test]
    fn the_ring_never_grows_past_its_capacity() {
        let ring = ring_of(5, 1000);
        assert_eq!(ring.len(), 5);
        assert_eq!(ring.next_seq(), 1000);
    }

    #[test]
    fn asking_from_beyond_the_end_returns_nothing_and_does_not_rewind() {
        let ring = ring_of(10, 3);
        let slice = ring.since(99, 100);
        assert!(slice.lines.is_empty());
        assert_eq!(slice.next_seq, 3);
        assert_eq!(slice.missed, 0);
    }

    #[test]
    fn clearing_keeps_sequences_moving_so_stale_readers_are_not_confused() {
        let mut ring = ring_of(10, 5);
        ring.clear();
        assert!(ring.is_empty());
        ring.push(Stream::Stdout, "after");
        // Not 0: a console still holding seq 3 must not be handed this line as
        // though it were the one it already displayed.
        assert_eq!(ring.since(0, 10).lines[0].seq, 5);
    }

    #[test]
    fn a_zero_capacity_ring_still_holds_one_line() {
        let mut ring = LogRing::new(0);
        ring.push(Stream::Stdout, "kept");
        assert_eq!(ring.len(), 1);
    }
}

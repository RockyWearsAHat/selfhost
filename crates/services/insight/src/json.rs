//! The on-disk and on-the-wire shape of every insight type. One mapping serves
//! both, so the NDJSON history and the admin API can never disagree.

use crate::{DiskSample, Event, NetSample, ProcessSample, Sample};
use selfhost_json::Json;

pub(crate) fn num(value: u64) -> Json {
    Json::Number(value as f64)
}

/// A float rounded to two places: enough for a chart, and lines stay short.
pub(crate) fn real(value: f64) -> Json {
    Json::Number((value * 100.0).round() / 100.0)
}

pub(crate) fn text(value: &str) -> Json {
    Json::String(value.to_owned())
}

fn u64_of(json: &Json, key: &str) -> u64 {
    json.get(key).and_then(Json::as_u64).unwrap_or(0)
}

fn str_of(json: &Json, key: &str) -> String {
    json.get(key).and_then(Json::as_str).unwrap_or_default().to_owned()
}

fn list_of<T>(json: &Json, key: &str, each: impl Fn(&Json) -> Option<T>) -> Vec<T> {
    json.get(key)
        .and_then(Json::as_array)
        .map(|items| items.iter().filter_map(each).collect())
        .unwrap_or_default()
}

impl Sample {
    /// The JSON form, as stored and served. Processes are left out when there
    /// are none, which is five samples in six.
    pub fn to_json(&self) -> Json {
        let mut fields = vec![
            ("at_unix", num(self.at_unix)),
            ("cpu_pct", self.cpu_pct.map_or(Json::Null, real)),
            ("mem_total_mb", num(self.mem_total_mb)),
            ("mem_used_mb", num(self.mem_used_mb)),
            ("commit_limit_mb", num(self.commit_limit_mb)),
            ("commit_used_mb", num(self.commit_used_mb)),
            ("disks", Json::array(self.disks.iter().map(DiskSample::to_json))),
            ("net", Json::array(self.net.iter().map(NetSample::to_json))),
        ];
        if !self.processes.is_empty() {
            fields.push(("processes", Json::array(self.processes.iter().map(ProcessSample::to_json))));
        }
        Json::object(fields)
    }

    /// Reads the JSON form back; `None` if it is not a sample.
    pub fn from_json(json: &Json) -> Option<Self> {
        Some(Self {
            at_unix: json.get("at_unix")?.as_u64()?,
            cpu_pct: json.get("cpu_pct").and_then(Json::as_f64),
            mem_total_mb: u64_of(json, "mem_total_mb"),
            mem_used_mb: u64_of(json, "mem_used_mb"),
            commit_limit_mb: u64_of(json, "commit_limit_mb"),
            commit_used_mb: u64_of(json, "commit_used_mb"),
            disks: list_of(json, "disks", DiskSample::from_json),
            net: list_of(json, "net", NetSample::from_json),
            processes: list_of(json, "processes", ProcessSample::from_json),
        })
    }
}

impl DiskSample {
    /// The JSON form.
    pub fn to_json(&self) -> Json {
        Json::object([
            ("mount", text(&self.mount)),
            ("total_mb", num(self.total_mb)),
            ("free_mb", num(self.free_mb)),
        ])
    }

    fn from_json(json: &Json) -> Option<Self> {
        Some(Self {
            mount: json.get("mount")?.as_str()?.to_owned(),
            total_mb: u64_of(json, "total_mb"),
            free_mb: u64_of(json, "free_mb"),
        })
    }
}

impl NetSample {
    /// The JSON form.
    pub fn to_json(&self) -> Json {
        Json::object([
            ("name", text(&self.name)),
            ("rx_bps", num(self.rx_bps)),
            ("tx_bps", num(self.tx_bps)),
            ("errors", num(self.errors)),
            ("discards", num(self.discards)),
        ])
    }

    fn from_json(json: &Json) -> Option<Self> {
        Some(Self {
            name: json.get("name")?.as_str()?.to_owned(),
            rx_bps: u64_of(json, "rx_bps"),
            tx_bps: u64_of(json, "tx_bps"),
            errors: u64_of(json, "errors"),
            discards: u64_of(json, "discards"),
        })
    }
}

impl ProcessSample {
    /// The JSON form.
    pub fn to_json(&self) -> Json {
        Json::object([
            ("pid", num(u64::from(self.pid))),
            ("name", text(&self.name)),
            ("cpu_cores", real(self.cpu_cores)),
            ("working_set_mb", num(self.working_set_mb)),
            ("private_mb", num(self.private_mb)),
            ("handles", num(u64::from(self.handles))),
        ])
    }

    fn from_json(json: &Json) -> Option<Self> {
        Some(Self {
            pid: u32::try_from(json.get("pid")?.as_u64()?).ok()?,
            name: str_of(json, "name"),
            cpu_cores: json.get("cpu_cores").and_then(Json::as_f64).unwrap_or(0.0),
            working_set_mb: u64_of(json, "working_set_mb"),
            private_mb: u64_of(json, "private_mb"),
            handles: u32::try_from(u64_of(json, "handles")).unwrap_or(u32::MAX),
        })
    }
}

impl Event {
    /// The JSON form.
    pub fn to_json(&self) -> Json {
        Json::object([
            ("at_unix", num(self.at_unix)),
            ("kind", text(&self.kind)),
            ("source", text(&self.source)),
            ("title", text(&self.title)),
            ("evidence", self.evidence.clone()),
        ])
    }

    /// Reads the JSON form back; `None` if it is not an event.
    pub fn from_json(json: &Json) -> Option<Self> {
        Some(Self {
            at_unix: json.get("at_unix")?.as_u64()?,
            kind: json.get("kind")?.as_str()?.to_owned(),
            source: str_of(json, "source"),
            title: str_of(json, "title"),
            evidence: json.get("evidence").cloned().unwrap_or(Json::Null),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_sample_survives_its_own_json() {
        let sample = Sample {
            at_unix: 1_790_000_000,
            cpu_pct: Some(12.5),
            mem_total_mb: 32_000,
            mem_used_mb: 20_000,
            commit_limit_mb: 40_000,
            commit_used_mb: 25_000,
            disks: vec![DiskSample { mount: "C:\\".into(), total_mb: 1_000_000, free_mb: 250_000 }],
            net: vec![NetSample { name: "Ethernet".into(), rx_bps: 1000, tx_bps: 2000, errors: 1, discards: 0 }],
            processes: vec![ProcessSample {
                pid: 7316,
                name: "selfhost.exe".into(),
                cpu_cores: 1.0,
                working_set_mb: 23,
                private_mb: 30,
                handles: 512,
            }],
        };
        let line = sample.to_json().to_text();
        let back = Sample::from_json(&selfhost_json::parse(&line).unwrap()).unwrap();
        assert_eq!(back, sample);
    }

    #[test]
    fn a_first_sample_has_no_cpu_and_no_processes_on_disk() {
        let sample = Sample { at_unix: 5, ..Sample::default() };
        let json = sample.to_json();
        assert!(json.get("cpu_pct").unwrap().is_null());
        assert!(json.get("processes").is_none());
        assert_eq!(Sample::from_json(&json).unwrap(), sample);
    }
}

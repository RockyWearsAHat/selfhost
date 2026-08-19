//! The live state of the house, and the one place it is mutated.
//!
//! Everything else in this crate either produces facts (a driver) or renders
//! them (the API). The hub is where they meet, and it exists so that there is
//! exactly one answer to "what is true right now" — a dashboard that asks two
//! places and gets two answers is the failure this design is shaped to avoid.
//!
//! # Why it polls rather than listening
//!
//! Sonos offers GENA eventing: subscribe with a callback URL and the speaker
//! POSTs every state change within milliseconds. It is implemented and tested
//! in [`crate::sonos::event`], and it is deliberately **not wired up here**.
//!
//! A callback URL is a URL the *speaker* must reach, so using it means binding
//! a socket on the LAN interface. This box has a real public IP, and
//! `docs/SECURITY.md` sets default-deny with exactly one intended public
//! surface — the reverse proxy. Opening a second one to save a second of
//! latency on two speakers is not a trade this deployment should make without
//! going through that guidebook's checklist deliberately, and "we needed it
//! for a volume slider" is not the argument that should carry it.
//!
//! Polling costs a handful of TCP connections every couple of seconds on a
//! LAN, which is nothing, and it fails in the way one wants: a speaker that
//! goes away stops answering and is marked unreachable on the next pass,
//! whereas a subscription that silently lapses leaves a dashboard confidently
//! showing state that stopped being true an hour ago. The parser stays because
//! the day the checklist is run, the hard half is already written and proved.
//!
//! # The generation counter
//!
//! Every mutation bumps `generation`. The page polls once a second and redraws
//! only when the number moved, so an idle house costs one small request a
//! second and no rendering at all — which is the browser's version of the
//! rule that an idle console must stop drawing.

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use crate::device::{Command, Device, DeviceId};
use crate::discovery;
use crate::registry::Registry;
use crate::sonos;
use crate::wiz;

/// How often every known device's state is re-read, unless the deployment's
/// `[home] refresh_secs` says otherwise.
///
/// Two seconds is under the threshold at which a person pressing pause on
/// their phone and watching the speaker believes the button did not work,
/// while being far enough apart that two speakers cost a negligible amount of
/// the network. Public because the caller with no config at all —
/// `selfhost home mcp` — needs the same defaults the config crate documents.
pub const DEFAULT_REFRESH_EVERY: Duration = Duration::from_secs(2);

/// How often the network is swept for devices that were not there before,
/// unless `[home] discover_secs` says otherwise.
///
/// Much rarer than a refresh: discovery is multicast and a device appearing is
/// a thing that happens when somebody plugs something in, not something worth
/// asking about every two seconds.
pub const DEFAULT_DISCOVER_EVERY: Duration = Duration::from_secs(60);

/// How long a discovery sweep listens.
const DISCOVER_WINDOW: Duration = Duration::from_secs(3);

/// Everything the house currently is.
pub struct Hub {
    /// Devices by id. Ordered, so the page's list does not reshuffle between
    /// polls for no reason.
    devices: Mutex<BTreeMap<DeviceId, Device>>,
    /// Bumped on every change, so the page can skip a render.
    generation: AtomicU64,
    /// The names and rooms a person chose.
    registry: Mutex<Registry>,
    /// Where that registry is kept.
    registry_path: PathBuf,
    /// When set, an admitted command is recorded instead of being sent.
    ///
    /// A test seam, and a deliberately narrow one: it sits *after* the whole
    /// gate — unknown device, unreachable device, missing capability — so the
    /// tests above it exercise every refusal for real and only the final hop
    /// onto the network is stood in for. A seam placed any earlier would let a
    /// gate regress while its tests still passed.
    performed: Option<Mutex<Vec<(DeviceId, Command)>>>,
}

impl Hub {
    /// A hub that will discover its own devices once [`Hub::run`] is spawned.
    #[must_use]
    pub fn new(registry_path: PathBuf) -> Self {
        let registry = Registry::load(&registry_path);
        Hub {
            devices: Mutex::new(BTreeMap::new()),
            generation: AtomicU64::new(1),
            registry: Mutex::new(registry),
            registry_path,
            performed: None,
        }
    }

    /// A hub holding exactly these devices and touching no network.
    ///
    /// Exists for tests of the layers above, which need a house to talk to
    /// without one being present.
    #[must_use]
    pub fn for_test(devices: Vec<Device>) -> Self {
        let map = devices.into_iter().map(|device| (device.id.clone(), device)).collect();
        Hub {
            devices: Mutex::new(map),
            generation: AtomicU64::new(1),
            registry: Mutex::new(Registry::default()),
            registry_path: PathBuf::new(),
            performed: Some(Mutex::new(Vec::new())),
        }
    }

    /// Every command a test hub admitted, in order.
    ///
    /// Empty on a real hub, which sends commands rather than recording them.
    #[must_use]
    pub fn performed(&self) -> Vec<(DeviceId, Command)> {
        self.performed
            .as_ref()
            .map(|log| log.lock().unwrap_or_else(|e| e.into_inner()).clone())
            .unwrap_or_default()
    }

    /// The whole house: its generation, the time, and every visible device.
    ///
    /// The person's own names and rooms are overlaid here rather than being
    /// written into the stored device, so a driver refreshing a device can
    /// never quietly undo a rename.
    pub async fn snapshot(&self) -> (u64, String, Vec<Device>) {
        let generation = self.generation.load(Ordering::Relaxed);
        let devices = {
            let devices = self.devices.lock().unwrap_or_else(|e| e.into_inner());
            let registry = self.registry.lock().unwrap_or_else(|e| e.into_inner());
            devices
                .values()
                .filter(|device| !registry.hidden(&device.id))
                .map(|device| {
                    let mut device = device.clone();
                    registry.apply(&mut device);
                    device
                })
                .collect()
        };
        (generation, now_iso8601(), devices)
    }

    /// Asks one device to do one thing.
    ///
    /// The capability gate is applied here, once, before any driver is
    /// reached: an unknown device, an unreachable one, and one that cannot
    /// perform the command each produce a different sentence, because they are
    /// different problems for the reader.
    pub async fn perform(&self, id: &DeviceId, command: Command) -> Result<(), String> {
        let (device, house) = {
            let devices = self.devices.lock().unwrap_or_else(|e| e.into_inner());
            let device = devices
                .get(id)
                .cloned()
                .ok_or_else(|| "There is no device with that name here.".to_owned())?;
            let house: Vec<Device> = devices.values().cloned().collect();
            (device, house)
        };

        if !device.reachable {
            return Err(device
                .note
                .clone()
                .unwrap_or_else(|| format!("{} is not answering.", device.name)));
        }
        if !device.can(command.needs()) {
            return Err(format!(
                "{} cannot be asked to {}.",
                device.name,
                command.as_str().replace('_', " ")
            ));
        }

        // The seam: a test hub records what it was asked and stops here,
        // having already been through every refusal above.
        if let Some(log) = &self.performed {
            log.lock()
                .unwrap_or_else(|e| e.into_inner())
                .push((device.id.clone(), command));
            self.touch();
            return Ok(());
        }

        let outcome = match device.id.driver() {
            sonos::DRIVER => sonos::perform(&device, &house, &command).await,
            wiz::DRIVER => wiz::perform(&device, &command).await,
            other => Err(format!("Nothing here knows how to drive a {other}.")),
        };

        if outcome.is_ok() {
            // The command landed, so whatever the page is showing is now one
            // step out of date. Refreshing the one device immediately is what
            // makes a button feel instant rather than feeling like it waited
            // for the next poll.
            self.refresh_one(id).await;
        }
        outcome
    }

    /// Renames a device, or clears the name back to what its protocol says.
    pub async fn set_name(&self, id: &DeviceId, name: Option<String>) -> std::io::Result<()> {
        {
            let mut registry = self.registry.lock().unwrap_or_else(|e| e.into_inner());
            registry.set_name(id, name);
        }
        self.save_registry()
    }

    /// Moves a device to a room, or clears the room.
    pub async fn set_room(&self, id: &DeviceId, room: Option<String>) -> std::io::Result<()> {
        {
            let mut registry = self.registry.lock().unwrap_or_else(|e| e.into_inner());
            registry.set_room(id, room);
        }
        self.save_registry()
    }

    /// Hides a device from every snapshot, or shows it again.
    pub async fn set_hidden(&self, id: &DeviceId, hidden: bool) -> std::io::Result<()> {
        {
            let mut registry = self.registry.lock().unwrap_or_else(|e| e.into_inner());
            registry.set_hidden(id, hidden);
        }
        self.save_registry()
    }

    /// Whether the house has ever adopted this device — hidden or not.
    ///
    /// The snapshot cannot answer this, because it filters hidden devices out;
    /// this is what lets a hidden device be shown again by its id instead of
    /// being unreachable through the very door that hid it.
    pub async fn contains(&self, id: &DeviceId) -> bool {
        self.devices.lock().unwrap_or_else(|e| e.into_inner()).contains_key(id)
    }

    /// Performs one act — a device command, or a write to the house's memory.
    ///
    /// This is the one dispatch both surfaces (the HTTP route and the MCP
    /// `command` tool) call, so a word added to the vocabulary reaches both
    /// without either changing. Registry writes are gated only on the device
    /// being known: renaming an unreachable lamp is legitimate — the name is
    /// the person's, not the lamp's — but renaming a typo would write garbage
    /// the registry then carries forever.
    pub async fn apply(&self, id: &DeviceId, act: crate::api::Act) -> Result<(), String> {
        use crate::api::Act;
        match act {
            Act::Command(command) => self.perform(id, command).await,
            Act::Rename(_) | Act::Room(_) | Act::Hide(_) if !self.contains(id).await => {
                Err("There is no device with that name here.".to_owned())
            }
            Act::Rename(name) => self.set_name(id, name).await.map_err(remember_failed),
            Act::Room(room) => self.set_room(id, room).await.map_err(remember_failed),
            Act::Hide(hidden) => self.set_hidden(id, hidden).await.map_err(remember_failed),
        }
    }

    fn save_registry(&self) -> std::io::Result<()> {
        self.touch();
        if self.registry_path.as_os_str().is_empty() {
            return Ok(());
        }
        let registry = self.registry.lock().unwrap_or_else(|e| e.into_inner());
        registry.save(&self.registry_path)
    }

    /// The background loop: sweep for devices, then keep their state true.
    ///
    /// Runs forever and never returns an error, because there is no error a
    /// caller could act on — a network that is down is a network that will be
    /// swept again in a minute, and a hub that exited on the first failure
    /// would take the dashboard down with it.
    /// The cadence is the caller's: the daemon passes the deployment's
    /// `[home] refresh_secs` / `discover_secs`, and a caller with no config
    /// passes the `DEFAULT_*` constants above — which keeps the config's two
    /// knobs real rather than documented-and-ignored.
    pub async fn run(
        self: std::sync::Arc<Self>,
        refresh_every: Duration,
        discover_every: Duration,
    ) {
        // Sweep once immediately so the first person to open the page does not
        // wait a minute for the house to appear.
        self.discover().await;

        let mut last_sweep = tokio::time::Instant::now();
        loop {
            self.refresh_all().await;
            if last_sweep.elapsed() >= discover_every {
                self.discover().await;
                last_sweep = tokio::time::Instant::now();
            }
            tokio::time::sleep(refresh_every).await;
        }
    }

    /// Sweeps the network and adopts anything new.
    ///
    /// A device already known keeps its state: discovery answers "what is
    /// there", not "what is it doing", and letting a sweep reset a playing
    /// speaker to blank would make the page flicker every minute.
    pub async fn discover(&self) {
        // The two sweeps ask different networks-within-the-network — SSDP is
        // multicast, WiZ is broadcast — and neither waits on the other, so
        // they share the window rather than queuing behind each other.
        let (found, lights) =
            tokio::join!(discovery::sweep(DISCOVER_WINDOW), wiz::discover(DISCOVER_WINDOW));
        self.adopt(lights);

        // One Sonos answers for the whole household, so the first one found is
        // enough to learn every speaker — asking each of them the same
        // question would return the same document N times.
        if let Some(seed) = found.iter().find(|f| f.kind == discovery::FoundKind::Sonos) {
            match sonos::household(&seed.address).await {
                Ok(speakers) => self.adopt(speakers),
                Err(error) => eprintln!("[home] the Sonos household did not answer: {error}"),
            }
        }

        // A Fire TV is recorded even though nothing can drive it yet, because
        // "your television is here but ADB is switched off" is a fact the
        // reader needs in order to fix it, and an empty page is not.
        for firetv in found.iter().filter(|f| f.kind == discovery::FoundKind::FireTv) {
            let mut device = Device::new(
                DeviceId::new("firetv", &firetv.address),
                firetv.name.clone().unwrap_or_else(|| "Fire TV".to_owned()),
                crate::device::Kind::Television,
            );
            device.address = Some(firetv.address.clone());
            device.reachable = false;
            device.note = Some(
                "The debug bridge is not enabled on this television, so nothing here can drive it yet."
                    .to_owned(),
            );
            self.adopt(vec![device]);
        }
    }

    /// Folds newly-discovered devices into the house.
    fn adopt(&self, discovered: Vec<Device>) {
        let mut changed = false;
        {
            let mut devices = self.devices.lock().unwrap_or_else(|e| e.into_inner());
            for device in discovered {
                match devices.get_mut(&device.id) {
                    // Known already: take the facts discovery is authoritative
                    // about and leave the rest, so a playing speaker does not
                    // blink every time the network is swept.
                    Some(existing) => {
                        if existing.name != device.name
                            || existing.address != device.address
                            || existing.state.group != device.state.group
                            || existing.state.coordinator != device.state.coordinator
                        {
                            existing.name = device.name;
                            existing.address = device.address;
                            existing.state.coordinator = device.state.coordinator;
                            existing.state.group = device.state.group;
                            existing.state.battery_pct = device.state.battery_pct;
                            existing.state.battery_charging = device.state.battery_charging;
                            changed = true;
                        }
                    }
                    None => {
                        devices.insert(device.id.clone(), device);
                        changed = true;
                    }
                }
            }
        }
        if changed {
            self.touch();
        }
    }

    /// Re-reads every device's state.
    async fn refresh_all(&self) {
        let ids: Vec<DeviceId> = {
            let devices = self.devices.lock().unwrap_or_else(|e| e.into_inner());
            devices.keys().cloned().collect()
        };
        for id in ids {
            self.refresh_one(&id).await;
        }
    }

    /// Re-reads one device's state, and bumps the generation if it moved.
    ///
    /// The device is cloned out, refreshed without the lock held, and written
    /// back. Holding a mutex across an `await` on a network call would stall
    /// every request for as long as the slowest speaker takes to answer.
    async fn refresh_one(&self, id: &DeviceId) {
        let Some(mut device) = self
            .devices
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get(id)
            .cloned()
        else {
            return;
        };

        let before = device.clone();
        match device.id.driver() {
            sonos::DRIVER => sonos::refresh(&mut device).await,
            wiz::DRIVER => wiz::refresh(&mut device).await,
            // A driver that does not exist yet leaves the device exactly as
            // discovery left it, note and all.
            _ => return,
        }

        if device != before {
            self.devices
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .insert(id.clone(), device);
            self.touch();
        }
    }

    /// Records that something changed.
    fn touch(&self) {
        self.generation.fetch_add(1, Ordering::Relaxed);
    }
}

/// The sentence for a registry write that could not reach disk.
///
/// The change *has* been applied in memory — the page shows it — so the
/// sentence says what was actually lost: durability, not the act.
fn remember_failed(error: std::io::Error) -> String {
    format!("The change is made but could not be saved, so it will not survive a restart: {error}")
}

/// The current time as `YYYY-MM-DDTHH:MM:SSZ`.
///
/// Written here rather than pulled from another crate because the only thing
/// this crate needs a clock for is stamping a snapshot, and a dependency on a
/// service crate for one timestamp would be a dependency edge that outlives
/// the reason for it. Days are converted with the civil-from-days algorithm,
/// which is exact for every date and carries no table.
#[must_use]
pub fn now_iso8601() -> String {
    let seconds = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |since| since.as_secs());
    iso8601(seconds)
}

/// Formats a Unix timestamp as `YYYY-MM-DDTHH:MM:SSZ`.
#[must_use]
pub fn iso8601(unix_seconds: u64) -> String {
    let days = (unix_seconds / 86_400) as i64;
    let time = unix_seconds % 86_400;
    let (year, month, day) = civil_from_days(days);
    format!(
        "{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}Z",
        time / 3600,
        (time % 3600) / 60,
        time % 60
    )
}

/// Howard Hinnant's `civil_from_days`: a Unix day number to a calendar date.
fn civil_from_days(days: i64) -> (i64, u32, u32) {
    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let day_of_era = (z - era * 146_097) as u64;
    let year_of_era =
        (day_of_era - day_of_era / 1460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let year = year_of_era as i64 + era * 400;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let mp = (5 * day_of_year + 2) / 153;
    let day = (day_of_year - (153 * mp + 2) / 5 + 1) as u32;
    let month = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    (if month <= 2 { year + 1 } else { year }, month, day)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::device::{Capability, Kind, Transport};

    fn speaker(key: &str, name: &str) -> Device {
        let mut device = Device::new(sonos::id_of(key), name, Kind::Speaker)
            .advertise(&[Capability::Transport, Capability::Volume]);
        device.reachable = true;
        device.address = Some("192.168.1.6".into());
        device
    }

    #[tokio::test]
    async fn a_snapshot_carries_every_device() {
        let hub = Hub::for_test(vec![speaker("RINCON_A", "Kitchen"), speaker("RINCON_B", "Move")]);
        let (_, _, devices) = hub.snapshot().await;
        assert_eq!(devices.len(), 2);
    }

    #[tokio::test]
    async fn an_unknown_device_is_refused_in_words() {
        let hub = Hub::for_test(Vec::new());
        let error = hub
            .perform(&DeviceId::from_wire("sonos:nobody"), Command::Play)
            .await
            .expect_err("must refuse");
        assert!(error.contains("no device"));
    }

    /// Three different problems must produce three different sentences, or the
    /// reader cannot tell which one they have.
    #[tokio::test]
    async fn a_capability_the_device_lacks_is_refused_by_name() {
        let hub = Hub::for_test(vec![speaker("RINCON_A", "Kitchen")]);
        let error = hub
            .perform(&sonos::id_of("RINCON_A"), Command::Brightness(50))
            .await
            .expect_err("a speaker has no brightness");
        assert!(error.contains("Kitchen"));
        assert!(error.contains("brightness"));
    }

    #[tokio::test]
    async fn an_unreachable_device_says_so_rather_than_timing_out() {
        let mut absent = speaker("RINCON_A", "Kitchen");
        absent.reachable = false;
        absent.note = Some("Kitchen did not answer.".into());
        let hub = Hub::for_test(vec![absent]);
        let error = hub
            .perform(&sonos::id_of("RINCON_A"), Command::Play)
            .await
            .expect_err("must refuse");
        assert_eq!(error, "Kitchen did not answer.");
    }

    #[tokio::test]
    async fn a_rename_survives_into_the_snapshot() {
        let hub = Hub::for_test(vec![speaker("RINCON_A", "Kitchen")]);
        hub.set_name(&sonos::id_of("RINCON_A"), Some("Coffee Corner".into()))
            .await
            .expect("no file to write in a test hub");
        let (_, _, devices) = hub.snapshot().await;
        assert_eq!(devices[0].name, "Coffee Corner");
    }

    #[tokio::test]
    async fn an_act_on_a_device_the_house_never_adopted_is_refused() {
        let hub = Hub::for_test(Vec::new());
        let error = hub
            .apply(&DeviceId::from_wire("wiz:nobody"), crate::api::Act::Rename(Some("Porch".into())))
            .await
            .expect_err("a typo must not become a registry entry");
        assert!(error.contains("no device"));
    }

    #[tokio::test]
    async fn a_rename_through_apply_lands_in_the_snapshot() {
        let hub = Hub::for_test(vec![speaker("RINCON_A", "Kitchen")]);
        hub.apply(&sonos::id_of("RINCON_A"), crate::api::Act::Rename(Some("Coffee Corner".into())))
            .await
            .expect("a known device");
        let (_, _, devices) = hub.snapshot().await;
        assert_eq!(devices[0].name, "Coffee Corner");
    }

    /// Hiding removes the device from every snapshot; showing it again by id
    /// is the reason `contains` looks past the snapshot's filter — otherwise
    /// `show` could never be said through the very door that hid it.
    #[tokio::test]
    async fn a_hidden_device_can_be_shown_again_by_its_id() {
        let hub = Hub::for_test(vec![speaker("RINCON_A", "Kitchen")]);
        let id = sonos::id_of("RINCON_A");
        hub.apply(&id, crate::api::Act::Hide(true)).await.expect("a known device");
        assert!(hub.snapshot().await.2.is_empty(), "hidden means not in the snapshot");
        assert!(hub.contains(&id).await, "hidden must not mean forgotten");
        hub.apply(&id, crate::api::Act::Hide(false)).await.expect("a known device");
        assert_eq!(hub.snapshot().await.2.len(), 1);
    }

    /// `apply` is a door, not a second gate: a device command passes through
    /// to `perform` and meets the same checks it always did.
    #[tokio::test]
    async fn a_device_command_through_apply_reaches_perform() {
        let hub = Hub::for_test(vec![speaker("RINCON_A", "Kitchen")]);
        hub.apply(&sonos::id_of("RINCON_A"), crate::api::Act::Command(Command::Play))
            .await
            .expect("an admitted command");
        assert_eq!(hub.performed(), vec![(sonos::id_of("RINCON_A"), Command::Play)]);
    }

    /// The rename must be an overlay: a driver refreshing the device from the
    /// speaker's own name must not quietly undo it.
    #[tokio::test]
    async fn a_refresh_cannot_undo_a_rename() {
        let hub = Hub::for_test(vec![speaker("RINCON_A", "Kitchen")]);
        hub.set_name(&sonos::id_of("RINCON_A"), Some("Coffee Corner".into()))
            .await
            .expect("no file");
        // Whatever the driver writes back, the stored name stays the
        // protocol's and the overlay stays the person's.
        {
            let mut devices = hub.devices.lock().unwrap();
            let device = devices.get_mut(&sonos::id_of("RINCON_A")).unwrap();
            device.name = "Kitchen".into();
            device.state.transport = Some(Transport::Playing);
        }
        let (_, _, devices) = hub.snapshot().await;
        assert_eq!(devices[0].name, "Coffee Corner");
        assert_eq!(devices[0].state.transport, Some(Transport::Playing));
    }

    #[tokio::test]
    async fn the_generation_moves_when_something_changes() {
        let hub = Hub::for_test(vec![speaker("RINCON_A", "Kitchen")]);
        let (before, _, _) = hub.snapshot().await;
        hub.set_room(&sonos::id_of("RINCON_A"), Some("Kitchen".into()))
            .await
            .expect("no file");
        let (after, _, _) = hub.snapshot().await;
        assert!(after > before, "a change must bump the generation");
    }

    /// Adopting the same discovery twice must not look like a change, or an
    /// idle house would bump its generation every sweep and the page would
    /// redraw every minute for nothing.
    #[tokio::test]
    async fn adopting_an_unchanged_device_does_not_bump_the_generation() {
        let hub = Hub::for_test(vec![speaker("RINCON_A", "Kitchen")]);
        let (before, _, _) = hub.snapshot().await;
        hub.adopt(vec![speaker("RINCON_A", "Kitchen")]);
        let (after, _, _) = hub.snapshot().await;
        assert_eq!(before, after);
    }

    /// The seam sits after the gate, so an admitted command reaches it and a
    /// refused one never does.
    #[tokio::test]
    async fn an_admitted_command_is_recorded_and_a_refused_one_is_not() {
        let hub = Hub::for_test(vec![speaker("RINCON_A", "Kitchen")]);
        hub.perform(&sonos::id_of("RINCON_A"), Command::Play)
            .await
            .expect("a speaker admits play");
        hub.perform(&sonos::id_of("RINCON_A"), Command::Brightness(50))
            .await
            .expect_err("a speaker has no brightness");
        let performed = hub.performed();
        assert_eq!(performed.len(), 1);
        assert_eq!(performed[0].1, Command::Play);
    }

    #[tokio::test]
    async fn a_newly_discovered_device_is_adopted() {
        let hub = Hub::for_test(Vec::new());
        hub.adopt(vec![speaker("RINCON_A", "Kitchen")]);
        let (_, _, devices) = hub.snapshot().await;
        assert_eq!(devices.len(), 1);
    }

    #[test]
    fn the_epoch_formats_correctly() {
        assert_eq!(iso8601(0), "1970-01-01T00:00:00Z");
    }

    #[test]
    fn a_known_timestamp_formats_correctly() {
        // 2026-08-17T19:20:00Z
        assert_eq!(iso8601(1_786_994_400), "2026-08-17T19:20:00Z");
    }

    /// A leap day is the day it says it is — the arithmetic here is exact
    /// rather than approximate, and this is the case that proves it.
    #[test]
    fn a_leap_day_is_the_day_it_says_it_is() {
        // 2024-02-29T12:00:00Z
        assert_eq!(iso8601(1_709_208_000), "2024-02-29T12:00:00Z");
    }

    #[test]
    fn the_end_of_a_year_rolls_over_correctly() {
        // 2025-12-31T23:59:59Z
        assert_eq!(iso8601(1_767_225_599), "2025-12-31T23:59:59Z");
    }
}

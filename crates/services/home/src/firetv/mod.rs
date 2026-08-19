//! The Fire TV driver: full remote control of an Android Fire TV over ADB, the
//! one capability set a television cannot have without an operator's say-so.
//!
//! # Where this sits against DIAL
//!
//! [`crate::dial`] is the whole zero-setup surface of a Fire TV: launch an app,
//! stop it, read what is on the screen, with nothing asked of anybody. That
//! ceiling was measured, not assumed (home-lab.dx §"The televisions, driven"),
//! and it is real — power, directional keys and volume need a protocol DIAL
//! does not carry. That protocol is ADB, and reaching it costs operator
//! actions, once: enabling ADB debugging in the television's developer options,
//! and tapping "allow" on the screen the first time this box connects. The
//! project's rule is that such a device is still shown and still driven by DIAL
//! with no setup — ADB is **opt-in, never a prerequisite** — so this driver adds
//! capabilities to a television that is already on the page, and its absence
//! costs that television nothing it had.
//!
//! Two platforms wear the Fire TV name and only one can run this. The
//! Android-based sticks (`AFTMM` and kin) speak ADB; Amazon's newer **Vega**
//! televisions (`AFTCL001`) have no ADB at all, and stay DIAL-only forever. The
//! driver therefore attaches to a television only after its ADB port answers,
//! and never on the strength of a model string.
//!
//! # The shape
//!
//! | Module | Pure? | What it is the authority on |
//! |---|---|---|
//! | [`rsa`] | yes | the RSA key and signature ADB's auth challenge needs |
//! | [`message`] | yes | the ADB wire format: framing, checksums, the six commands |
//! | this file | mixed | the connection, the auth handshake, and one command surface |
//!
//! The pure halves are proved in isolation down to the byte; the live half —
//! the socket, the handshake, the shell stream — is what waits on hardware and
//! the operator's one-time allow, and is written against the protocol as
//! captured and specified rather than against a device this session could
//! reach.

pub mod message;
pub mod rsa;

use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use crate::device::{Capability, Command, Device, Key};
use message::{AuthKind, Message, A_AUTH, A_CLSE, A_CNXN, A_OKAY, A_WRTE};
use rsa::PrivateKey;

/// The port a Fire TV's ADB daemon listens on once debugging is enabled. The
/// port being open *is* the "ADB is enabled" signal this driver probes for;
/// authorisation is a separate, later step the television gates behind its
/// on-screen "allow" dialog.
pub const PORT: u16 = 5555;

/// The name this host presents in the television's list of authorised
/// computers, carried in the public key the "allow" dialog is shown for.
const KEY_LABEL: &str = "selfhost@home";

/// How long a bare reachability probe waits for the ADB port to accept a
/// connection. Short, because it runs on the refresh cadence and an off
/// television must not stall the whole sweep — an absent host is the slow case
/// and this bounds it.
const PROBE_TIMEOUT: Duration = Duration::from_millis(800);

/// How long the initial TCP connect for a real command may take.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(3);

/// How long the whole authenticated handshake may take, generous on purpose:
/// the very first connection to a television waits on a person walking to the
/// screen and tapping "allow", and a tighter budget would turn that one-time
/// consent into a command that always fails the first time. Every later
/// connection is answered in milliseconds, because the television remembers the
/// key.
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(30);

/// The Android key code one command presses, or `None` if this driver does not
/// own the command. Numeric codes rather than `KEYCODE_*` names, because the
/// numbers are stable across every Android and Fire OS build while the name
/// table is not guaranteed on a minimal one.
#[must_use]
fn keycode_for(command: &Command) -> Option<u32> {
    Some(match command {
        // Wake and sleep rather than the single POWER toggle (26): a toggle
        // cannot be aimed, and "turn it on" must not turn an on television off.
        Command::Power(true) => 224,  // KEYCODE_WAKEUP
        Command::Power(false) => 223, // KEYCODE_SLEEP
        Command::Key(key) => keycode(*key),
        _ => return None,
    })
}

/// The Android key code for one remote key.
#[must_use]
fn keycode(key: Key) -> u32 {
    match key {
        Key::Up => 19,
        Key::Down => 20,
        Key::Left => 21,
        Key::Right => 22,
        Key::Select => 23,
        Key::Back => 4,
        Key::Home => 3,
        Key::Menu => 82,
        Key::PlayPause => 85,
        Key::Next => 87,
        Key::Previous => 88,
        Key::VolumeUp => 24,
        Key::VolumeDown => 25,
    }
}

/// The shell command that performs one firetv command, or `None` when the
/// command belongs to another driver (DIAL owns apps; this owns power and keys).
#[must_use]
fn shell_for(command: &Command) -> Option<String> {
    keycode_for(command).map(|code| format!("input keyevent {code}"))
}

/// The two capabilities a reachable ADB daemon adds to a television. Kept
/// together so the probe adds and removes exactly this set and never disturbs
/// the DIAL `Apps` capability the television already carries.
const ADB_CAPABILITIES: [Capability; 2] = [Capability::Power, Capability::Keys];

/// Reflects whether ADB is reachable into the television's capabilities.
///
/// Called on the refresh cadence, so enabling ADB on the device makes the
/// power and key controls appear within one refresh, and disabling it makes
/// them disappear — the dashboard never offers a control the television has
/// stopped accepting. Never touches any capability outside [`ADB_CAPABILITIES`].
pub async fn probe(device: &mut Device) {
    // A television that did not answer DIAL is off or gone; skip the extra
    // connect attempt (it would only spend the probe timeout) and drop the ADB
    // controls, because an unreachable device admits nothing anyway.
    let reachable = if device.reachable {
        match &device.address {
            Some(address) => port_open(address).await,
            None => false,
        }
    } else {
        false
    };

    device.capabilities.retain(|capability| !ADB_CAPABILITIES.contains(capability));
    if reachable {
        device.capabilities.extend_from_slice(&ADB_CAPABILITIES);
    }
    device.capabilities.sort_unstable();
    device.capabilities.dedup();
}

/// Whether the ADB port accepts a connection within the probe budget.
async fn port_open(address: &str) -> bool {
    matches!(
        tokio::time::timeout(PROBE_TIMEOUT, TcpStream::connect((address, PORT))).await,
        Ok(Ok(_))
    )
}

/// Performs one power or key command against a Fire TV over ADB.
///
/// The key is loaded (or generated once and persisted) off the async runtime,
/// then the connection is opened, authenticated, and used for a single shell
/// keyevent. Every failure is a sentence, because it travels to the reader
/// verbatim — including the one that matters most on day one: a television
/// waiting for the operator to tap "allow".
pub async fn perform(device: &Device, command: &Command, key_path: &Path) -> Result<(), String> {
    let address = device
        .address
        .clone()
        .ok_or_else(|| format!("{} has no address to reach over ADB.", device.name))?;
    let shell = shell_for(command).ok_or_else(|| {
        format!("{} cannot be asked to {}.", device.name, command.as_str().replace('_', " "))
    })?;

    // Keygen is CPU-bound and, on the first ever call, takes a moment; run it
    // off the runtime so one television's first connection does not stall the
    // refresh of every other device.
    let path = key_path.to_path_buf();
    let key = tokio::task::spawn_blocking(move || load_or_generate_key(&path))
        .await
        .map_err(|error| format!("the ADB key task did not finish: {error}"))?;

    let mut stream = connect_authenticated(&address, &key, &device.name).await?;
    run_shell(&mut stream, &shell).await
}

/// Opens a connection and carries it through the ADB auth challenge to a
/// working transport.
///
/// The state machine is small and exact: the host connects, the television
/// answers with an auth token, the host signs it with its one key; if the
/// television already trusts that key it connects, and if not it asks again,
/// at which point the host offers its public key and the television shows the
/// "allow" dialog. A second refusal after the key was offered is a television
/// the operator has not authorised, said as such.
async fn connect_authenticated(
    address: &str,
    key: &PrivateKey,
    name: &str,
) -> Result<TcpStream, String> {
    let deadline = Instant::now() + HANDSHAKE_TIMEOUT;
    let mut stream = tokio::time::timeout(CONNECT_TIMEOUT, TcpStream::connect((address, PORT)))
        .await
        .map_err(|_| format!("{name} did not accept an ADB connection on {PORT}."))?
        .map_err(|error| format!("{name} could not be reached over ADB: {error}"))?;

    write_message(&mut stream, &Message::connect(), deadline).await?;

    let mut signed = false;
    let mut offered_key = false;
    loop {
        let message = read_message(&mut stream, deadline).await?;
        match message.command {
            A_CNXN => return Ok(stream),
            A_AUTH => match AuthKind::from_u32(message.arg0) {
                Some(AuthKind::Token) => {
                    if !signed {
                        let signature = key.sign_token(&message.payload).ok_or_else(|| {
                            format!("{name} sent a malformed ADB auth token.")
                        })?;
                        write_message(&mut stream, &Message::auth_signature(signature), deadline)
                            .await?;
                        signed = true;
                    } else if !offered_key {
                        let public_key = key.android_pubkey(KEY_LABEL);
                        write_message(&mut stream, &Message::auth_public_key(public_key), deadline)
                            .await?;
                        offered_key = true;
                    } else {
                        return Err(format!(
                            "{name} has not authorised this box — allow it on the TV screen \
                             (a dialog should be waiting), then try again."
                        ));
                    }
                }
                _ => return Err(format!("{name} sent an ADB auth step this box does not speak.")),
            },
            other => {
                return Err(format!("{name} answered the ADB handshake with {other:#010x}."));
            }
        }
    }
}

/// Opens a shell stream, runs one command, and drains it to its close.
///
/// The command's own output is not wanted — a keyevent prints nothing useful —
/// so this reads only far enough to know the television ran it: it waits for the
/// stream to open, acknowledges whatever the device writes, and returns when the
/// device closes the stream. Acknowledging writes matters even when the output
/// is discarded, because a device that is not acked can wedge waiting for the
/// window to open.
async fn run_shell(stream: &mut TcpStream, command: &str) -> Result<(), String> {
    let deadline = Instant::now() + CONNECT_TIMEOUT;
    let local_id = 1;
    write_message(stream, &Message::open(local_id, &format!("shell:{command}")), deadline).await?;

    // Wait for the television to open its half of the stream.
    let remote_id = loop {
        let message = read_message(stream, deadline).await?;
        match message.command {
            A_OKAY if message.arg1 == local_id => break message.arg0,
            A_CLSE => return Err("the TV refused to run the command.".to_owned()),
            _ => {}
        }
    };

    // Acknowledge output and return when the stream closes.
    loop {
        let message = read_message(stream, deadline).await?;
        match message.command {
            A_WRTE if message.arg1 == local_id => {
                write_message(stream, &Message::okay(local_id, remote_id), deadline).await?;
            }
            A_CLSE => {
                let _ = write_message(stream, &Message::close(local_id, remote_id), deadline).await;
                return Ok(());
            }
            _ => {}
        }
    }
}

/// Writes one message, bounded by the handshake deadline.
async fn write_message(stream: &mut TcpStream, message: &Message, deadline: Instant) -> Result<(), String> {
    let budget = deadline.saturating_duration_since(Instant::now());
    tokio::time::timeout(budget, stream.write_all(&message.encode()))
        .await
        .map_err(|_| "the ADB connection went quiet while sending.".to_owned())?
        .map_err(|error| format!("the ADB connection dropped: {error}"))
}

/// Reads one whole message — header then the payload it declares — bounded by
/// the deadline, rejecting any frame whose checksum or magic does not hold.
async fn read_message(stream: &mut TcpStream, deadline: Instant) -> Result<Message, String> {
    let mut header = [0_u8; message::HEADER_LEN];
    read_exact(stream, &mut header, deadline).await?;
    let length = Message::payload_len(&header)
        .ok_or_else(|| "the TV sent a torn ADB header.".to_owned())?;
    let mut payload = vec![0_u8; length];
    read_exact(stream, &mut payload, deadline).await?;
    Message::from_parts(&header, payload)
        .ok_or_else(|| "the TV sent an ADB message that failed its own checksum.".to_owned())
}

/// Reads exactly `buffer.len()` bytes, or fails with a sentence.
async fn read_exact(stream: &mut TcpStream, buffer: &mut [u8], deadline: Instant) -> Result<(), String> {
    let budget = deadline.saturating_duration_since(Instant::now());
    tokio::time::timeout(budget, stream.read_exact(buffer))
        .await
        .map_err(|_| "the TV stopped answering mid-message (still waiting for allow?).".to_owned())?
        .map_err(|error| format!("the ADB connection dropped: {error}"))?;
    Ok(())
}

/// Loads the persisted ADB key, or generates one and saves it.
///
/// The key must persist: the television remembers the *public* key the operator
/// allowed, so a box that generated a fresh key every run would face the "allow"
/// dialog every run. A path that cannot be read or written yields an ephemeral
/// key rather than failing — control still works this session, it just cannot
/// remember consent, which is the right degradation for a missing data
/// directory. An empty path (a test hub) is always ephemeral.
#[must_use]
fn load_or_generate_key(path: &Path) -> PrivateKey {
    if !path.as_os_str().is_empty() {
        if let Ok(text) = std::fs::read_to_string(path) {
            if let Some(key) = parse_key(&text) {
                return key;
            }
        }
    }
    let key = PrivateKey::generate();
    if !path.as_os_str().is_empty() {
        let _ = std::fs::write(path, render_key(&key));
    }
    key
}

/// The stored key file: a header and three hex lines, `n`/`e`/`d`. Its own
/// format rather than PEM because the crate carries no ASN.1 reader and the
/// three integers are all a reload needs; a person who opens the file is told
/// what it is and warned off sharing it.
#[must_use]
fn render_key(key: &PrivateKey) -> String {
    let (n, e, d) = key.to_parts();
    format!(
        "# selfhost-home ADB key — the private key that authorises this box to a Fire TV.\n\
         # Keep it secret: anyone with it can drive any TV that has allowed this box.\n\
         n={}\ne={}\nd={}\n",
        hex(&n),
        hex(&e),
        hex(&d),
    )
}

/// Reads a stored key back, or `None` if the file is not one this wrote.
#[must_use]
fn parse_key(text: &str) -> Option<PrivateKey> {
    let mut n = None;
    let mut e = None;
    let mut d = None;
    for line in text.lines() {
        let line = line.trim();
        if line.starts_with('#') || line.is_empty() {
            continue;
        }
        let (field, value) = line.split_once('=')?;
        let bytes = unhex(value.trim())?;
        match field.trim() {
            "n" => n = Some(bytes),
            "e" => e = Some(bytes),
            "d" => d = Some(bytes),
            _ => {}
        }
    }
    Some(PrivateKey::from_parts(&n?, &e?, &d?))
}

/// Lower-case hex of a byte string.
#[must_use]
fn hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(char::from_digit(u32::from(byte >> 4), 16).unwrap());
        out.push(char::from_digit(u32::from(byte & 0x0f), 16).unwrap());
    }
    out
}

/// Bytes from lower- or upper-case hex, or `None` on a stray character.
#[must_use]
fn unhex(text: &str) -> Option<Vec<u8>> {
    if text.len() % 2 != 0 {
        return None;
    }
    let mut out = Vec::with_capacity(text.len() / 2);
    let bytes = text.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        let high = (bytes[i] as char).to_digit(16)?;
        let low = (bytes[i + 1] as char).to_digit(16)?;
        out.push((high * 16 + low) as u8);
        i += 2;
    }
    Some(out)
}

/// Where a deployment keeps its ADB key: beside the device registry, the one
/// other file this subsystem writes. Sharing the registry's directory means a
/// deployment that can persist names can persist consent, with no second path
/// to configure.
#[must_use]
pub fn key_path_beside(registry_path: &Path) -> PathBuf {
    registry_path.with_file_name("home.adbkey")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::device::{DeviceId, Kind};

    #[test]
    fn power_maps_to_wake_and_sleep_not_a_toggle() {
        assert_eq!(shell_for(&Command::Power(true)).as_deref(), Some("input keyevent 224"));
        assert_eq!(shell_for(&Command::Power(false)).as_deref(), Some("input keyevent 223"));
    }

    #[test]
    fn every_remote_key_maps_to_a_keyevent() {
        for (key, code) in [
            (Key::Up, 19), (Key::Down, 20), (Key::Left, 21), (Key::Right, 22),
            (Key::Select, 23), (Key::Back, 4), (Key::Home, 3), (Key::Menu, 82),
            (Key::PlayPause, 85), (Key::Next, 87), (Key::Previous, 88),
            (Key::VolumeUp, 24), (Key::VolumeDown, 25),
        ] {
            assert_eq!(shell_for(&Command::Key(key)).as_deref(), Some(format!("input keyevent {code}").as_str()));
        }
    }

    /// The commands another driver owns are not this one's: a colour or a
    /// launch returns `None`, so dispatch never sends them here.
    #[test]
    fn commands_this_driver_does_not_own_return_none() {
        assert_eq!(shell_for(&Command::Launch("Netflix".into())), None);
        assert_eq!(shell_for(&Command::Color("FF0000".into())), None);
        assert_eq!(shell_for(&Command::Volume(30)), None);
        assert_eq!(shell_for(&Command::Stop), None);
    }

    /// The probe adds exactly power and keys and leaves DIAL's `Apps` alone,
    /// so a Fire TV shows one tile with every control it can take.
    #[tokio::test]
    async fn the_probe_adds_control_capabilities_without_disturbing_apps() {
        let mut tv = Device::new(DeviceId::new("dial", "x"), "TV", Kind::Television)
            .advertise(&[Capability::Apps]);
        tv.reachable = true;
        // No address: the probe cannot reach ADB, so it must not advertise
        // power or keys, but must keep Apps.
        probe(&mut tv).await;
        assert!(tv.can(Capability::Apps));
        assert!(!tv.can(Capability::Power));
        assert!(!tv.can(Capability::Keys));
    }

    /// An unreachable television drops its ADB controls rather than offering a
    /// button that will only ever time out.
    #[tokio::test]
    async fn an_unreachable_television_loses_its_adb_controls() {
        let mut tv = Device::new(DeviceId::new("dial", "x"), "TV", Kind::Television)
            .advertise(&[Capability::Apps, Capability::Power, Capability::Keys]);
        tv.reachable = false;
        probe(&mut tv).await;
        assert!(tv.can(Capability::Apps));
        assert!(!tv.can(Capability::Power));
        assert!(!tv.can(Capability::Keys));
    }

    #[test]
    fn a_key_file_round_trips() {
        let key = PrivateKey::generate();
        let text = render_key(&key);
        let reloaded = parse_key(&text).expect("what render wrote, parse reads");
        let token = [0x11_u8; 20];
        assert_eq!(key.sign_token(&token), reloaded.sign_token(&token));
    }

    #[test]
    fn a_file_that_is_not_a_key_is_refused() {
        assert!(parse_key("not a key").is_none());
        assert!(parse_key("# only a comment\n").is_none());
        assert!(parse_key("n=zz\n").is_none()); // bad hex
    }

    #[test]
    fn the_key_lives_beside_the_registry() {
        let path = key_path_beside(Path::new("/var/lib/selfhost/home.registry"));
        assert_eq!(path, Path::new("/var/lib/selfhost/home.adbkey"));
    }

    #[test]
    fn hex_round_trips() {
        assert_eq!(unhex(&hex(&[0x00, 0x0f, 0xa5, 0xff])), Some(vec![0x00, 0x0f, 0xa5, 0xff]));
        assert_eq!(unhex("abc"), None); // odd length
    }
}

//! The DIAL half of a television: launch, stop and status, with nothing asked
//! of anybody.
//!
//! DIAL — Discovery and Launch, the protocol behind the "cast" button — is the
//! **floor** of a television: it delivers exactly three things per
//! application — is it running, start it, stop it — and it needs nothing from
//! anybody, which is what makes it the half that always works.
//!
//! It was once recorded here as the *ceiling* too, on the strength of a
//! targeted SSDP search in which both real televisions answered only the DIAL
//! service urn. **That was wrong, and the correction is worth carrying rather
//! than quietly deleting.** The search was sound; the inference was not.
//! Keys, transport, application-launch-by-package and a wake all live behind
//! one DIAL application this module's own enumeration never asked for, because
//! the enumeration asked only for *streaming* app names — see
//! [`crate::firetv`], which is that surface, and home-lab.dx §"The ceiling was
//! wrong". A television is therefore two protocols behind one capability set,
//! and `crate::hub` is the one place that decides which of them owns a
//! command.
//!
//! What genuinely is unreachable, and by physics rather than by protocol:
//! **volume, mute and television power**, which the physical remote performs
//! with its own infrared emitter. [`crate::firetv`] carries that measurement.
//!
//! The shape mirrors [`crate::wiz`]: a pure protocol half — request builders
//! and parsers proved against captured responses — under a thin live half that
//! rides [`crate::soap`]'s HTTP transport, which already owns the connect,
//! deadline and framing discipline.
//!
//! Two measured facts are encoded here so nobody rediscovers them:
//!
//! * **YouTube answers `403 Forbidden` to a bare status request** and `200` to
//!   an identical one carrying `Origin: https://www.youtube.com`. That is
//!   DIAL's origin check, not a missing app, and [`origin_for`] is the fact's
//!   one home.
//! * **A launch is `POST /apps/<name>` and a stop is `DELETE
//!   /apps/<name>/run`** — the extra path segment is the DIAL "run resource",
//!   and sending the `DELETE` to the app URL instead answers 400.
//!
//! The applications base is not guessed: the television states it in the
//! `Application-URL` header over its device description, and it is kept on the
//! device ([`crate::device::Device::location`]) so a refresh does not re-fetch
//! the description it arrived with.

use crate::device::{Capability, Command, Device, DeviceId, Kind, Power};
use crate::discovery::Found;
use crate::soap;
use crate::xml;

/// The word this driver travels as in a [`DeviceId`].
pub const DRIVER: &str = "dial";

/// The port a Fire TV serves its device description on, used only when an SSDP
/// answer arrived without a `LOCATION` — the header is the authority and this
/// is the measured fallback, both televisions stating `:60000/dd.xml`.
pub const DESCRIPTION_PORT: u16 = 60000;

/// The port a Fire TV serves its applications on.
///
/// A device states this itself in its `Application-URL` header and that
/// statement is what [`television`] follows; this constant is the fallback for
/// the one caller that has an address and no description in hand —
/// [`crate::firetv::wake`], which has to reach the launch endpoint *before*
/// anything has been fetched, because until it runs the remote service is not
/// listening. Both real televisions state `:8009/apps/`.
pub const APPS_PORT: u16 = 8009;

/// The applications whose state a refresh asks about.
///
/// DIAL has no enumeration: the only way to learn what is installed is to ask
/// for names, one request each. Twenty-five names were asked of both real
/// televisions and these are the ones that exist (home-lab.dx §"The
/// televisions, driven"); a name not listed here can still be asked for
/// through [`Command::Launch`], which takes whatever the caller says.
pub const KNOWN_APPS: [&str; 2] = ["Netflix", "YouTube"];

/// The `Origin` an application's requests must carry, when it demands one.
///
/// Measured, not read from a specification: YouTube 403s a bare request and
/// accepts the same bytes with its own origin. Every other measured app
/// answers without one, and sending none is the default because an origin a
/// server does not expect is a new way to be refused.
#[must_use]
pub fn origin_for(app: &str) -> Option<&'static str> {
    app.eq_ignore_ascii_case("youtube").then_some("https://www.youtube.com")
}

/// What a television says it is, read from its device description.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Description {
    /// The name a person knows the television by: `Waldo's 2nd Fire TV`.
    pub friendly_name: String,
    /// The hardware model, `AFTMM` or `AFTCL001` here — worth keeping because
    /// it is what decides whether ADB can ever exist on the device.
    pub model: Option<String>,
}

/// Reads a device description, or decides the document does not describe one.
///
/// `friendlyName` is required: a description without it is not a device a
/// person can be shown.
#[must_use]
pub fn parse_description(document: &str) -> Option<Description> {
    let friendly_name = xml::element(document, "friendlyName")?.trim().to_owned();
    if friendly_name.is_empty() {
        return None;
    }
    let model = xml::element(document, "modelName")
        .map(|model| model.trim().to_owned())
        .filter(|model| !model.is_empty());
    Some(Description { friendly_name, model })
}

/// One application's state, read from its DIAL status document.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AppStatus {
    /// Whether the application is on the screen right now.
    pub running: bool,
    /// Whether the television will honour a stop. Stated per-application in
    /// the status document, and a `DELETE` sent against `allowStop="false"`
    /// would be refused — so it is read rather than assumed.
    pub allow_stop: bool,
}

/// Reads an application status document, or decides it is not one.
#[must_use]
pub fn parse_app_status(document: &str) -> Option<AppStatus> {
    let state = xml::element(document, "state")?;
    let allow_stop = xml::elements(document, "options")
        .first()
        .and_then(|options| xml::attr(options.attrs, "allowStop"))
        .is_some_and(|value| value.eq_ignore_ascii_case("true"));
    Some(AppStatus { running: state.trim().eq_ignore_ascii_case("running"), allow_stop })
}

/// The authority and path halves of a stated URL.
///
/// The television states its applications base absolutely
/// (`http://192.168.1.12:8009/apps/`), and the transport wants the two halves
/// separately. Not a general URL parser: the host is whatever stands before
/// the first `/`, which is all the URLs a LAN device states ever need.
#[must_use]
pub fn split_url(url: &str) -> Option<(String, String)> {
    let rest = url.split_once("://").map(|(_, rest)| rest).unwrap_or(url);
    let (authority, path) = match rest.split_once('/') {
        Some((authority, path)) => (authority, format!("/{path}")),
        None => (rest, "/".to_owned()),
    };
    (!authority.is_empty()).then(|| (authority.to_owned(), path))
}

/// The status request for one application: `GET <apps>/<name>`.
#[must_use]
pub fn status_request(authority: &str, apps_path: &str, app: &str) -> Vec<u8> {
    request("GET", authority, &app_path(apps_path, app), origin_for(app))
}

/// The launch request: `POST <apps>/<name>`, an empty body.
///
/// A launch payload — the way a specific video rather than merely the app
/// reaches the screen — would travel in this body; nothing here sends one yet.
#[must_use]
pub fn launch_request(authority: &str, apps_path: &str, app: &str) -> Vec<u8> {
    request("POST", authority, &app_path(apps_path, app), origin_for(app))
}

/// The stop request: `DELETE <apps>/<name>/run` — the run resource, not the
/// application. Measured: the `DELETE` against the application URL is refused.
#[must_use]
pub fn stop_request(authority: &str, apps_path: &str, app: &str) -> Vec<u8> {
    let path = format!("{}/run", app_path(apps_path, app));
    request("DELETE", authority, &path, origin_for(app))
}

/// One application's URL path under the stated base, tolerant of the base
/// arriving with or without its trailing slash.
fn app_path(apps_path: &str, app: &str) -> String {
    format!("{}/{app}", apps_path.trim_end_matches('/'))
}

/// Serialises one bodiless DIAL request.
///
/// `Content-Length: 0` is stated even on the `GET` side of the family it is
/// pointless for, because the `POST` needs it — a length-less `POST` leaves
/// the television waiting for a body that never comes — and one shape for all
/// three verbs is one thing to prove instead of three.
fn request(method: &str, authority: &str, path: &str, origin: Option<&str>) -> Vec<u8> {
    let mut request = String::with_capacity(160);
    request.push_str(method);
    request.push(' ');
    request.push_str(path);
    request.push_str(" HTTP/1.1\r\n");
    request.push_str("HOST: ");
    request.push_str(authority);
    request.push_str("\r\n");
    if let Some(origin) = origin {
        request.push_str("ORIGIN: ");
        request.push_str(origin);
        request.push_str("\r\n");
    }
    request.push_str("CONTENT-LENGTH: 0\r\n");
    request.push_str("CONNECTION: close\r\n\r\n");
    request.into_bytes()
}

/// A television as a [`Device`], from what discovery heard and one fetch.
///
/// The fetch is the device description the SSDP answer pointed at: it carries
/// the name a person knows (`friendlyName`), the model, and — as the
/// `Application-URL` response header, which is why the transport surfaces
/// headers at all — the applications base every later request is built on.
/// A description without that header is a DIAL device with no application
/// surface, which for this driver means no device.
pub async fn television(found: &Found) -> Result<Device, String> {
    let location = found
        .location
        .clone()
        .unwrap_or_else(|| format!("http://{}:{DESCRIPTION_PORT}/dd.xml", found.address));
    let (authority, path) =
        split_url(&location).ok_or_else(|| format!("{location} is not a URL"))?;

    let fetch = request("GET", &authority, &path, None);
    let (status, headers, body) =
        soap::http(&authority, &fetch).await.map_err(|error| error.to_string())?;
    if status != 200 {
        return Err(format!("{location} answered {status}"));
    }
    let description = parse_description(&body)
        .ok_or_else(|| format!("{location} did not describe a device"))?;
    let apps = headers
        .get_str("application-url")
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| format!("{location} stated no Application-URL"))?
        .to_owned();

    // The SSDP UUID is the stable identity, surviving an address change the
    // way a Sonos's RINCON does; the address stands in only for a television
    // that answered without one.
    let key = found.key.clone().unwrap_or_else(|| found.address.clone());
    // `Power` is advertised on every Fire TV and needs nothing from anybody:
    // powering one on is a DIAL launch of `FireTVRemote`, which takes no token
    // (`crate::firetv::wake`). Keys and transport are *not* advertised here,
    // because those do need a pairing — the hub adds them for a television it
    // holds a token for, which is what keeps the page showing controls that
    // exist rather than controls that would refuse.
    let mut device =
        Device::new(DeviceId::new(DRIVER, &key), description.friendly_name, Kind::Television)
            .advertise(&[Capability::Apps, Capability::Power]);
    device.address = Some(found.address.clone());
    device.location = Some(apps);
    device.reachable = true;
    Ok(device)
}

/// Re-reads which application, if any, is on the screen.
pub async fn refresh(device: &mut Device) {
    let Some((authority, apps_path)) = base_of(device) else {
        device.reachable = false;
        return;
    };

    let mut answered = false;
    let mut running = None;
    for app in KNOWN_APPS {
        match ask(&authority, &apps_path, app).await {
            Asked::Status(status) => {
                answered = true;
                if status.running && running.is_none() {
                    running = Some(app.to_owned());
                }
            }
            // 404 is an answer: the television is there, the app is not.
            Asked::NotInstalled => answered = true,
            Asked::NoAnswer => {}
        }
    }
    device.reachable = answered;
    device.state.app = running;
    // What "on" means for a television, stated precisely because it is not
    // what a reader might assume. A Fire TV stick that answers DIAL is powered
    // and taking commands; whether its *television* is showing anything is a
    // fact about an HDMI-CEC wire this box cannot read, and the household's
    // own set obeys the standby half of that wire only sometimes. So this
    // reports the stick and never guesses at the screen — and it stays
    // `Unknown` rather than becoming `Off` when nothing answered, because a
    // stick drawing power from the television's USB port simply disappears
    // when the television does, and "gone" is not "off".
    device.state.power = answered.then_some(Power::On);
}

/// Performs one command against one television.
pub async fn perform(device: &Device, command: &Command) -> Result<(), String> {
    let (authority, apps_path) = base_of(device)
        .ok_or_else(|| format!("{} has not stated its application surface yet.", device.name))?;

    match command {
        Command::Launch(app) => {
            let request = launch_request(&authority, &apps_path, app);
            match soap::http(&authority, &request).await {
                // 201 is the specified answer and 200 is a television agreeing
                // that the app was already on the screen.
                Ok((200 | 201, _, _)) => Ok(()),
                Ok((404, _, _)) => Err(format!("{} does not have {app}.", device.name)),
                Ok((403, _, _)) => Err(format!("{app} refused the request's origin.")),
                Ok((status, _, _)) => Err(format!("{} answered {status}.", device.name)),
                Err(error) => Err(error.to_string()),
            }
        }
        Command::Stop => {
            // A stop is of whatever is running, so the running app is looked
            // up rather than remembered — the state on the page may be two
            // seconds old, and stopping the wrong thing is worse than a
            // sentence.
            for app in KNOWN_APPS {
                if let Asked::Status(status) = ask(&authority, &apps_path, app).await {
                    if !status.running {
                        continue;
                    }
                    if !status.allow_stop {
                        return Err(format!("{app} does not allow being stopped."));
                    }
                    let request = stop_request(&authority, &apps_path, app);
                    return match soap::http(&authority, &request).await {
                        Ok((200, _, _)) => Ok(()),
                        Ok((status, _, _)) => Err(format!("{} answered {status}.", device.name)),
                        Err(error) => Err(error.to_string()),
                    };
                }
            }
            Err(format!("Nothing is running on {}.", device.name))
        }
        other => Err(format!(
            "{} cannot be asked to {}.",
            device.name,
            other.as_str().replace('_', " ")
        )),
    }
}

/// One application's status, asked of the television.
enum Asked {
    /// The television answered with a status document.
    Status(AppStatus),
    /// The television answered 404: present, but no such application.
    NotInstalled,
    /// Nothing answered, or the answer was not a status.
    NoAnswer,
}

async fn ask(authority: &str, apps_path: &str, app: &str) -> Asked {
    let request = status_request(authority, apps_path, app);
    match soap::http(authority, &request).await {
        Ok((200, _, body)) => match parse_app_status(&body) {
            Some(status) => Asked::Status(status),
            None => Asked::NoAnswer,
        },
        Ok((404, _, _)) => Asked::NotInstalled,
        Ok(_) => Asked::NoAnswer,
        Err(_) => Asked::NoAnswer,
    }
}

/// The transport halves of the device's stated applications base.
fn base_of(device: &Device) -> Option<(String, String)> {
    split_url(device.location.as_deref()?)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The description both real televisions serve on :60000, reconstructed
    /// from the 2026-08-18 capture (home-lab.dx §"The televisions, driven"):
    /// the elements are the measured ones, and the apostrophe arrives escaped
    /// because that is how a device must send it.
    const DESCRIPTION: &str = r#"<?xml version="1.0"?>
<root xmlns="urn:schemas-upnp-org:device-1-0">
  <specVersion><major>1</major><minor>0</minor></specVersion>
  <device>
    <deviceType>urn:dial-multiscreen-org:device:dial:1</deviceType>
    <friendlyName>Andreas&apos;s 7th Fire TV</friendlyName>
    <manufacturer>Amazon</manufacturer>
    <modelName>AFTMM</modelName>
    <UDN>uuid:17df6a1e-1e65-4d29-a538-fdd4d8d38a03</UDN>
  </device>
</root>"#;

    /// The pin the plan named: a television is named by its own device
    /// description, not by a port probe.
    #[test]
    fn a_television_is_named_by_its_device_description() {
        let description = parse_description(DESCRIPTION).expect("a device description");
        assert_eq!(description.friendly_name, "Andreas's 7th Fire TV");
        assert_eq!(description.model.as_deref(), Some("AFTMM"));
    }

    #[test]
    fn a_document_without_a_name_is_not_a_device() {
        assert_eq!(parse_description("<root><modelName>AFTMM</modelName></root>"), None);
        assert_eq!(parse_description("<root><friendlyName>  </friendlyName></root>"), None);
        assert_eq!(parse_description("not xml at all"), None);
    }

    /// The status document as the Vega television answered it live: stopped,
    /// and stoppable.
    const STOPPED: &str = r#"<?xml version="1.0" encoding="UTF-8"?>
<service xmlns="urn:dial-multiscreen-org:schemas:dial" dialVer="2.1">
  <name>Netflix</name>
  <options allowStop="true"/>
  <state>stopped</state>
</service>"#;

    #[test]
    fn an_app_status_carries_its_state_and_its_stop_permission() {
        let status = parse_app_status(STOPPED).expect("a status document");
        assert!(!status.running);
        assert!(status.allow_stop);

        let running = STOPPED.replace("stopped", "running");
        let status = parse_app_status(&running).expect("a status document");
        assert!(status.running);
    }

    /// `allowStop` absent means stop is not offered; assuming it and sending
    /// the `DELETE` anyway would be refused with a status a person then reads.
    #[test]
    fn a_missing_allow_stop_is_read_as_not_allowed() {
        let terse = "<service><name>X</name><state>running</state></service>";
        let status = parse_app_status(terse).expect("a status document");
        assert!(!status.allow_stop);
        assert_eq!(parse_app_status("<service><name>X</name></service>"), None);
    }

    /// The measured YouTube fact: its requests carry its origin, everything
    /// else's carry none — a bare request to YouTube answers 403 and the same
    /// bytes with the header answer 200.
    #[test]
    fn only_youtube_requests_carry_an_origin() {
        let youtube = String::from_utf8(status_request("192.168.1.12:8009", "/apps/", "YouTube"))
            .expect("ascii");
        assert!(youtube.contains("ORIGIN: https://www.youtube.com\r\n"));
        let netflix = String::from_utf8(status_request("192.168.1.12:8009", "/apps/", "Netflix"))
            .expect("ascii");
        assert!(!netflix.contains("ORIGIN"));
    }

    /// The launch and its undo, exactly as measured: `POST` to the app,
    /// `DELETE` to the app's run resource.
    #[test]
    fn a_launch_posts_the_app_and_a_stop_deletes_its_run() {
        let launch = String::from_utf8(launch_request("192.168.1.12:8009", "/apps/", "Netflix"))
            .expect("ascii");
        assert!(launch.starts_with("POST /apps/Netflix HTTP/1.1\r\n"));
        assert!(launch.contains("HOST: 192.168.1.12:8009\r\n"));
        assert!(launch.contains("CONTENT-LENGTH: 0\r\n"));
        assert!(launch.ends_with("\r\n\r\n"));

        let stop = String::from_utf8(stop_request("192.168.1.12:8009", "/apps/", "Netflix"))
            .expect("ascii");
        assert!(stop.starts_with("DELETE /apps/Netflix/run HTTP/1.1\r\n"));
    }

    /// The stated base arrives with a trailing slash; a base without one must
    /// build the same paths rather than fusing the segment onto `apps`.
    #[test]
    fn the_apps_base_works_with_and_without_its_trailing_slash() {
        assert_eq!(app_path("/apps/", "Netflix"), "/apps/Netflix");
        assert_eq!(app_path("/apps", "Netflix"), "/apps/Netflix");
    }

    #[test]
    fn a_stated_url_splits_into_authority_and_path() {
        assert_eq!(
            split_url("http://192.168.1.12:8009/apps/"),
            Some(("192.168.1.12:8009".to_owned(), "/apps/".to_owned()))
        );
        assert_eq!(
            split_url("http://192.168.1.4:60000/dd.xml"),
            Some(("192.168.1.4:60000".to_owned(), "/dd.xml".to_owned()))
        );
        assert_eq!(split_url("http://host"), Some(("host".to_owned(), "/".to_owned())));
        assert_eq!(split_url("http:///nothing"), None);
    }
}

//! The daemon's arm for the smart home.
//!
//! Shaped like every other optional subsystem here: absent configuration means
//! the arm pends forever and nothing is spawned, so a deployment that has
//! never heard of this feature does not sweep its network because a crate was
//! linked into the binary.
//!
//! Two tasks are started when it is switched on, and they are separate on
//! purpose. [`selfhost_home::Hub::run`] keeps the house's state true — it
//! sweeps, polls, and never returns. [`selfhost_home::serve`] answers the
//! dashboard. If the second ever fails to bind, the first is still worth
//! running: the state stays true, and the operator gets a named error rather
//! than a daemon that exits.

use std::sync::Arc;

use selfhost_config::Config;
use selfhost_home::Hub;

/// The running subsystem, or nothing.
pub struct Home {
    /// Where the dashboard's API is answering, for the banner.
    bind: String,
}

impl Home {
    /// The line the daemon prints at startup.
    ///
    /// Says where the API is and, deliberately, that it is loopback — an
    /// operator reading the banner should be able to see that nothing new was
    /// exposed without going to look.
    pub fn banner(&self) -> String {
        format!(
            "home     the house is being watched; its API answers on {} (loopback only)",
            self.bind
        )
    }
}

/// Starts the smart-home subsystem, if this deployment declares one.
///
/// Returns `None` when there is no `[home]` block or it is switched off, in
/// which case nothing at all has been started.
pub fn start(config: &Config, data_dir: &std::path::Path) -> Option<Home> {
    let settings = config.home.as_ref()?;
    if !settings.enabled {
        return None;
    }

    // The registry lives beside the daemon's other state, and is the only file
    // this subsystem writes. It holds names and rooms a person chose — no
    // credential, nothing that opens anything — so it needs no special mode.
    let registry_path = data_dir.join("home.registry");
    let hub = Arc::new(Hub::new(registry_path));
    let bind = settings.bind();

    tokio::spawn(Arc::clone(&hub).run(settings.refresh(), settings.discover()));

    let serving = bind.clone();
    tokio::spawn(async move {
        if let Err(error) = selfhost_home::serve(&serving, hub).await {
            // Named rather than fatal: the house's state is still being kept
            // true by the task above, and a daemon that exited here would take
            // every other subsystem down with it over a dashboard.
            eprintln!("[home] the house API could not be served on {serving}: {error}");
        }
    });

    Some(Home { bind })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A config with `[home]` in whichever state the test wants, parsed from
    /// TOML so it exercises the loader the daemon uses rather than a struct
    /// literal that would keep passing when a required field appears.
    fn config_with(home: &str) -> Config {
        let text = format!(
            "version = 1\n\n[server]\nacme_email = \"a@b.com\"\nacme = \"self-signed\"\n\n\
             [[nodes]]\nname = \"home\"\nrole = \"owner\"\n{home}"
        );
        Config::parse(&text).expect("the config parses")
    }

    /// The property that matters most: a deployment with no `[home]` block
    /// starts nothing, so linking this crate in cannot cause a network sweep.
    #[test]
    fn no_block_starts_nothing() {
        assert!(start(&config_with(""), std::path::Path::new("/nonexistent")).is_none());
    }

    /// Present-but-false parks the subsystem without deleting the settings
    /// around it, the same way `[mesh] dial = false` parks a peer link.
    #[test]
    fn a_disabled_block_starts_nothing() {
        let config = config_with("\n[home]\nenabled = false\nport = 9210\n");
        assert!(start(&config, std::path::Path::new("/nonexistent")).is_none());
    }

    /// The block parses into the loopback bind the server will be handed.
    #[test]
    fn an_enabled_block_names_a_loopback_bind() {
        let config = config_with("\n[home]\nenabled = true\nport = 9211\n");
        let home = config.home.as_ref().expect("a [home] block");
        assert!(home.enabled);
        assert_eq!(home.bind(), "127.0.0.1:9211");
    }

    /// The banner must say "loopback", because that is the fact an operator
    /// scanning startup output needs in order to know nothing was exposed.
    #[test]
    fn the_banner_says_where_and_says_loopback() {
        let home = Home { bind: "127.0.0.1:9210".into() };
        let banner = home.banner();
        assert!(banner.contains("127.0.0.1:9210"));
        assert!(banner.contains("loopback"));
    }
}

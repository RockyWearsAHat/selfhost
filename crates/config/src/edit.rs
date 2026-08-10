//! Surgical edits to the hand-authored config file.
//!
//! `selfhost site add|remove` changes the sites the operator owns, in the file
//! the operator owns. This is deliberately *not* the daemon: the daemon never
//! writes `selfhost.config.toml`, precisely so the comments `init` left there —
//! the ACME rate-limit warning, the bind-address reasoning — survive a console
//! save (see [`crate::service`]). The CLI edits the file only on the operator's
//! explicit command, and even then it changes as little as it can.
//!
//! The change is a *text* edit rather than a re-serialisation of the parsed
//! document. Serialising a parsed [`Config`] back to TOML discards every comment
//! and reorders and re-styles every section; a `site add` that did that would be
//! the exact thing the two-file split exists to prevent. So these functions add
//! one `[[sites]]` block to the end of the file, or excise the one block being
//! removed, and touch nothing else — every comment, blank line, and the order of
//! untouched sections is preserved byte for byte.
//!
//! Every returned document is validated as a whole before it is handed back: a
//! change that would collide two sites on a hostname, claim a port twice, or
//! otherwise break the deployment is refused rather than written. The caller can
//! therefore write the returned text knowing it parses and validates.

use crate::{Config, ConfigError, Health, Mailbox, Site};

/// Returns the config text with `site` appended as a new `[[sites]]` block.
///
/// The current text must itself be a valid config: editing a file that does not
/// parse would append a block onto a document already broken in some other way,
/// hiding the real problem behind a new one. The returned text is validated too,
/// so a site whose name or a domain collides with an existing one — or whose
/// ports clash — comes back as [`ConfigError::Invalid`] and is never written.
pub fn add_site(source: &str, site: &Site) -> Result<String, ConfigError> {
    // Refuse to edit a config that is already broken; the operator should fix
    // what is wrong before adding to it, rather than have the two errors mixed.
    Config::parse(source)?;

    let mut text = source.to_owned();
    if !text.ends_with('\n') {
        text.push('\n');
    }
    // One blank line separates the new block from whatever came before, matching
    // the spacing `init` writes between sections.
    if !text.trim_end().is_empty() {
        text.push('\n');
    }
    text.push_str(&render_site_block(site));

    // The whole-document check: this is where a duplicate hostname or a port
    // collision with an existing site is caught and refused.
    Config::parse(&text)?;
    Ok(text)
}

/// Returns the config text with the site named `name` removed, or `None` if no
/// site by that name is present.
///
/// The site's `[[sites]]` block — and its `[sites.health]` / `[[sites.instances]]`
/// sub-tables — are excised as a contiguous span; every other section is left
/// exactly as it was. The result is validated before it is returned, which for a
/// removal can only fail if the file was already invalid in some unrelated way.
pub fn remove_site(source: &str, name: &str) -> Result<Option<String>, ConfigError> {
    let config = Config::parse(source)?;
    let Some(index) = config.sites.iter().position(|site| site.name == name) else {
        return Ok(None);
    };

    // The N-th site in the parsed document is the N-th `[[sites]]` block in the
    // text, because both are read in document order. Removing by position rather
    // than by re-matching the name out of the raw text means the block boundary
    // logic never has to parse a `name = "..."` value itself.
    let edited = remove_nth_site_block(source, index)
        .expect("a parsed site has a corresponding text block");

    Config::parse(&edited)?;
    Ok(Some(edited))
}

/// Renders one `[[sites]]` block, emitting only the fields that carry meaning.
///
/// Defaults are left out — no `spa = false`, no empty `app_paths`, no
/// `[sites.health]` table when the health settings are the defaults — so an
/// added block reads like one a person would have written by hand rather than a
/// serialiser's exhaustive dump.
fn render_site_block(site: &Site) -> String {
    let mut out = String::from("[[sites]]\n");
    out.push_str(&format!("name = {}\n", quote(&site.name)));
    out.push_str(&format!("domains = {}\n", quote_array(&site.domains)));

    if let Some(root) = &site.static_root {
        out.push_str(&format!("static_root = {}\n", quote(&root.to_string_lossy())));
    }
    if site.spa {
        out.push_str("spa = true\n");
    }
    if !site.app_paths.is_empty() {
        out.push_str(&format!("app_paths = {}\n", quote_array(&site.app_paths)));
    }
    if !site.canonical_redirect {
        out.push_str("canonical_redirect = false\n");
    }

    for instance in &site.instances {
        out.push_str("\n[[sites.instances]]\n");
        out.push_str(&format!("node = {}\n", quote(&instance.node)));
        out.push_str(&format!("port = {}\n", instance.port));
    }

    if !health_is_default(&site.health) {
        let health = &site.health;
        out.push_str("\n[sites.health]\n");
        out.push_str(&format!("path = {}\n", quote(&health.path)));
        out.push_str(&format!("interval_secs = {}\n", health.interval_secs));
        out.push_str(&format!("timeout_secs = {}\n", health.timeout_secs));
        out.push_str(&format!("unhealthy_after = {}\n", health.unhealthy_after));
        out.push_str(&format!("healthy_after = {}\n", health.healthy_after));
    }

    out
}

/// Whether these health settings are the defaults, so the block can omit them.
///
/// Compared field by field rather than through `PartialEq` so [`Health`] need
/// not derive it solely for this one call site.
fn health_is_default(health: &Health) -> bool {
    let default = Health::default();
    health.path == default.path
        && health.interval_secs == default.interval_secs
        && health.timeout_secs == default.timeout_secs
        && health.unhealthy_after == default.unhealthy_after
        && health.healthy_after == default.healthy_after
}

/// A TOML-quoted, escaped scalar string, via the `toml` crate's own encoder.
///
/// Hand-rolling the quoting would get an embedded quote or backslash in a domain
/// or path subtly wrong; the encoder that reads the file back is the right thing
/// to write it with.
fn quote(value: &str) -> String {
    toml::Value::String(value.to_owned()).to_string()
}

/// A TOML inline array of quoted strings.
fn quote_array(values: &[String]) -> String {
    let items: Vec<String> = values.iter().map(|value| quote(value)).collect();
    format!("[{}]", items.join(", "))
}

/// Removes the `target`-th top-level `[[sites]]` block from the text.
///
/// The block runs from its `[[sites]]` header up to — but not including — the
/// next line that opens a section not belonging to this site: another
/// `[[sites]]`, or any header whose first dotted segment is not `sites`. Its own
/// `[sites.health]` and `[[sites.instances]]` sub-tables, and any blank lines
/// inside the span, are carried out with it. Returns `None` if the file has
/// fewer than `target + 1` site blocks.
fn remove_nth_site_block(source: &str, target: usize) -> Option<String> {
    // Split on '\n' rather than using `lines()`, so a trailing newline and any
    // carriage returns are preserved exactly on the lines that are kept.
    let parts: Vec<&str> = source.split('\n').collect();

    let mut seen = 0usize;
    let mut start = None;
    for (i, line) in parts.iter().enumerate() {
        if is_site_header(line) {
            if seen == target {
                start = Some(i);
                break;
            }
            seen += 1;
        }
    }
    let start = start?;

    let mut end = parts.len();
    for (offset, line) in parts.iter().enumerate().skip(start + 1) {
        if is_site_header(line) {
            end = offset;
            break;
        }
        match header_first_segment(line) {
            // A sub-table of this same site — keep consuming.
            Some("sites") => {}
            // The start of some other section ends the block.
            Some(_) => {
                end = offset;
                break;
            }
            // Ordinary key/value or blank line inside the block.
            None => {}
        }
    }

    let kept: Vec<&str> =
        parts[..start].iter().chain(parts[end..].iter()).copied().collect();
    let mut result = kept.join("\n");
    if source.ends_with('\n') && !result.ends_with('\n') {
        result.push('\n');
    }
    Some(result)
}

/// Whether `line` is exactly the `[[sites]]` header that opens a site block.
///
/// A `[[sites.instances]]` or `[sites.health]` header is a sub-table of a site,
/// not the start of one, and must not be mistaken for it.
fn is_site_header(line: &str) -> bool {
    line.trim() == "[[sites]]"
}

/// The first dotted segment of a TOML table header, or `None` for a line that is
/// not a table header at all.
///
/// `[server.firewall]` and `[[sites.instances]]` both answer their first
/// segment (`server`, `sites`); a `key = value` line or a blank line answers
/// `None`. This is what distinguishes "a new top-level section starts here" from
/// "still inside the current block".
fn header_first_segment(line: &str) -> Option<&str> {
    let trimmed = line.trim();
    let inner = trimmed
        .strip_prefix("[[")
        .and_then(|rest| rest.strip_suffix("]]"))
        .or_else(|| trimmed.strip_prefix('[').and_then(|rest| rest.strip_suffix(']')))?;
    let segment = inner.split('.').next().unwrap_or("").trim();
    (!segment.is_empty()).then_some(segment)
}

/// Returns the config text with `mailbox` appended as a new `[[mail.mailboxes]]`
/// block.
///
/// `[mail]` itself must already be present — a mailbox needs a hostname and a
/// domain to belong to, and inventing those here would be a deployment
/// decision this function has no business making. Refused as
/// [`ConfigError::Invalid`] (not written) when `[mail]` is absent, exactly
/// like a genuine validation failure.
pub fn add_mailbox(source: &str, mailbox: &Mailbox) -> Result<String, ConfigError> {
    let config = Config::parse(source)?;
    if config.mail.is_none() {
        return Err(ConfigError::Invalid(vec![crate::validate::Problem {
            field: "mail".to_owned(),
            message: "no [mail] section — configure hostname and domains before adding a mailbox"
                .to_owned(),
        }]));
    }

    let mut text = source.to_owned();
    if !text.ends_with('\n') {
        text.push('\n');
    }
    if !text.trim_end().is_empty() {
        text.push('\n');
    }
    text.push_str(&render_mailbox_block(mailbox));

    // The whole-document check: this is where an address already claimed by
    // another mailbox, or one outside `mail.domains`, is caught and refused.
    Config::parse(&text)?;
    Ok(text)
}

/// Returns the config text with the mailbox at `address` removed, or `None` if
/// no mailbox by that address is present.
pub fn remove_mailbox(source: &str, address: &str) -> Result<Option<String>, ConfigError> {
    let config = Config::parse(source)?;
    let Some(mail) = &config.mail else { return Ok(None) };
    let Some(index) = mail.mailboxes.iter().position(|mailbox| mailbox.address == address) else {
        return Ok(None);
    };

    let edited = remove_nth_mailbox_block(source, index)
        .expect("a parsed mailbox has a corresponding text block");

    Config::parse(&edited)?;
    Ok(Some(edited))
}

/// Renders one `[[mail.mailboxes]]` block, omitting `aliases` when empty so an
/// added block reads like one a person would have written by hand.
fn render_mailbox_block(mailbox: &Mailbox) -> String {
    let mut out = String::from("[[mail.mailboxes]]\n");
    out.push_str(&format!("address = {}\n", quote(&mailbox.address)));
    out.push_str(&format!("password_hash = {}\n", quote(&mailbox.password_hash)));
    if !mailbox.aliases.is_empty() {
        out.push_str(&format!("aliases = {}\n", quote_array(&mailbox.aliases)));
    }
    out
}

/// Removes the `target`-th `[[mail.mailboxes]]` block from the text.
///
/// A mailbox block has no sub-tables of its own, so — unlike a site's — it runs
/// only from its `[[mail.mailboxes]]` header up to the next line that opens any
/// section at all, or the end of the file.
fn remove_nth_mailbox_block(source: &str, target: usize) -> Option<String> {
    let parts: Vec<&str> = source.split('\n').collect();

    let mut seen = 0usize;
    let mut start = None;
    for (i, line) in parts.iter().enumerate() {
        if is_mailbox_header(line) {
            if seen == target {
                start = Some(i);
                break;
            }
            seen += 1;
        }
    }
    let start = start?;

    let mut end = parts.len();
    for (offset, line) in parts.iter().enumerate().skip(start + 1) {
        if header_first_segment(line).is_some() {
            end = offset;
            break;
        }
    }

    let kept: Vec<&str> = parts[..start].iter().chain(parts[end..].iter()).copied().collect();
    let mut result = kept.join("\n");
    if source.ends_with('\n') && !result.ends_with('\n') {
        result.push('\n');
    }
    Some(result)
}

/// Whether `line` is exactly the `[[mail.mailboxes]]` header that opens a
/// mailbox block.
fn is_mailbox_header(line: &str) -> bool {
    line.trim() == "[[mail.mailboxes]]"
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Instance;
    use std::path::PathBuf;

    /// A minimal valid config with one owner node and no sites.
    const EMPTY: &str = "\
version = 1

[server]
acme_email = \"a@b.com\"
acme = \"self-signed\"

# a comment a person left, which must survive every edit
[[nodes]]
name = \"home\"
role = \"owner\"
";

    fn static_site(name: &str, domain: &str) -> Site {
        Site {
            name: name.into(),
            domains: vec![domain.into()],
            static_root: Some(PathBuf::from("./sites/blog")),
            spa: false,
            app_paths: vec![],
            instances: vec![],
            health: Health::default(),
            canonical_redirect: true,
            allowed_cidrs: vec![],
            console: false,
        }
    }

    #[test]
    fn adding_a_site_appends_a_block_and_leaves_it_valid() {
        let text = add_site(EMPTY, &static_site("blog", "blog.example.com")).unwrap();
        let config = Config::parse(&text).unwrap();
        assert_eq!(config.sites.len(), 1);
        assert_eq!(config.sites[0].name, "blog");
        assert_eq!(config.sites[0].canonical(), "blog.example.com");
    }

    #[test]
    fn adding_a_site_preserves_the_hand_written_comment() {
        let text = add_site(EMPTY, &static_site("blog", "blog.example.com")).unwrap();
        assert!(
            text.contains("# a comment a person left"),
            "the operator's comment must survive a site add:\n{text}"
        );
    }

    #[test]
    fn a_defaulted_site_writes_no_noise() {
        let text = add_site(EMPTY, &static_site("blog", "blog.example.com")).unwrap();
        // Defaults are omitted so the block reads like a hand-written one.
        assert!(!text.contains("spa ="), "{text}");
        assert!(!text.contains("app_paths ="), "{text}");
        assert!(!text.contains("[sites.health]"), "{text}");
        assert!(!text.contains("canonical_redirect"), "{text}");
    }

    #[test]
    fn an_app_site_writes_its_instances() {
        let mut site = static_site("api", "api.example.com");
        site.static_root = None;
        site.instances = vec![Instance { node: "home".into(), port: 5050 }];
        let text = add_site(EMPTY, &site).unwrap();
        let config = Config::parse(&text).unwrap();
        assert_eq!(config.sites[0].instances.len(), 1);
        assert_eq!(config.sites[0].instances[0].node, "home");
        assert_eq!(config.sites[0].instances[0].port, 5050);
    }

    #[test]
    fn adding_a_duplicate_hostname_is_refused_not_written() {
        let once = add_site(EMPTY, &static_site("blog", "blog.example.com")).unwrap();
        // A second site claiming the same hostname must be rejected as invalid,
        // rather than written and left to break routing at boot.
        let clash = static_site("other", "blog.example.com");
        assert!(matches!(add_site(&once, &clash), Err(ConfigError::Invalid(_))));
    }

    #[test]
    fn a_non_default_health_block_is_emitted_and_round_trips() {
        let mut site = static_site("api", "api.example.com");
        site.static_root = None;
        site.instances = vec![Instance { node: "home".into(), port: 5050 }];
        site.health = Health {
            path: "/healthz".into(),
            interval_secs: 20,
            timeout_secs: 5,
            unhealthy_after: 3,
            healthy_after: 2,
        };
        let text = add_site(EMPTY, &site).unwrap();
        assert!(text.contains("[sites.health]"), "{text}");
        let config = Config::parse(&text).unwrap();
        assert_eq!(config.sites[0].health.path, "/healthz");
        assert_eq!(config.sites[0].health.interval_secs, 20);
    }

    #[test]
    fn removing_a_site_takes_only_its_block() {
        let one = add_site(EMPTY, &static_site("blog", "blog.example.com")).unwrap();
        let two = add_site(&one, &static_site("shop", "shop.example.com")).unwrap();

        let text = remove_site(&two, "blog").unwrap().expect("blog was present");
        let config = Config::parse(&text).unwrap();
        assert_eq!(config.sites.len(), 1);
        assert_eq!(config.sites[0].name, "shop");
        // The untouched site and the operator's comment are both still there.
        assert!(text.contains("shop.example.com"), "{text}");
        assert!(text.contains("# a comment a person left"), "{text}");
        // And the removed one is gone entirely, sub-tables and all.
        assert!(!text.contains("blog.example.com"), "{text}");
    }

    #[test]
    fn removing_a_site_with_sub_tables_takes_them_too() {
        let mut site = static_site("api", "api.example.com");
        site.static_root = None;
        site.instances = vec![Instance { node: "home".into(), port: 5050 }];
        site.health = Health { path: "/healthz".into(), ..Health::default() };
        let with = add_site(EMPTY, &site).unwrap();

        let text = remove_site(&with, "api").unwrap().expect("api was present");
        assert!(!text.contains("[[sites.instances]]"), "{text}");
        assert!(!text.contains("[sites.health]"), "{text}");
        assert_eq!(Config::parse(&text).unwrap().sites.len(), 0);
    }

    #[test]
    fn removing_the_first_of_two_leaves_the_second_parseable() {
        let one = add_site(EMPTY, &static_site("a", "a.example.com")).unwrap();
        let two = add_site(&one, &static_site("b", "b.example.com")).unwrap();
        let text = remove_site(&two, "a").unwrap().unwrap();
        let config = Config::parse(&text).unwrap();
        assert_eq!(config.sites.len(), 1);
        assert_eq!(config.sites[0].name, "b");
    }

    #[test]
    fn removing_an_absent_site_reports_none() {
        assert!(remove_site(EMPTY, "ghost").unwrap().is_none());
    }

    #[test]
    fn editing_a_config_that_does_not_parse_is_refused() {
        let broken = "this is not valid toml {{{";
        assert!(add_site(broken, &static_site("x", "x.com")).is_err());
        assert!(remove_site(broken, "x").is_err());
    }

    #[test]
    fn a_domain_with_awkward_characters_is_quoted_correctly() {
        // Not a real hostname, but it proves the encoder — not hand-rolled
        // quoting — writes the value, so an embedded quote can never break the file.
        let mut site = static_site("weird", "ok.example.com");
        site.name = "wei\"rd".into();
        let text = add_site(EMPTY, &site).unwrap();
        // It must round-trip through the parser unchanged.
        let config = Config::parse(&text).unwrap();
        assert_eq!(config.sites[0].name, "wei\"rd");
    }

    // ---- mailboxes -----------------------------------------------------------

    const WITH_MAIL: &str = "\
version = 1

[server]
acme_email = \"a@b.com\"
acme = \"self-signed\"

[[nodes]]
name = \"home\"
role = \"owner\"

# the mail operator's own comment, which must survive every edit
[mail]
hostname = \"mail.example.com\"
domains = [\"example.com\"]
";

    fn mailbox(address: &str) -> Mailbox {
        Mailbox { address: address.into(), password_hash: "pbkdf2-sha256$...".into(), aliases: vec![] }
    }

    #[test]
    fn adding_a_mailbox_appends_a_block_and_leaves_it_valid() {
        let text = add_mailbox(WITH_MAIL, &mailbox("dave@example.com")).unwrap();
        let config = Config::parse(&text).unwrap();
        let mail = config.mail.expect("mail present");
        assert_eq!(mail.mailboxes.len(), 1);
        assert_eq!(mail.mailboxes[0].address, "dave@example.com");
    }

    #[test]
    fn adding_a_mailbox_preserves_the_operators_comment() {
        let text = add_mailbox(WITH_MAIL, &mailbox("dave@example.com")).unwrap();
        assert!(text.contains("# the mail operator's own comment"), "{text}");
    }

    #[test]
    fn adding_a_mailbox_without_a_mail_section_is_refused() {
        assert!(matches!(add_mailbox(EMPTY, &mailbox("dave@example.com")), Err(ConfigError::Invalid(_))));
    }

    #[test]
    fn adding_a_duplicate_address_is_refused_not_written() {
        let once = add_mailbox(WITH_MAIL, &mailbox("dave@example.com")).unwrap();
        assert!(matches!(
            add_mailbox(&once, &mailbox("dave@example.com")),
            Err(ConfigError::Invalid(_))
        ));
    }

    #[test]
    fn removing_a_mailbox_takes_only_its_block() {
        let one = add_mailbox(WITH_MAIL, &mailbox("dave@example.com")).unwrap();
        let two = add_mailbox(&one, &mailbox("sam@example.com")).unwrap();

        let text = remove_mailbox(&two, "dave@example.com").unwrap().expect("dave was present");
        let config = Config::parse(&text).unwrap();
        assert_eq!(config.mail.unwrap().mailboxes.len(), 1);
        assert!(text.contains("sam@example.com"), "{text}");
        assert!(!text.contains("dave@example.com"), "{text}");
    }

    #[test]
    fn removing_an_absent_mailbox_reports_none() {
        assert!(remove_mailbox(WITH_MAIL, "ghost@example.com").unwrap().is_none());
    }

    #[test]
    fn a_mailbox_with_aliases_writes_and_round_trips_them() {
        let mut box_ = mailbox("dave@example.com");
        box_.aliases = vec!["postmaster@example.com".into()];
        let text = add_mailbox(WITH_MAIL, &box_).unwrap();
        let config = Config::parse(&text).unwrap();
        assert_eq!(config.mail.unwrap().mailboxes[0].aliases, vec!["postmaster@example.com"]);
    }
}

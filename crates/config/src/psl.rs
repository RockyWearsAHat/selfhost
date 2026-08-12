//! The Public Suffix List: where a registrable domain actually begins.
//!
//! `registrable("shop.example.co.uk")` must answer `example.co.uk`, and there is
//! no shortcut that gets this right: the set of public suffixes is thousands of
//! entries (`co.uk`, `com.au`, `surf`, `*.ck`, …) maintained by Mozilla at
//! <https://publicsuffix.org>. A hand-kept shortlist silently mis-groups every
//! domain under a suffix it forgot, and the failure lands far away — a zone
//! derived for the wrong apex, or a certificate requested for a name that is
//! not ours to claim. So the real list is vendored at `data/public_suffix_list.dat`,
//! compiled in with `include_str!` (no runtime file, no network, no dependency),
//! and matched with the list's own algorithm.
//!
//! Only the **ICANN section** is read. The private section (`github.io`,
//! `s3.amazonaws.com`, …) marks operator-drawn boundaries, not registry ones,
//! and this crate's question is always "what is the registrable domain" — the
//! apex a zone is derived for.
//!
//! Refresh the vendored file with `scripts/update-psl.sh`; the list changes a
//! few times a year and a stale copy degrades exactly like the shortlist did,
//! one forgotten suffix at a time.

use std::collections::HashSet;
use std::sync::OnceLock;

/// The vendored list, exactly as published.
const LIST: &str = include_str!("../data/public_suffix_list.dat");

/// The ICANN rules, parsed once on first use.
struct Rules {
    /// Plain rules: the name itself is a public suffix (`co.uk`, `surf`).
    exact: HashSet<&'static str>,
    /// Wildcard rules, stored by parent: `*.ck` is held as `ck`, meaning every
    /// direct child of `ck` is a public suffix.
    wildcard: HashSet<&'static str>,
    /// Exception rules: `!www.ck` — the name a wildcard would otherwise cover
    /// that is *not* a public suffix.
    exception: HashSet<&'static str>,
}

/// Parses the ICANN section of the vendored list. Runs once; the list is a
/// compile-time constant, so failure modes are limited to the file's own
/// format, and an unrecognised line is skipped rather than trusted.
fn rules() -> &'static Rules {
    static RULES: OnceLock<Rules> = OnceLock::new();
    RULES.get_or_init(|| {
        let mut parsed = Rules {
            exact: HashSet::new(),
            wildcard: HashSet::new(),
            exception: HashSet::new(),
        };
        let mut in_icann = false;
        for line in LIST.lines() {
            let line = line.trim();
            if line == "// ===BEGIN ICANN DOMAINS===" {
                in_icann = true;
                continue;
            }
            if line == "// ===END ICANN DOMAINS===" {
                break;
            }
            if !in_icann || line.is_empty() || line.starts_with("//") {
                continue;
            }
            if let Some(exception) = line.strip_prefix('!') {
                parsed.exception.insert(exception);
            } else if let Some(parent) = line.strip_prefix("*.") {
                parsed.wildcard.insert(parent);
            } else {
                parsed.exact.insert(line);
            }
        }
        parsed
    })
}

/// The registered domain `name` belongs to — the public suffix plus one label,
/// lowercased — or `None` for a name nobody registers: a bare public suffix
/// (`co.uk`, `com`), a single label (`localhost`), or the empty string.
///
/// Matching follows the list's published algorithm: the longest matching rule
/// wins, an exception rule (`!www.ck`) beats the wildcard that would otherwise
/// cover it, and a name matching no rule at all treats its last label as the
/// suffix — so `real.example` still groups to itself rather than vanishing.
pub fn registrable(name: &str) -> Option<String> {
    let trimmed = name.trim_end_matches('.').to_ascii_lowercase();
    let labels: Vec<&str> = trimmed.split('.').collect();
    if labels.len() < 2 || labels.iter().any(|label| label.is_empty()) {
        return None;
    }

    let suffix_labels = public_suffix_len(&labels);
    if labels.len() <= suffix_labels {
        return None;
    }
    Some(labels[labels.len() - suffix_labels - 1..].join("."))
}

/// How many trailing labels of `labels` form the public suffix.
///
/// Every trailing slice is tested against the rules; per the list's algorithm
/// an exception match ends the search immediately (its suffix is the matched
/// name minus its leftmost label), and otherwise the longest exact or wildcard
/// match wins, with the default rule `*` guaranteeing at least one label.
fn public_suffix_len(labels: &[&str]) -> usize {
    let rules = rules();
    let mut longest = 1;
    for start in (0..labels.len()).rev() {
        let candidate = labels[start..].join(".");
        let length = labels.len() - start;
        if rules.exception.contains(candidate.as_str()) {
            return length - 1;
        }
        if rules.exact.contains(candidate.as_str()) {
            longest = longest.max(length);
        }
        if length >= 2 && rules.wildcard.contains(labels[start + 1..].join(".").as_str()) {
            longest = longest.max(length);
        }
    }
    longest
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plain_tlds_group_to_the_last_two_labels() {
        assert_eq!(registrable("WWW.Example.COM").as_deref(), Some("example.com"));
        assert_eq!(registrable("deep.sub.example.com").as_deref(), Some("example.com"));
        assert_eq!(registrable("example.com.").as_deref(), Some("example.com"));
        // The failure that motivated vendoring the real list: a niche TLD a
        // shortlist would never carry.
        assert_eq!(registrable("waves.surf").as_deref(), Some("waves.surf"));
        assert_eq!(registrable("big.waves.surf").as_deref(), Some("waves.surf"));
    }

    #[test]
    fn multi_label_suffixes_keep_a_third_label() {
        assert_eq!(registrable("shop.example.co.uk").as_deref(), Some("example.co.uk"));
        assert_eq!(registrable("example.co.uk").as_deref(), Some("example.co.uk"));
        assert_eq!(registrable("Example.COM.AU").as_deref(), Some("example.com.au"));
    }

    #[test]
    fn nobody_registers_a_bare_suffix_or_a_single_label() {
        assert_eq!(registrable("co.uk"), None);
        assert_eq!(registrable("com"), None);
        assert_eq!(registrable("surf"), None);
        assert_eq!(registrable("localhost"), None);
        assert_eq!(registrable(""), None);
        assert_eq!(registrable("bad..name"), None);
    }

    #[test]
    fn wildcard_and_exception_rules_are_honoured() {
        // `*.ck` makes every child of ck a suffix, so a domain needs a third
        // label — except `!www.ck`, carved back out by the exception rule.
        assert_eq!(registrable("shop.some.ck").as_deref(), Some("shop.some.ck"));
        assert_eq!(registrable("some.ck"), None);
        assert_eq!(registrable("www.ck").as_deref(), Some("www.ck"));
        assert_eq!(registrable("deep.www.ck").as_deref(), Some("www.ck"));
    }

    #[test]
    fn private_section_boundaries_are_registry_invisible() {
        // github.io sits in the PRIVATE section: the registry sold `github.io`
        // itself (under the ICANN rule `io`), so that is the registrable name.
        assert_eq!(registrable("user.github.io").as_deref(), Some("github.io"));
    }

    #[test]
    fn a_name_matching_no_rule_still_groups_to_two_labels() {
        // Not every name people serve is on the list (LAN pseudo-domains); the
        // default rule keeps them grouping instead of vanishing.
        assert_eq!(registrable("real.example").as_deref(), Some("real.example"));
        assert_eq!(registrable("a.b.internal").as_deref(), Some("b.internal"));
    }
}

//! Turning an attacker-controlled request path into a name inside one share.
//!
//! This is the single most security-critical file in the project. Everything the
//! NAS does — listing, downloading, uploading, moving, deleting — begins by
//! deciding which name on disk a caller asked for, and a mistake here is not a
//! bug in a feature. It is "read any file on the box", and on the write path it
//! is "write any file on the box", which on a machine whose own source tree
//! rebuilds and restarts itself is remote code execution.
//!
//! # What the static file server already does, and why it is not enough
//!
//! `crates/proxy/src/files.rs` has stood in front of a public listener for a
//! while and its traversal defence is correct for what it defends. Precisely,
//! `files.rs::resolve` (`:82`) and its helpers do six things:
//!
//! 1. **Percent-decode first** (`percent_decode`, `:41`), refusing a malformed
//!    escape outright rather than passing the half-decoded text through, and
//!    refusing a decoded NUL byte because a NUL truncates the path for every
//!    C-based syscall layer underneath us. Decoding *after* the traversal check
//!    is exactly how `%2e%2e%2f` gets through, so the order is the defence.
//! 2. **Refuse a decoded NUL again** on the whole string (`:87`).
//! 3. **Map `\` to `/`** (`:92`) so a Windows backslash cannot smuggle a
//!    separator past a check that only looks for `/`.
//! 4. **Skip `""` and `"."`** segments (`:97`).
//! 5. **Refuse `..` rather than pop it** (`:98-102`). Popping serves a
//!    *different* file than was asked for and hides the attempt; refusing says
//!    what happened.
//! 6. **Require each remaining segment to be exactly one `Component::Normal`**
//!    (`:104-112`), with no second component — which is what stops a drive
//!    letter, a UNC prefix, or a root from arriving inside a segment.
//! 7. Finally **`confine()`** (`:172`) canonicalises the candidate and asserts
//!    it still starts with the canonicalised root, which is the only thing that
//!    catches a symlink inside the root pointing outside it.
//!
//! Every one of those rules is inherited here. What is *not* inherited is the
//! function itself, and the reason is worth stating plainly, because "call the
//! existing one" is the obvious review comment:
//!
//! - `confine()` canonicalises **the candidate**. `Path::canonicalize` returns
//!   `ENOENT` for a path that does not exist yet, so it answers "rejected" for
//!   every single file a caller is trying to create. A write path cannot be
//!   built on it.
//! - `resolve()` **invents paths**. It falls back to a directory index, then to
//!   the clean-URL form (`/about` → `about.html`), then to an SPA shell. That is
//!   exactly right for a published site and catastrophic for a file share: a
//!   `GET` for a file that does not exist would silently return the *contents of
//!   a different file*, and a client that stores what it downloaded would then
//!   overwrite the original with it.
//!
//! Underneath both differences is one fact about the two problems. **A static
//! root is read-only, published, and never written by a caller. A share is none
//! of those.** Its contents were put there by people; its names were chosen by
//! people; a caller can create a name, and therefore a caller can create a name
//! designed to be misread later — including a symlink, which no amount of string
//! handling can catch. So a share needs every rule a static root needs, plus the
//! rules that only matter once names are attacker-chosen: the Windows path
//! normalisation that turns `".. "` back into `".."`, the colon that opens an
//! NTFS alternate data stream, the reserved device names, the 8.3 aliases, and
//! the case collisions that destroy data on a case-insensitive volume without
//! any byte comparison ever noticing.
//!
//! # The division of labour — read this before assuming this file is enough
//!
//! **This module is pure. It never touches the filesystem, and it therefore
//! cannot be the confinement.**
//!
//! A pure function cannot `stat`, so it cannot know that `photos` is a symlink
//! to `/`. Text alone can prove that a request names something *textually*
//! inside the root; only the *open* can prove that the bytes it reaches are
//! inside the root. On a read-only published site that gap is theoretical,
//! because nobody can create the symlink. On a NAS the attacker can create it —
//! over WebDAV, over SMB, or as any local user of the box.
//!
//! So the contract is split, and both halves are mandatory:
//!
//! | Layer | Proves | Mechanism |
//! |---|---|---|
//! | `path.rs` (here, pure) | the *text* names one file inside the share | this module |
//! | `fs.rs` (impure, **still owed** — Phase 3) | the *bytes* live inside the share | descriptor walk, `O_NOFOLLOW\|O_DIRECTORY` per component on unix, `FILE_FLAG_OPEN_REPARSE_POINT` on Windows |
//!
//! The second row is a requirement, not a description of code that exists:
//! [`crate::fs`] today holds only the creation primitive, and its documentation
//! says which of its promises are kept and which are owed. Nothing in this crate
//! may treat the walk as done until it is.
//!
//! [`Resolved::textual_path`] is named the way it is so that this cannot be
//! forgotten at a call site. Handing that path to `File::open` is a defect even
//! though it compiles, and the accessor's own documentation says so.
//!
//! # Decoding happens exactly once
//!
//! [`resolve`] percent-decodes its input one time. A doubly-encoded traversal
//! (`%252e%252e`) therefore decodes to the literal seven-character name
//! `%2e%2e`, which is an ordinary legal filename and is treated as one. That is
//! the correct answer and it is asserted in the table below, because the classic
//! way this file gets broken is somebody "fixing" a bug report by decoding in a
//! loop until the string stops changing — at which point `%252e%252e` becomes
//! `..` and the traversal defence has been removed by hand.
//!
//! # The round trip is an invariant, and it is this module's to state
//!
//! Decoding once is right, and it has a consequence in the other direction that
//! has to be said out loud because it is a rule on every layer above: **`%` is
//! an ordinary character in a name.** A `PUT /a%252fb` creates the
//! five-character name `a%2fb`. Hand that stored name back to a client
//! unencoded — in a JSON listing the console turns into a link, in a WebDAV
//! `href`, in a breadcrumb — and the client asks for `/a%2fb`, which this module
//! decodes to `a/b`: a different file, one directory down. A `GET` then reads
//! the wrong file and a `PUT` writes one.
//!
//! So the invariant, which [`encode_segment`] exists to keep and which the tests
//! assert over every name the resolver accepts:
//!
//! ```text
//! resolve(root, "/" + encode_segment(name)).relative().segments() == [name]
//! ```
//!
//! It is enforceable rather than advisory because no type in this crate renders
//! a name into a link without it: [`RelativePath::to_url_path`] is the only
//! whole-path spelling offered for a URL, and
//! [`crate::listing::Entry::to_json`] cannot be called without the parent path
//! it needs to emit an encoded `href`, so a caller cannot reach the raw name and
//! forget. `Display` for [`RelativePath`] remains the *unencoded* form, because
//! that is what breadcrumb labels, log lines and the API's `path` field want —
//! and its documentation says which of the two a reader is holding.
//!
//! [`encode_segment`] is the third percent-encoder in this repository
//! ([`crate::respond`]'s RFC 5987 one, and `registrar/src/lib.rs:264`). All
//! three should collapse onto `crates/http/src/uri.rs` when the plan's shared
//! `uri` module lands; that is the encoder that must exist, and until it does
//! this one is the storage crate's answer rather than a private convenience.

use std::fmt;
use std::path::{Component, Path, PathBuf};

/// Longest single name component, in bytes.
///
/// 255 is the limit every filesystem this box will ever see agrees on: ext4,
/// APFS, NTFS and exFAT all cap a component at 255 (bytes for the first,
/// UTF-16 code units for the last two, and 255 bytes is the stricter of the
/// two readings, so this is safe on all of them).
pub const MAX_SEGMENT_BYTES: usize = 255;

/// Longest whole path, in bytes, counting the share root.
///
/// This is Linux's `PATH_MAX`, the smallest of the three platforms' limits, so
/// a path accepted here can be expressed on any of them.
///
/// Windows' classic 260-character `MAX_PATH` is deliberately **not** enforced.
/// Long-path support has been available since Windows 10 1607 and a share may
/// legitimately already contain files whose paths exceed it; refusing them here
/// would make files that exist on the volume permanently unreachable through
/// the NAS while remaining visible over SMB. Where the OS genuinely cannot open
/// a long path it returns its own error, which the filesystem layer reports
/// honestly rather than guessing about in advance.
pub const MAX_PATH_BYTES: usize = 4096;

/// The prefix reserved for the filesystem layer's own in-progress writes.
///
/// When a caller asks to **replace** an existing file, [`crate::fs::Upload`]
/// stages the new bytes as `<directory>/.selfhost-tmp-<unique>` beside the
/// destination and renames it into place — beside it, because rename is atomic
/// only within a filesystem and a share may well live on a different volume
/// than `data_dir` (the same argument `crates/admin/src/store.rs:77-88` makes
/// for its own atomic writes). A *fresh* file never uses this prefix at all: it
/// is created at its own name, for the reason `fs`'s module documentation gives
/// at length.
///
/// A caller who could *name* a file with this prefix could plant a file that a
/// concurrent replace would then rename over, so the prefix is refused on the
/// way in and belongs to us alone.
pub const TEMP_PREFIX: &str = ".selfhost-tmp-";

/// Characters that may never appear in a segment, on any platform.
///
/// The colon is the one that changes an outcome rather than a naming
/// convention. `readme.txt:evil` parses as exactly one `Component::Normal` on
/// every platform — only a *single-letter* prefix is recognised as a drive — so
/// without this rule a `PUT` writes an NTFS alternate data stream: a second
/// body of bytes hanging off a file that no directory listing shows, that no
/// quota counts, and that a `DELETE` of the visible file does not necessarily
/// remove. The rest are refused because Windows rejects them anyway and a name
/// that one platform accepts and another refuses is a share that cannot be
/// migrated between them.
const FORBIDDEN_CHARS: [char; 7] = ['"', '*', ':', '<', '>', '?', '|'];

// ---------------------------------------------------------------------------
// The table comes first on purpose.
//
// This module's rules *are* its specification, and the specification is a list
// of concrete attacks with concrete answers. Everything below the table is only
// an implementation of it. A reader who wants to know what this file promises
// should not have to read the code to find out, and a reader changing the code
// should have to walk past what they are about to break.
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn root() -> PathBuf {
        PathBuf::from("/srv/share")
    }

    /// Every refusal this module makes, as `(request path, why)`.
    ///
    /// Each row is an attack somebody has actually used against a file server.
    const REFUSED: &[(&str, Refusal)] = &[
        // --- Traversal, in every dress Windows path normalisation permits ---
        ("/../etc/passwd", Refusal::Traversal),
        ("/a/../../b", Refusal::Traversal),
        // Windows strips trailing dots and spaces from a component *before the
        // filesystem sees it*, so each of these normalises back to "..". An
        // exact-equality check against ".." — which is what a read-only static
        // server can afford — passes every one of them straight through.
        ("/.. /passwd", Refusal::Traversal),
        ("/.../passwd", Refusal::Traversal),
        ("/.. ./passwd", Refusal::Traversal),
        ("/..../passwd", Refusal::Traversal),
        // Percent-encoded, decoded before the check rather than after it.
        ("/%2e%2e/passwd", Refusal::Traversal),
        ("/%2E%2E/passwd", Refusal::Traversal),
        ("/%2e%2e%20/passwd", Refusal::Traversal),
        ("/..%20/passwd", Refusal::Traversal),
        ("/%2e./passwd", Refusal::Traversal),
        // A backslash is a separator on Windows, so it must be one here too —
        // on *every* host, or a share written on a Mac becomes traversable the
        // day it is served from the Windows box.
        ("/..\\..\\passwd", Refusal::Traversal),
        ("/%2e%2e%5cpasswd", Refusal::Traversal),
        // A segment that is nothing but dots and spaces leaves no name at all.
        ("/. /x", Refusal::EffectivelyEmpty),
        ("/%20/x", Refusal::EffectivelyEmpty),
        ("/   /x", Refusal::EffectivelyEmpty),
        // --- Names Windows would silently rewrite ---
        ("/notes.txt.", Refusal::TrailingDotOrSpace),
        ("/notes.txt ", Refusal::TrailingDotOrSpace),
        ("/dir. /file", Refusal::TrailingDotOrSpace),
        ("/notes.txt%20", Refusal::TrailingDotOrSpace),
        // --- NTFS alternate data streams and the other Windows-illegal set ---
        ("/readme.txt:evil", Refusal::ForbiddenCharacter(':')),
        ("/C:/Windows/win.ini", Refusal::ForbiddenCharacter(':')),
        ("/a/b:stream", Refusal::ForbiddenCharacter(':')),
        ("/what?.txt", Refusal::ForbiddenCharacter('?')),
        ("/a<b", Refusal::ForbiddenCharacter('<')),
        ("/a>b", Refusal::ForbiddenCharacter('>')),
        ("/a|b", Refusal::ForbiddenCharacter('|')),
        ("/a*b", Refusal::ForbiddenCharacter('*')),
        ("/a\"b", Refusal::ForbiddenCharacter('"')),
        // --- Reserved device stems: the rule is on the stem, so an extension
        //     does not rescue them ---
        ("/CON", Refusal::ReservedDeviceName),
        ("/NUL", Refusal::ReservedDeviceName),
        ("/AUX", Refusal::ReservedDeviceName),
        ("/PRN", Refusal::ReservedDeviceName),
        ("/CON.txt", Refusal::ReservedDeviceName),
        ("/con.txt.gz", Refusal::ReservedDeviceName),
        ("/CoM1", Refusal::ReservedDeviceName),
        ("/lpt9.log", Refusal::ReservedDeviceName),
        // Microsoft's list also holds the zeroth ports and the surviving DOS
        // clock device; a denylist that is nearly the vendor's reads as
        // complete and is not.
        ("/COM0", Refusal::ReservedDeviceName),
        ("/lpt0.txt", Refusal::ReservedDeviceName),
        ("/CLOCK$", Refusal::ReservedDeviceName),
        ("/clock$.log", Refusal::ReservedDeviceName),
        ("/CONIN$", Refusal::ReservedDeviceName),
        ("/conout$.txt", Refusal::ReservedDeviceName),
        ("/dir/NUL/file", Refusal::ReservedDeviceName),
        // --- 8.3 short names alias a long name, defeating both a name denylist
        //     and the case-collision scan ---
        ("/PROGRA~1", Refusal::ShortName),
        ("/progra~1/x", Refusal::ShortName),
        ("/AB~9.txt", Refusal::ShortName),
        // A `+` is not a hexadecimal digit, but `u8::from_str_radix` accepts a
        // leading sign — so the escape parser checks the digits itself rather
        // than delegating the whole decision.
        ("/a%+1b", Refusal::MalformedEscape),
        ("/a% 1b", Refusal::MalformedEscape),
        // --- NUL, malformed escapes, and non-UTF-8 ---
        ("/a%00b", Refusal::EncodedNul),
        ("/a\0b", Refusal::Nul),
        ("/a%zzb", Refusal::MalformedEscape),
        ("/a%2", Refusal::MalformedEscape),
        ("/a%", Refusal::MalformedEscape),
        ("/a%ffb", Refusal::NotUtf8),
        // A control byte in a name breaks every log line and every listing that
        // ever renders it.
        ("/a%01b", Refusal::ControlCharacter),
        ("/a%0ab", Refusal::ControlCharacter),
        ("/a%7fb", Refusal::ControlCharacter),
        // --- Our own reserved namespace ---
        (".selfhost-tmp-abc", Refusal::ReservedPrefix),
        ("/dir/.selfhost-tmp-abc", Refusal::ReservedPrefix),
    ];

    #[test]
    fn refuses_every_known_attack() {
        for (input, expected) in REFUSED {
            let outcome = resolve(&root(), input);
            assert_eq!(
                outcome.as_ref().err(),
                Some(expected),
                "input {input:?} should be refused as {expected:?}, got {outcome:?}"
            );
        }
    }

    /// Paths that are legal names and must survive, with the segments they mean.
    const ACCEPTED: &[(&str, &[&str])] = &[
        ("/", &[]),
        ("", &[]),
        ("/notes.txt", &["notes.txt"]),
        ("/a/b/c.txt", &["a", "b", "c.txt"]),
        ("/a//b", &["a", "b"]),
        ("/./a/./b", &["a", "b"]),
        ("/a%20b.txt", &["a b.txt"]),
        ("/caf%C3%A9.txt", &["café.txt"]),
        // A leading slash is how every request target arrives; it is not an
        // "absolute path" attack, because the segments are joined onto the root
        // rather than replacing it.
        ("/etc/passwd", &["etc", "passwd"]),
        // A backslash used as a separator resolves the same way a slash does,
        // on a unix host as well as a Windows one.
        ("/a\\b\\c.txt", &["a", "b", "c.txt"]),
        // A UNC-looking prefix loses its meaning entirely: the empty segments
        // vanish and what is left names a file *inside* the share. Confinement,
        // not refusal, is the right answer — `\\server\share` under a share root
        // is just a directory called `server`.
        ("//server/share/file", &["server", "share", "file"]),
        ("\\\\server\\share\\file", &["server", "share", "file"]),
        // Decoded exactly once. `%252e%252e` is a file literally named `%2e%2e`,
        // and treating it as `..` would mean this module decodes in a loop —
        // which is how a traversal defence gets removed by a well-meaning fix.
        ("/%252e%252e/x", &["%2e%2e", "x"]),
        // Leading dots are ordinary. Only a name that *reduces* to `.` or `..`
        // is a traversal.
        ("/.hidden", &[".hidden"]),
        ("/..hidden", &["..hidden"]),
        ("/...hidden", &["...hidden"]),
        // A name that merely contains a reserved stem is not one.
        ("/CONTRACT.pdf", &["CONTRACT.pdf"]),
        ("/NULL.txt", &["NULL.txt"]),
        ("/COM10.log", &["COM10.log"]),
        // A tilde is only an 8.3 shape when a digit follows it and the stem is
        // short enough for the OS to have generated it.
        ("/backup~.txt", &["backup~.txt"]),
        ("/document~1.txt", &["document~1.txt"]),
        ("/a~b", &["a~b"]),
        // Our reserved prefix is a prefix, not a substring.
        ("/x.selfhost-tmp-abc", &["x.selfhost-tmp-abc"]),
    ];

    #[test]
    fn accepts_and_confines_every_legal_name() {
        for (input, expected) in ACCEPTED {
            let resolved = resolve(&root(), input)
                .unwrap_or_else(|e| panic!("input {input:?} should resolve, got {e:?}"));
            assert_eq!(resolved.relative().segments(), *expected, "input {input:?}");
            assert!(
                resolved.textual_path().starts_with(root()),
                "input {input:?} left the root: {:?}",
                resolved.textual_path()
            );
        }
    }

    #[test]
    fn segment_length_is_capped_at_the_filesystem_limit() {
        let longest = "a".repeat(MAX_SEGMENT_BYTES);
        assert!(resolve(&root(), &format!("/{longest}")).is_ok());

        let too_long = "a".repeat(MAX_SEGMENT_BYTES + 1);
        assert_eq!(
            resolve(&root(), &format!("/{too_long}")).unwrap_err(),
            Refusal::SegmentTooLong
        );

        // Multi-byte characters count as the bytes they occupy, because the
        // filesystem counts bytes.
        let multibyte = "é".repeat(MAX_SEGMENT_BYTES / 2 + 1);
        assert_eq!(resolve(&root(), &format!("/{multibyte}")).unwrap_err(), Refusal::SegmentTooLong);
    }

    #[test]
    fn whole_path_is_capped_including_the_root() {
        // Refused before decoding, so an enormous request costs nothing.
        let huge = "a/".repeat(MAX_PATH_BYTES);
        assert_eq!(resolve(&root(), &huge).unwrap_err(), Refusal::PathTooLong);

        // And refused again *after joining*, because a long root plus a short,
        // entirely legal relative path can exceed the limit when neither does
        // on its own. Only the second check catches this one.
        let long_root = PathBuf::from(format!("/{}", "r".repeat(MAX_PATH_BYTES - 1)));
        assert_eq!(resolve(&long_root, "/a").unwrap_err(), Refusal::PathTooLong);
        assert!(resolve(&long_root, "/").is_ok());

        let near_root = PathBuf::from("/x");
        assert!(resolve(&near_root, "/a/b/c").is_ok());
    }

    #[test]
    fn a_segment_must_be_exactly_one_normal_component() {
        // This is the rule that stops a `PathBuf::push` from *replacing* the
        // root rather than extending it. Constructed rather than requested,
        // because the separator mapping above already turns most of these into
        // ordinary multi-segment paths.
        assert_eq!(validate_segment("."), Err(Refusal::EffectivelyEmpty));
        assert_eq!(validate_segment(".."), Err(Refusal::Traversal));
        assert_eq!(validate_segment("a/b"), Err(Refusal::NotOneComponent));
        assert_eq!(validate_segment("a\\b"), Err(Refusal::NotOneComponent));
        assert_eq!(validate_segment("/"), Err(Refusal::NotOneComponent));
        assert_eq!(validate_segment(""), Err(Refusal::EffectivelyEmpty));
        assert_eq!(validate_segment("ok.txt"), Ok(()));
    }

    #[test]
    fn case_collisions_are_visible_to_the_filesystem_layer() {
        // On APFS and NTFS these two names are one file, so creating the second
        // beside the first destroys data while a byte comparison sees nothing.
        assert!(collides("Report.pdf", "report.pdf"));
        assert!(collides("REPORT.PDF", "report.pdf"));
        assert!(collides("Résumé.doc", "résumé.doc"));
        // Byte-identical is not a collision — it is an overwrite, which is a
        // different decision made elsewhere.
        assert!(!collides("report.pdf", "report.pdf"));
        assert!(!collides("report.pdf", "report2.pdf"));
        assert!(!collides("a.txt", "b.txt"));
    }

    #[test]
    fn trailing_slash_is_carried_because_a_collection_is_not_a_file() {
        assert!(resolve(&root(), "/dir/").unwrap().trailing_slash());
        assert!(!resolve(&root(), "/dir").unwrap().trailing_slash());
        // The share root is always a collection.
        assert!(resolve(&root(), "/").unwrap().trailing_slash());
        assert!(resolve(&root(), "").unwrap().trailing_slash());
    }

    #[test]
    fn a_relative_path_reports_its_own_shape() {
        let resolved = resolve(&root(), "/a/b/c.txt").unwrap();
        let relative = resolved.relative();
        assert_eq!(relative.to_string(), "a/b/c.txt");
        assert_eq!(relative.file_name(), Some("c.txt"));
        assert_eq!(relative.parent().to_string(), "a/b");
        assert!(!relative.is_root());

        let root_path = resolve(&root(), "/").unwrap();
        assert!(root_path.relative().is_root());
        assert_eq!(root_path.relative().to_string(), "");
        assert_eq!(root_path.relative().file_name(), None);
        assert_eq!(root_path.relative().parent().to_string(), "");
        assert_eq!(root_path.textual_path(), root());
    }

    #[test]
    fn refusals_say_what_happened_without_repeating_the_input() {
        // A refusal is logged; the caller is told 404. So the message names the
        // rule, never the attacker's string — a log line that echoes untrusted
        // bytes is a second injection surface.
        for (input, _) in REFUSED {
            let message = resolve(&root(), input).unwrap_err().to_string();
            assert!(!message.is_empty());
            assert!(!message.contains(*input), "refusal echoed its input: {message}");
        }
    }

    #[test]
    fn every_forbidden_character_is_refused_by_name() {
        for bad in FORBIDDEN_CHARS {
            let segment = format!("a{bad}b");
            assert_eq!(validate_segment(&segment), Err(Refusal::ForbiddenCharacter(bad)));
        }
    }

    #[test]
    fn percent_decoding_is_total() {
        assert_eq!(percent_decode("abc"), Ok("abc".to_string()));
        assert_eq!(percent_decode("a%2fb"), Ok("a/b".to_string()));
        assert_eq!(percent_decode("%41"), Ok("A".to_string()));
        assert_eq!(percent_decode("%"), Err(Refusal::MalformedEscape));
        assert_eq!(percent_decode("%4"), Err(Refusal::MalformedEscape));
        assert_eq!(percent_decode("%4g"), Err(Refusal::MalformedEscape));
        assert_eq!(percent_decode("%00"), Err(Refusal::EncodedNul));
        assert_eq!(percent_decode("%ff"), Err(Refusal::NotUtf8));
        // Every byte value that can appear, one at a time, must produce either a
        // string or a typed error — never a panic, which under `panic = "abort"`
        // would take the whole box down with it.
        for byte in 0u8..=255 {
            let _ = percent_decode(&format!("%{byte:02x}"));
            let _ = percent_decode(std::str::from_utf8(&[byte]).unwrap_or("?"));
        }
    }

    // -----------------------------------------------------------------------
    // Adversarial review, 2026-08-10. The tests below were added by a reviewer
    // whose brief was to escape a share root and to find the vector the table
    // above does not cover. They pin behaviour that is *currently* what the code
    // does; where that behaviour is a gap rather than a decision, the test says
    // so and names the layer that has to close it. Nothing here changes the
    // implementation.
    // -----------------------------------------------------------------------

    /// Confinement holds under a combinatorial sweep of hostile fragments.
    ///
    /// The refusal table above is a list of named attacks. This is the property
    /// the table is trying to establish, asserted directly: for *every* input
    /// the resolver accepts, the joined path is still under the root and no
    /// surviving segment is a separator, a `.` or a `..`. The alphabet is the
    /// pieces every published traversal is built out of, four deep, which is
    /// enough to reach `..%2f..%5c` and `%252e%252e` and `.. .` and their
    /// interleavings — roughly 38k inputs.
    ///
    /// It found no escape, which is the finding: the *textual* half of the
    /// contract is sound. Every hole the reviewer did find is somewhere else —
    /// in the root this resolver is handed, or in what happens to a name after
    /// this module has blessed it.
    #[test]
    fn confinement_holds_across_a_combinatorial_sweep_of_hostile_fragments() {
        const FRAGMENTS: &[&str] = &[
            "..", ".", "", "a", "/", "\\", "%2e", "%2f", "%5c", " ", "%20", "...", ".. ", "%252e",
        ];

        let root = root();
        let mut accepted = 0usize;
        for a in FRAGMENTS {
            for b in FRAGMENTS {
                for c in FRAGMENTS {
                    for d in FRAGMENTS {
                        let input = format!("/{a}{b}{c}{d}");
                        let Ok(resolved) = resolve(&root, &input) else {
                            continue;
                        };
                        accepted += 1;
                        assert!(
                            resolved.textual_path().starts_with(&root),
                            "{input:?} left the root as {:?}",
                            resolved.textual_path()
                        );
                        for segment in resolved.relative().segments() {
                            assert!(
                                !segment.contains('/')
                                    && !segment.contains('\\')
                                    && segment != "."
                                    && segment != "..",
                                "{input:?} produced the segment {segment:?}"
                            );
                        }
                    }
                }
            }
        }
        assert!(accepted > 1000, "the sweep must actually accept things: {accepted}");
    }

    /// [`collides`] is a case fold and says so; the clobber it cannot see is
    /// stopped by the volume, in [`crate::fs`].
    ///
    /// The reviewer's finding was not that this fold is incomplete — a pure
    /// function cannot know another machine's normalisation rules — but that
    /// the documentation named a mitigation that could not fire. It claimed the
    /// remainder was caught by "the filesystem layer's atomic create —
    /// `CREATE_NEW` / `O_EXCL`", while the scheme `fs.rs` described was *temp
    /// file, then rename*: the exclusive create guarded the temp name and
    /// `rename(2)` replaced the destination silently. On this machine's APFS
    /// volume the full sequence destroyed the original file with no error
    /// anywhere.
    ///
    /// What changed is the mechanism, not this function.
    /// [`crate::fs::Upload::begin`] creates **at the destination name**, so the
    /// volume answers the question this fold cannot, and
    /// `fs::tests::an_nfd_upload_cannot_destroy_the_nfc_file_it_folds_onto`
    /// recreates the reviewer's exact scenario against a real directory. This
    /// test now pins the honest contract: a `true` here is reliable, a `false`
    /// is not a promise of distinctness, and nothing may be built on the second.
    #[test]
    fn the_collision_fold_is_advisory_and_documented_as_such() {
        // Case: caught, and correctly. This is the half that produces a good
        // `409` message naming the file that is in the way.
        assert!(collides("Report.pdf", "report.pdf"));
        assert!(collides("R\u{c9}SUM\u{c9}.doc", "r\u{e9}sum\u{e9}.doc"));

        // Normalisation: not caught, and by design — see `collides`. A volume
        // that folds these two into one file refuses the create itself.
        let nfc = "caf\u{e9}.txt"; // é          U+00E9
        let nfd = "cafe\u{301}.txt"; // e + U+0301
        assert_ne!(nfc, nfd, "the two spellings are different bytes");
        assert!(!collides(nfc, nfd));
        assert!(!collides("\u{d55c}.txt", "\u{1112}\u{1161}\u{11ab}.txt"));

        // And the over-refusal in the other direction, which is harmless and is
        // now stated in the doc: the Kelvin sign lowercases onto an ordinary
        // `k`, so an upload named `K.txt` is answered `409` beside a `k.txt`
        // even on a case-sensitive volume where both could exist.
        assert!(collides("\u{212a}.txt", "k.txt"));
    }

    /// A name may contain a literal `%`, and [`encode_segment`] is what makes
    /// the round trip back through a URL name the same file again.
    ///
    /// The reviewer's finding was that this invariant existed and was unstated,
    /// with no encoder anywhere in the crate to keep it. Both halves are fixed:
    /// the module documentation states it, and this test asserts it over every
    /// name the module accepts — including the hostile ones, whose whole point
    /// is that they mean something *else* when a decoder sees them twice.
    #[test]
    fn a_stored_name_round_trips_through_the_encoder_and_not_without_it() {
        // One legal name, five characters of it, created by an upload.
        let stored = resolve(&root(), "/a%252fb").unwrap();
        assert_eq!(stored.relative().segments(), ["a%2fb"]);
        assert_eq!(stored.textual_path(), root().join("a%2fb"));

        // Unencoded, the stored name names a different file one directory down.
        let raw = resolve(&root(), &format!("/{}", stored.relative())).unwrap();
        assert_eq!(raw.relative().segments(), ["a", "b"]);
        assert_ne!(raw.relative(), stored.relative());

        // Encoded, it names itself.
        let encoded = resolve(&root(), &format!("/{}", stored.relative().to_url_path())).unwrap();
        assert_eq!(encoded.relative(), stored.relative());

        // The invariant, over every name this module accepts — the legal table
        // above, plus the names that only exist because a `%` survives.
        let names: Vec<String> = ACCEPTED
            .iter()
            .flat_map(|(_, segments)| segments.iter().map(|s| (*s).to_string()))
            .chain(
                ["a%2fb", "%2e%2e", "a b.txt", "100%.txt", "a#b&c.txt", "café.txt", "'quote'"]
                    .iter()
                    .map(|s| (*s).to_string()),
            )
            .collect();
        for name in names {
            let request = format!("/{}", encode_segment(&name));
            let resolved = resolve(&root(), &request)
                .unwrap_or_else(|e| panic!("encoded {name:?} became unresolvable: {e:?}"));
            assert_eq!(
                resolved.relative().segments(),
                std::slice::from_ref(&name),
                "round trip of {name:?}"
            );
        }

        // The whole-path form encodes every segment, and `Display` deliberately
        // does not — the two are different answers to different questions.
        let path = RelativePath::default().join("a%2fb").unwrap().join("c d.txt").unwrap();
        assert_eq!(path.to_string(), "a%2fb/c d.txt");
        assert_eq!(path.to_url_path(), "a%252fb/c%20d.txt");
        assert_eq!(resolve(&root(), &format!("/{}", path.to_url_path())).unwrap().relative(), &path);

        // An empty path is empty in both spellings, not a stray slash.
        assert_eq!(RelativePath::default().to_url_path(), "");
    }

    /// The reserved-device denylist is Microsoft's whole list.
    ///
    /// `COM0` and `LPT0` appear in *Naming Files, Paths, and Namespaces*
    /// alongside `COM1`–`COM9`; `CLOCK$` is the surviving DOS device the NT
    /// namespace still recognises. None of the three was ever an escape — the
    /// worst case is the one the rule already defends against, an upload that
    /// opens a device and silently stores nothing — but a denylist that is
    /// nearly the vendor's list reads as complete, which is the defect.
    #[test]
    fn the_reserved_device_denylist_is_microsofts_own_list() {
        for reserved in [
            "CON", "PRN", "AUX", "NUL", "CONIN$", "CONOUT$", "CLOCK$", "COM0", "COM1", "COM9",
            "LPT0", "LPT9", "clock$", "lpt0.txt", "COM\u{b9}",
        ] {
            assert_eq!(
                validate_segment(reserved),
                Err(Refusal::ReservedDeviceName),
                "{reserved:?} names a device"
            );
        }

        // Still ordinary names: the rule is on the stem, and a second digit
        // takes a name out of the device range entirely.
        for ordinary in ["CONTRACT.pdf", "NULL.txt", "COM10.log", "LPT10", "CLOCK", "COM"] {
            assert_eq!(validate_segment(ordinary), Ok(()), "{ordinary:?} is a file");
        }
    }

    /// **Not a gap — recorded because it looks like one.**
    ///
    /// A backslash is mapped to a separator on every platform, which is right
    /// for the attack it stops and wrong for a name that legitimately contains
    /// one: `a\b.txt` is an ordinary filename on ext4 and APFS, and a share
    /// that already holds one cannot be addressed through the NAS at all. The
    /// listing layer will show the name and every request for it will resolve
    /// to `a/b.txt` instead; [`RelativePath::join`] refuses it outright, so
    /// even a walk that reads the name off the disk cannot build a path to it.
    ///
    /// That is a reachability bug, not a confinement bug, and the trade is the
    /// right way round. [`resolve`]'s own documentation now says so at step 4,
    /// which is where a reader tempted to `cfg`-gate the rule will be standing.
    #[test]
    fn a_backslash_in_a_real_filename_makes_that_file_unreachable() {
        let resolved = resolve(&root(), "/a%5Cb.txt").unwrap();
        assert_eq!(resolved.relative().segments(), ["a", "b.txt"]);
        assert_eq!(RelativePath::default().join("a\\b.txt"), Err(Refusal::NotOneComponent));

        // Not even the encoder rescues it: encoding the backslash produces the
        // same request the resolver splits, which is the honest consequence of
        // the mapping being unconditional.
        assert_eq!(
            resolve(&root(), &format!("/{}", encode_segment("a\\b.txt"))).unwrap().relative(),
            &RelativePath::default().join("a").unwrap().join("b.txt").unwrap()
        );
    }
}

/// Why a request path was refused.
///
/// Refusals are typed rather than boolean because they are logged, and an
/// operator reading "traversal" learns something an operator reading "bad path"
/// does not. They are deliberately *not* shown to the caller: a traversal
/// attempt is answered `404`, the same as a name that simply is not there, so a
/// prober cannot use the difference to map the filesystem — which is the choice
/// `proxy/src/server.rs:889` already makes for the static server.
///
/// No variant carries the offending text. A log line that echoes attacker bytes
/// is a second injection surface, and the rule that fired is the part worth
/// recording anyway.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Refusal {
    /// A `%` escape was truncated or not hexadecimal.
    MalformedEscape,
    /// An escape decoded to a NUL byte, which truncates the path for every
    /// C-based syscall layer beneath us.
    EncodedNul,
    /// A literal NUL arrived in the request path.
    Nul,
    /// The decoded bytes were not UTF-8. Creating a non-UTF-8 name is refused
    /// as policy, not by accident — see [`resolve`].
    NotUtf8,
    /// A segment named the parent directory, in some dress.
    Traversal,
    /// A segment was nothing but dots and spaces, so nothing is left of it once
    /// Windows has normalised it.
    EffectivelyEmpty,
    /// A real name carried trailing dots or spaces, which Windows strips before
    /// the filesystem sees the name — so the name we validated would not be the
    /// name that gets used.
    TrailingDotOrSpace,
    /// A character that may never appear in a name, most importantly `:`.
    ForbiddenCharacter(char),
    /// A control byte (below `0x20`, or `0x7f`) appeared in a name.
    ControlCharacter,
    /// A Windows reserved device stem: `CON`, `NUL`, `COM3`, `CONIN$`, and
    /// friends, with or without an extension.
    ReservedDeviceName,
    /// An 8.3 short-name shape such as `PROGRA~1`, which aliases a long name.
    ShortName,
    /// A name beginning with [`TEMP_PREFIX`], which belongs to the upload path.
    ReservedPrefix,
    /// A segment longer than [`MAX_SEGMENT_BYTES`].
    SegmentTooLong,
    /// A whole path longer than [`MAX_PATH_BYTES`], counting the share root.
    PathTooLong,
    /// A segment did not parse as exactly one ordinary name — it contained a
    /// separator, a root, or a platform prefix such as a drive letter.
    NotOneComponent,
}

impl fmt::Display for Refusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let reason = match self {
            Self::MalformedEscape => "malformed percent-escape",
            Self::EncodedNul => "percent-encoded NUL byte",
            Self::Nul => "NUL byte in path",
            Self::NotUtf8 => "path is not valid UTF-8",
            Self::Traversal => "segment names the parent directory",
            Self::EffectivelyEmpty => "segment is only dots and spaces",
            Self::TrailingDotOrSpace => "segment ends in a dot or a space",
            Self::ForbiddenCharacter(_) => "segment contains a character no name may hold",
            Self::ControlCharacter => "segment contains a control byte",
            Self::ReservedDeviceName => "segment names a reserved device",
            Self::ShortName => "segment is an 8.3 short-name alias",
            Self::ReservedPrefix => "segment uses the reserved upload prefix",
            Self::SegmentTooLong => "segment exceeds the filesystem's name limit",
            Self::PathTooLong => "path exceeds the platform's length limit",
            Self::NotOneComponent => "segment is not a single ordinary name",
        };
        f.write_str(reason)
    }
}

impl std::error::Error for Refusal {}

/// A validated path relative to a share root: zero or more ordinary names.
///
/// Every segment has passed [`validate_segment`], so this type is a proof rather
/// than a container — a value of it cannot be constructed from unvalidated text
/// outside this module, which is why the field is private.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct RelativePath {
    segments: Vec<String>,
}

impl RelativePath {
    /// The individual names, outermost first. Empty for the share root.
    pub fn segments(&self) -> &[String] {
        &self.segments
    }

    /// Whether this names the share root itself.
    pub fn is_root(&self) -> bool {
        self.segments.is_empty()
    }

    /// The last name, or `None` at the share root.
    pub fn file_name(&self) -> Option<&str> {
        self.segments.last().map(String::as_str)
    }

    /// The containing directory. The root's parent is the root, because a share
    /// has no outside and a caller asking for one gets the share back rather
    /// than an error that would tempt a caller into walking further.
    pub fn parent(&self) -> Self {
        let mut segments = self.segments.clone();
        segments.pop();
        Self { segments }
    }

    /// Extends this path by one already-validated name.
    ///
    /// Used by the filesystem and WebDAV layers, which build a child path from a
    /// name they read off the disk or out of a `Destination` header. The name is
    /// re-validated here rather than trusted, because a name that came *off* the
    /// disk is no safer than one that arrived on the wire — it may have been
    /// written over SMB by somebody else entirely.
    pub fn join(&self, segment: &str) -> Result<Self, Refusal> {
        validate_segment(segment)?;
        let mut segments = self.segments.clone();
        segments.push(segment.to_string());
        Ok(Self { segments })
    }

    /// The path as it may be put in a URL: each segment [`encode_segment`]ed,
    /// joined with slashes, no leading slash and none trailing.
    ///
    /// This is the **only** whole-path spelling that survives being sent to a
    /// client and asked for again. [`Display`](fmt::Display) renders the same
    /// path unencoded, which is right for a label, a log line and the API's
    /// `path` field and wrong for a link — see the module documentation's
    /// round-trip invariant.
    pub fn to_url_path(&self) -> String {
        self.segments.iter().map(|segment| encode_segment(segment)).collect::<Vec<_>>().join("/")
    }
}

impl fmt::Display for RelativePath {
    /// Renders as a slash-joined relative path, with no leading slash and none
    /// trailing, **unencoded**.
    ///
    /// This is the form the JSON API's `path` field, a breadcrumb *label* and a
    /// log line want: the name as a person wrote it. It is not a URL, and a name
    /// containing `%` or `#` will name something else if one is built out of it
    /// — [`RelativePath::to_url_path`] is that form.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.segments.join("/"))
    }
}

/// A request path resolved against a share root — **textually**.
///
/// See the module documentation's division-of-labour table. This value proves
/// that the request *names* something inside the share. It does not prove that
/// the bytes at that name are inside the share, and it cannot: no filesystem
/// call has happened.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Resolved {
    relative: RelativePath,
    full: PathBuf,
    trailing_slash: bool,
}

impl Resolved {
    /// The validated path relative to the share root.
    pub fn relative(&self) -> &RelativePath {
        &self.relative
    }

    /// The share root joined with the relative path — **before any filesystem
    /// check has happened**.
    ///
    /// Opening this path directly is a defect even though it compiles. A symlink
    /// planted anywhere along it — by a WebDAV client, by an SMB client, or by
    /// any local user — points wherever its author chose, and a plain
    /// `File::open` follows it out of the share without complaint. The
    /// filesystem layer must walk the components with directory descriptors and
    /// `O_NOFOLLOW` (or `FILE_FLAG_OPEN_REPARSE_POINT` on Windows) instead.
    ///
    /// It is still the right value to *display*, to log, and to compare against
    /// a canonicalised root once the walk has finished.
    pub fn textual_path(&self) -> &Path {
        &self.full
    }

    /// Whether the request arrived with a trailing slash.
    ///
    /// WebDAV distinguishes a collection from a file by this, and so does the
    /// browser file manager: `MKCOL /dav/vault/photos/` and a `PROPFIND` of a
    /// directory both mean something different from the same path without the
    /// slash. The share root always reports `true`, since a root is always a
    /// collection.
    pub fn trailing_slash(&self) -> bool {
        self.trailing_slash
    }
}

/// Resolves an attacker-controlled request path against one share root.
///
/// Pure: no filesystem call happens here, and the result is a *textual* claim
/// (see [`Resolved::textual_path`]).
///
/// The order of operations is itself the defence and must not be rearranged:
///
/// 1. cap the raw length, so an enormous request costs nothing to refuse;
/// 2. percent-decode **once**, refusing malformed escapes, encoded NULs and
///    non-UTF-8 bytes;
/// 3. refuse a literal NUL that arrived undecoded;
/// 4. map `\` to `/` on every platform, so a backslash cannot smuggle a
///    separator past a check that looks only for `/`;
/// 5. split, dropping `""` and `"."`, and validate every remaining segment;
/// 6. join onto the root and cap the total length.
///
/// **Step 4 has a cost, and it is paid in reachability.** A backslash is a legal
/// character in a filename on ext4 and APFS, so a share can genuinely contain a
/// file called `a\b.txt` — written over SMB, restored from a backup, or copied
/// from a Linux box. Because the mapping is unconditional, no request can ever
/// name that file: `/a%5Cb.txt` resolves to `a/b.txt` instead, and
/// [`RelativePath::join`] refuses the raw name outright, so even a walk that
/// reads the name off the disk cannot build a path to it. The listing layer
/// shows it, marked unreachable with the reason ([`crate::listing::Entry`]), and
/// the only way to get at it is over SMB or at the console. That is the
/// deliberate trade: one unreachable file on a unix volume, against a share
/// written on a Mac becoming traversable the day it is served from the Windows
/// box. It is stated here because a reader who does not know it will file the
/// symptom as a bug and "fix" it by making the rule `cfg(windows)`, which is the
/// vulnerability.
///
/// Non-UTF-8 names are a **stated policy**, not an accident of the decoder. We
/// refuse to *create* a name that is not valid UTF-8, because such a name cannot
/// be round-tripped through the JSON API, the WebDAV `href`, or the console
/// without becoming a different name — and a file you cannot name reliably is a
/// file you cannot reliably delete. An existing non-UTF-8 name on the volume is
/// reported by the listing layer as present but unreachable, which is honest
/// rather than silent.
pub fn resolve(root: &Path, request_path: &str) -> Result<Resolved, Refusal> {
    if request_path.len() > MAX_PATH_BYTES {
        return Err(Refusal::PathTooLong);
    }

    let decoded = percent_decode(request_path)?;

    // The decoder already refuses an encoded NUL; this catches one that arrived
    // as a raw byte in the target. `files.rs:87` makes the same double check for
    // the same reason: two paths into the same string deserve two guards.
    if decoded.contains('\0') {
        return Err(Refusal::Nul);
    }

    let normalised = decoded.replace('\\', "/");
    let trailing_slash = normalised.is_empty() || normalised.ends_with('/');

    let mut segments = Vec::new();
    for segment in normalised.split('/') {
        if segment.is_empty() || segment == "." {
            continue;
        }
        validate_segment(segment)?;
        segments.push(segment.to_string());
    }

    let mut full = root.to_path_buf();
    for segment in &segments {
        full.push(segment);
    }

    // Counted after joining, because a long root plus a legal relative path can
    // exceed the limit when neither does on its own.
    if full.as_os_str().len() > MAX_PATH_BYTES {
        return Err(Refusal::PathTooLong);
    }

    Ok(Resolved { relative: RelativePath { segments }, full, trailing_slash })
}

/// Checks one name for everything a share must refuse.
///
/// Public because the request line is not the only place a name arrives. A
/// WebDAV `Destination` header, a `MKCOL` collection name, a rename target and a
/// name read back off the disk all reach the filesystem the same way and all get
/// the identical treatment — a `MOVE` whose destination escapes the root is a
/// write-anywhere primitive as complete as a traversal on the request line.
///
/// A separator is refused here rather than split, because a caller of this
/// function is naming exactly one thing. Splitting would silently accept a path
/// where a name was required.
pub fn validate_segment(segment: &str) -> Result<(), Refusal> {
    // Windows removes trailing dots and spaces from every component before the
    // filesystem sees it. So the name we validate must be the name that gets
    // used: if stripping them changes the segment, we are validating a string
    // the operating system will not use, and `".. "` is `".."`.
    //
    // The rule is unconditional on purpose. It is not `cfg`-gated to Windows,
    // because a share written on the Mac is served from the Windows box the day
    // the data moves, and a `cfg`-gated security rule rots invisibly.
    let effective = segment.trim_end_matches(['.', ' ']);

    if effective == ".." || (effective.is_empty() && segment.contains("..")) {
        return Err(Refusal::Traversal);
    }
    if effective.is_empty() {
        return Err(Refusal::EffectivelyEmpty);
    }
    if effective != segment {
        return Err(Refusal::TrailingDotOrSpace);
    }

    if segment.len() > MAX_SEGMENT_BYTES {
        return Err(Refusal::SegmentTooLong);
    }

    for character in segment.chars() {
        if character == '/' || character == '\\' {
            return Err(Refusal::NotOneComponent);
        }
        if FORBIDDEN_CHARS.contains(&character) {
            return Err(Refusal::ForbiddenCharacter(character));
        }
        if character.is_control() {
            return Err(Refusal::ControlCharacter);
        }
    }

    if is_reserved_device(segment) {
        return Err(Refusal::ReservedDeviceName);
    }
    if is_short_name(segment) {
        return Err(Refusal::ShortName);
    }
    if segment.starts_with(TEMP_PREFIX) {
        return Err(Refusal::ReservedPrefix);
    }

    // Last, and never removed: the segment must be exactly one ordinary name.
    //
    // This is not belt-and-braces. `PathBuf::push` of a rooted or prefixed
    // component *discards the base* — `Path::new("/srv").join("C:/x")` is
    // `C:/x` on Windows, not `/srv/C:/x`. A join is not additive, so anything
    // the platform reads as a root, a prefix, or a drive letter must never
    // reach it. `files.rs:104-112` makes exactly this check and it is inherited
    // verbatim.
    let mut components = Path::new(segment).components();
    match (components.next(), components.next()) {
        (Some(Component::Normal(_)), None) => Ok(()),
        _ => Err(Refusal::NotOneComponent),
    }
}

/// Whether two names **certainly** fold together on a case-insensitive volume.
///
/// True only when the names differ byte-for-byte but fold to the same string,
/// which is the case worth naming in a message: `PUT Report.pdf` beside an
/// existing `report.pdf` is one file on APFS and NTFS and two on ext4. A
/// byte-identical pair is *not* a collision — that is an overwrite, a decision
/// made elsewhere by the caller's intent.
///
/// # This is advisory, and the word is exact
///
/// A `true` here is reliable. A `false` is **not** a promise that the two names
/// are different files, and no version of this function could make it one:
///
/// - The fold is `char::to_lowercase`, so it is a *case* fold and not a
///   *normalisation* fold. An NFC `é` (U+00E9) and an NFD `e`+U+0301 are two
///   names to this function and one name on APFS, which decomposes on the way
///   in. Closing that honestly needs the full Unicode decomposition tables;
///   hand-rolling the Latin-1 corner of them would be right for `café.txt` and
///   wrong for `한.txt`, which is a worse position than this one, because a
///   caller would start trusting the answer.
/// - Even a perfect fold would be a guess about *someone else's* volume. Case
///   sensitivity is a per-filesystem and, on APFS, a per-volume property; a
///   share can sit on a case-sensitive APFS volume, a case-insensitive one, or
///   an SMB mount whose server has its own opinion. A pure function is on the
///   wrong side of that question by construction.
///
/// So the volume is the authority, and the mechanism that *actually* prevents a
/// silent clobber is [`crate::fs::Upload::begin`]: an exclusive create at the
/// **destination** name, which fails with `EEXIST` exactly when the volume — not
/// this function — says the name is taken. This function's job is to turn the
/// common, explainable half of that into a `409` that says *which* existing name
/// the upload collided with, instead of a bare "already exists".
///
/// An earlier version of this comment claimed the remainder was caught by the
/// filesystem layer's `O_EXCL`. It was not: the exclusive create guarded the
/// *temporary* name and the destination was reached by `rename`, which replaces
/// its target silently and unconditionally. That gap is closed in
/// [`crate::fs`], not here.
pub fn collides(existing: &str, proposed: &str) -> bool {
    existing != proposed && folded(existing) == folded(proposed)
}

/// The case-folded form used by [`collides`].
fn folded(name: &str) -> String {
    name.chars().flat_map(char::to_lowercase).collect()
}

/// Percent-encodes one stored name so a URL round-trips back to that same name.
///
/// This is the other half of [`resolve`], and the module documentation states
/// the invariant it keeps: for every name this module accepts,
/// `resolve(root, "/" + encode_segment(name))` yields exactly `[name]` again.
/// A name containing `%`, a space, a `#`, or a `?` is otherwise a link to a
/// different file — or to no file — the moment a listing renders it.
///
/// The unreserved set of RFC 3986 (`A-Z a-z 0-9 - . _ ~`) is passed through and
/// **everything else is encoded**, byte by byte over the UTF-8 encoding. That is
/// more conservative than a URL needs: `!`, `$`, `&`, `'`, `(`, `)`, `+`, `,`,
/// `;`, `=` and `@` are all legal in a path segment unescaped. Encoding them
/// anyway costs three characters each in a link nobody types by hand, and buys
/// a rule with no exceptions to remember — which is the property that survives
/// being copied into an HTML attribute, a `Destination:` header and an XML
/// `href` by three different authors.
///
/// The output is ASCII, so it is safe in every one of those places without a
/// second escaping step for the *transport*. It is **not** HTML- or XML-escaped:
/// a WebDAV `href` element and an HTML attribute still need their own escaping
/// on top, and neither `&` nor `<` can survive this function unencoded anyway
/// (both are outside the unreserved set), which is why the two concerns can be
/// kept apart without a trap.
pub fn encode_segment(name: &str) -> String {
    /// Uppercase hexadecimal, indexed by a nibble, so no digit is ever computed
    /// by arithmetic on a character and no allocation happens per byte.
    const HEX: [u8; 16] = *b"0123456789ABCDEF";

    let mut out = String::with_capacity(name.len());
    for byte in name.as_bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => {
                out.push(*byte as char);
            }
            other => {
                // Both indices are a nibble, so they are 0..=15 and inside the
                // table by construction — the bound is the mask, not a hope.
                out.push('%');
                out.push(HEX[usize::from(other >> 4)] as char);
                out.push(HEX[usize::from(other & 0x0f)] as char);
            }
        }
    }
    out
}

/// Whether a name's stem is one of the Windows reserved device names.
///
/// The rule is on the **stem** — everything before the first dot — because
/// Windows resolves `CON.txt` and `con.txt.gz` to the console device just as it
/// resolves bare `CON`. Opening one on Windows attaches to a device rather than
/// a file; the operation neither fails nor creates anything, so a share
/// containing such a name is a share where uploads silently vanish.
///
/// The set is Microsoft's own, from *Naming Files, Paths, and Namespaces*, and
/// is deliberately the whole of it rather than the memorable part: `CLOCK$` is
/// the surviving DOS device the NT namespace still recognises, and `COM0` and
/// `LPT0` are listed there beside `COM1`–`COM9` even though no machine has ever
/// had a zeroth serial port. A denylist that is *nearly* the vendor's list is
/// the worst of the three options, because it reads as complete.
fn is_reserved_device(segment: &str) -> bool {
    let stem = segment.split('.').next().unwrap_or_default().to_ascii_uppercase();

    if matches!(stem.as_str(), "CON" | "PRN" | "AUX" | "NUL" | "CONIN$" | "CONOUT$" | "CLOCK$") {
        return true;
    }

    // `COM0`–`COM9` and `LPT0`–`LPT9`, plus the superscript spellings Windows 11
    // added (`COM¹`), which are separate code points and therefore separate
    // names to any check that only looks at ASCII.
    let Some(number) = stem.strip_prefix("COM").or_else(|| stem.strip_prefix("LPT")) else {
        return false;
    };
    let mut digits = number.chars();
    let (Some(digit), None) = (digits.next(), digits.next()) else {
        return false;
    };
    matches!(digit, '0'..='9' | '¹' | '²' | '³')
}

/// Whether a name has the shape of an 8.3 short name, such as `PROGRA~1`.
///
/// Windows keeps these aliases for long names on NTFS volumes, and opening
/// `PROGRA~1` opens `Program Files`. That defeats a denylist keyed on the long
/// name and it defeats the case-collision scan, since the alias collides with
/// nothing. The shape is a stem of one to six characters with no dot, a tilde,
/// and then a digit.
fn is_short_name(segment: &str) -> bool {
    let Some((stem, rest)) = segment.split_once('~') else {
        return false;
    };
    if stem.is_empty() || stem.len() > 6 || stem.contains('.') {
        return false;
    }
    rest.chars().next().is_some_and(|c| c.is_ascii_digit())
}

/// Percent-decodes a request path exactly once, refusing everything ambiguous.
///
/// Deliberately a copy of `proxy/src/files.rs:41` rather than a call to it: that
/// function is `pub(crate)` in a crate this one does not depend on (the
/// dependency edge runs `config → storage → http`, and `proxy` is a sibling), and
/// it answers `None` for four different failures where a share needs to tell
/// them apart in the log. The **rules** are identical, which is the part that
/// matters; when `crates/http/src/uri.rs` lands as the shared decoder, both
/// callers should move onto it and this function should be deleted.
fn percent_decode(input: &str) -> Result<String, Refusal> {
    let bytes = input.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut index = 0;

    while index < bytes.len() {
        match bytes[index] {
            b'%' => {
                // `get` rather than a slice: a truncated escape at the end of
                // the input must be an error, never a panicking index. Under
                // `panic = "abort"` a panic here is the whole box.
                let hex = bytes.get(index + 1..index + 3).ok_or(Refusal::MalformedEscape)?;
                // Both digits are checked here rather than handed to
                // `u8::from_str_radix`, which accepts a leading `+`: `%+1`
                // would otherwise decode to `0x01` and two layers would
                // disagree about what the caller wrote.
                if !hex.iter().all(u8::is_ascii_hexdigit) {
                    return Err(Refusal::MalformedEscape);
                }
                let text = std::str::from_utf8(hex).map_err(|_| Refusal::MalformedEscape)?;
                let byte = u8::from_str_radix(text, 16).map_err(|_| Refusal::MalformedEscape)?;
                if byte == 0 {
                    return Err(Refusal::EncodedNul);
                }
                out.push(byte);
                index += 3;
            }
            byte => {
                out.push(byte);
                index += 1;
            }
        }
    }

    String::from_utf8(out).map_err(|_| Refusal::NotUtf8)
}

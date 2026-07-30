//! Finding the faces to draw with on whatever machine this is.
//!
//! The toolkit rasterises fonts itself but does not carry one. A font file is
//! several hundred kilobytes of someone else's licensed work, and every desktop
//! this runs on already has good ones installed — so the console borrows the
//! platform's rather than shipping a copy that would look foreign on all three.
//!
//! Two faces are wanted: a proportional one for the interface, and a fixed-width
//! one for anything the machine produced — addresses, paths, log lines. The
//! second matters more than it sounds. A service's output aligns into columns
//! only in a fixed-width face, and a proportional one silently destroys the
//! shape of everything a program printed.
//!
//! Each list is tried in order and the first face that parses wins, so a machine
//! missing the preferred font falls back rather than failing.

use crate::{Font, FontId, Fonts};

use crate::shell::Error;

/// The loaded faces and the handles that select them.
pub struct LoadedFonts {
    /// The faces themselves, with their glyph cache.
    pub fonts: Fonts,
    /// The proportional face.
    pub ui_font: FontId,
    /// The fixed-width face.
    pub mono_font: FontId,
}

/// Candidate proportional faces, best first.
#[cfg(target_os = "macos")]
const UI_CANDIDATES: &[&str] = &[
    "/System/Library/Fonts/SFNS.ttf",
    "/System/Library/Fonts/Helvetica.ttc",
    "/System/Library/Fonts/Geneva.ttf",
    "/System/Library/Fonts/Supplemental/Arial.ttf",
];

/// Candidate fixed-width faces, best first.
#[cfg(target_os = "macos")]
const MONO_CANDIDATES: &[&str] = &[
    "/System/Library/Fonts/SFNSMono.ttf",
    "/System/Library/Fonts/Menlo.ttc",
    "/System/Library/Fonts/Monaco.ttf",
    "/System/Library/Fonts/Courier.ttc",
];

#[cfg(target_os = "windows")]
const UI_CANDIDATES: &[&str] = &[
    r"C:\Windows\Fonts\segoeui.ttf",
    r"C:\Windows\Fonts\tahoma.ttf",
    r"C:\Windows\Fonts\arial.ttf",
    r"C:\Windows\Fonts\verdana.ttf",
];

#[cfg(target_os = "windows")]
const MONO_CANDIDATES: &[&str] = &[
    r"C:\Windows\Fonts\consola.ttf",
    r"C:\Windows\Fonts\lucon.ttf",
    r"C:\Windows\Fonts\cour.ttf",
];

/// Where fonts are installed on the systems this is likely to run on.
///
/// Unlike macOS and Windows, there is no fixed path: the file is found by name
/// under whichever of these directories exists.
#[cfg(not(any(target_os = "macos", target_os = "windows")))]
const FONT_DIRECTORIES: &[&str] = &[
    "/usr/share/fonts",
    "/usr/local/share/fonts",
    "/usr/share/fonts/truetype",
];

#[cfg(not(any(target_os = "macos", target_os = "windows")))]
const UI_CANDIDATES: &[&str] = &[
    "DejaVuSans.ttf",
    "LiberationSans-Regular.ttf",
    "NotoSans-Regular.ttf",
    "FreeSans.ttf",
];

#[cfg(not(any(target_os = "macos", target_os = "windows")))]
const MONO_CANDIDATES: &[&str] = &[
    "DejaVuSansMono.ttf",
    "LiberationMono-Regular.ttf",
    "NotoSansMono-Regular.ttf",
    "FreeMono.ttf",
];

/// How deep the search for a font file will descend.
///
/// Font directories nest a few levels — vendor, then family. A bound stops a
/// symbolic link cycle from turning the search into a hang at start-up.
#[cfg(not(any(target_os = "macos", target_os = "windows")))]
const MAX_SEARCH_DEPTH: usize = 4;

impl LoadedFonts {
    /// Loads two specific font files.
    ///
    /// The escape hatch from the search: a deployment that must render
    /// identically everywhere ships its own files and names them here.
    pub fn from_files(ui: &str, mono: &str) -> Result<Self, Error> {
        let mut fonts = Fonts::new();
        let ui_font = fonts.add(Font::parse(std::fs::read(ui)?)?);
        let mono_font = fonts.add(Font::parse(std::fs::read(mono)?)?);
        Ok(Self { fonts, ui_font, mono_font })
    }
}

/// Finds and loads a proportional and a fixed-width face.
///
/// The fixed-width face falls back to the proportional one rather than failing:
/// a console that renders log output in the wrong face is worth having, and one
/// that refuses to start is not.
pub fn load_system_fonts() -> Result<LoadedFonts, Error> {
    let mut fonts = Fonts::new();

    let ui_font = match first_usable(UI_CANDIDATES) {
        Some(font) => fonts.add(font),
        None => {
            return Err(Error::NoFont {
                searched: UI_CANDIDATES.iter().map(|name| (*name).to_owned()).collect(),
            });
        }
    };
    let mono_font = first_usable(MONO_CANDIDATES).map_or(ui_font, |font| fonts.add(font));

    Ok(LoadedFonts { fonts, ui_font, mono_font })
}

/// The first candidate that exists and parses.
///
/// A candidate that is present but unreadable is skipped rather than fatal: the
/// point of a list is that the next entry is tried.
fn first_usable(candidates: &[&str]) -> Option<Font> {
    candidates.iter().find_map(|candidate| {
        let path = locate(candidate)?;
        let bytes = std::fs::read(path).ok()?;
        Font::parse(bytes).ok()
    })
}

/// Turns a candidate into a path that exists, or `None`.
#[cfg(any(target_os = "macos", target_os = "windows"))]
fn locate(candidate: &str) -> Option<std::path::PathBuf> {
    let path = std::path::PathBuf::from(candidate);
    path.is_file().then_some(path)
}

/// Searches the font directories for a file with this name.
#[cfg(not(any(target_os = "macos", target_os = "windows")))]
fn locate(candidate: &str) -> Option<std::path::PathBuf> {
    FONT_DIRECTORIES
        .iter()
        .find_map(|directory| find_named(std::path::Path::new(directory), candidate, 0))
}

/// Looks for `name` under `directory`, no deeper than [`MAX_SEARCH_DEPTH`].
#[cfg(not(any(target_os = "macos", target_os = "windows")))]
fn find_named(
    directory: &std::path::Path,
    name: &str,
    depth: usize,
) -> Option<std::path::PathBuf> {
    if depth > MAX_SEARCH_DEPTH {
        return None;
    }
    let entries = std::fs::read_dir(directory).ok()?;
    let mut subdirectories = Vec::new();

    for entry in entries.flatten() {
        let path = entry.path();
        match entry.file_type() {
            // Breadth first: the common case is the file sitting one level down,
            // and descending the first subdirectory to its bottom first would
            // walk a whole vendor tree before looking next door.
            Ok(kind) if kind.is_dir() => subdirectories.push(path),
            Ok(_) if path.file_name().is_some_and(|found| found == name) => return Some(path),
            _ => {}
        }
    }
    subdirectories
        .into_iter()
        .find_map(|subdirectory| find_named(&subdirectory, name, depth + 1))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_candidate_list_offers_a_fallback() {
        assert!(UI_CANDIDATES.len() > 1, "one candidate is not a fallback list");
        assert!(MONO_CANDIDATES.len() > 1);
    }

    #[test]
    fn a_missing_file_is_simply_not_located() {
        assert!(locate("/no/such/font/anywhere.ttf").is_none());
    }

    #[test]
    fn nothing_usable_in_a_list_answers_nothing() {
        assert!(first_usable(&["/no/such/font/anywhere.ttf"]).is_none());
    }

    /// Every character the console draws as a *mark* rather than as data.
    ///
    /// Not a decorative list. A character that no loaded face has is drawn as
    /// that face's own empty box, and it fails silently: the console's dismiss
    /// button spent a release as a filled rectangle because U+2715
    /// MULTIPLICATION X is in neither face macOS ships, and nothing said so.
    /// Data is a different matter — a service may print anything, and a missing
    /// glyph there is the font's answer and not a defect — so only the
    /// characters the interface itself chooses are listed.
    const MARKS: &[char] = &[
        's', 'S', '0', // ordinary text and figures
        '·', // separates the halves of a summary line
        '—', // sets off a reason from its advice
        '…', // where a run of text was cut short
        '×', // dismisses a notice
        '−', // removes an argument from the install form
        '+', // adds one, and adds a service
        '/', // the running-of-total figure
    ];

    /// The real check: this machine can actually produce a console.
    ///
    /// Skipped rather than failed where no font is installed, because that is a
    /// property of the machine and not of the code — but it is reported, so a
    /// silent skip cannot be mistaken for a pass.
    #[test]
    fn this_machine_has_the_faces_the_console_needs() {
        match load_system_fonts() {
            Ok(loaded) => {
                assert_eq!(loaded.fonts.len(), 2, "the two faces should be distinct files");
                // Both faces, not just the proportional one. The fixed-width
                // face draws the section labels and the log's own gutter, and a
                // mark missing from it is just as blank.
                for (name, id) in [("ui", loaded.ui_font), ("mono", loaded.mono_font)] {
                    let font = loaded.fonts.font(id).expect("the face just loaded");
                    for &character in MARKS {
                        assert!(
                            font.has_glyph(character),
                            "the {name} face has no {character:?} (U+{:04X}), which the \
                             console would draw as an empty box",
                            character as u32
                        );
                    }
                }
            }
            Err(error) => println!("skipped: no font on this machine ({error})"),
        }
    }

    /// Tracking widens a run, and by the same amount however it is measured.
    ///
    /// It lives here rather than in `rui` because that crate ships no
    /// face: with none loaded every glyph resolves to nothing, so a width test
    /// there would pass on an empty advance and assert nothing at all. This is
    /// the first place a real face exists. Skipped and reported where no font is
    /// installed, exactly as the check above is.
    #[test]
    fn tracking_opens_a_run_up_by_one_step_for_every_letter() {
        let Ok(loaded) = load_system_fonts() else {
            println!("skipped: no font on this machine");
            return;
        };
        let solid = crate::TextStyle::new(
            loaded.ui_font,
            10.0,
            crate::Color::WHITE,
        );
        let tracked = solid.tracked(2.0);
        let word = "SERVICES";

        let widened = loaded.fonts.measure(&tracked, word) - loaded.fonts.measure(&solid, word);
        let expected = 2.0 * word.chars().count() as f32;
        assert!(
            (widened - expected).abs() < 0.5,
            "{word:?} should open up by {expected}, not {widened}"
        );

        // The property that actually protects the layout: `fit` has to agree
        // with `measure`, or a tracked label is sized to one width and drawn at
        // another — which is how labels overrun the boxes they were fitted to.
        let width = loaded.fonts.measure(&tracked, word);
        assert_eq!(loaded.fonts.fit(&tracked, word, width), word.len());
        assert!(loaded.fonts.fit(&tracked, word, width - 1.0) < word.len());
    }
}

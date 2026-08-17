//! Content types for static files.
//!
//! A small explicit table rather than a database. Two entries matter more than
//! the rest and are the reason this is not left to a guess: `.m3u8` and `.ts`.
//! An HLS player fetches a playlist and then its segments, and it decides what
//! to do with them from the `Content-Type`. Serve a playlist as
//! `text/plain` — or worse, `application/octet-stream` — and the player either
//! refuses it or downloads it as a file instead of playing it.
//!
//! Anything unrecognised becomes `application/octet-stream`, which browsers
//! treat as an opaque download. Combined with the `X-Content-Type-Options:
//! nosniff` header the server always sends, that means an unknown file can never
//! be sniffed into being executed as script.

/// The content type for a file name, chosen by extension.
///
/// Matching is case-insensitive because Windows filesystems preserve case
/// without honouring it, and a file written as `Video.MP4` must still play.
pub fn for_path(path: &str) -> &'static str {
    let extension = path.rsplit('.').next().unwrap_or_default().to_ascii_lowercase();

    match extension.as_str() {
        // Adaptive video. The whole ladder is unplayable if these are wrong.
        "m3u8" => "application/vnd.apple.mpegurl",
        "ts" => "video/mp2t",
        "mp4" | "m4v" => "video/mp4",
        "m4s" => "video/iso.segment",
        "webm" => "video/webm",
        "mov" => "video/quicktime",

        // Documents and code.
        "html" | "htm" => "text/html; charset=utf-8",
        "css" => "text/css; charset=utf-8",
        "js" | "mjs" => "text/javascript; charset=utf-8",
        "json" => "application/json; charset=utf-8",
        "map" => "application/json; charset=utf-8",
        "xml" => "application/xml; charset=utf-8",
        "txt" => "text/plain; charset=utf-8",
        "md" => "text/markdown; charset=utf-8",
        "wasm" => "application/wasm",

        // Images.
        "svg" => "image/svg+xml",
        "png" => "image/png",
        "jpg" | "jpeg" => "image/jpeg",
        "webp" => "image/webp",
        "avif" => "image/avif",
        "gif" => "image/gif",
        "ico" => "image/x-icon",

        // Fonts.
        "woff2" => "font/woff2",
        "woff" => "font/woff",
        "ttf" => "font/ttf",
        "otf" => "font/otf",

        // Audio.
        "mp3" => "audio/mpeg",
        "aac" => "audio/aac",
        "wav" => "audio/wav",
        "ogg" => "audio/ogg",

        // Archives and everything else.
        "pdf" => "application/pdf",
        "zip" => "application/zip",
        "gz" => "application/gzip",
        _ => "application/octet-stream",
    }
}

/// Whether a content type is worth compressing.
///
/// Video, images, and archives are already compressed; running them through
/// deflate burns CPU to make the payload marginally larger. On a video-heavy
/// site that is most of the bytes served, so the default must be "no".
pub fn is_compressible(content_type: &str) -> bool {
    let base = content_type.split(';').next().unwrap_or_default().trim();
    base.starts_with("text/")
        || matches!(
            base,
            "application/json"
                | "application/xml"
                | "application/wasm"
                | "image/svg+xml"
                | "application/vnd.apple.mpegurl"
        )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hls_playlists_and_segments_get_playable_types() {
        // Get these wrong and the player downloads the ladder instead of
        // playing it.
        assert_eq!(for_path("yt-abc-master.m3u8"), "application/vnd.apple.mpegurl");
        assert_eq!(for_path("yt-abc-720p-00001.ts"), "video/mp2t");
        assert_eq!(for_path("clip.mp4"), "video/mp4");
    }

    #[test]
    fn extensions_are_matched_case_insensitively() {
        assert_eq!(for_path("Video.MP4"), "video/mp4");
        assert_eq!(for_path("INDEX.HTML"), "text/html; charset=utf-8");
    }

    #[test]
    fn unknown_extensions_become_opaque_downloads() {
        // With nosniff, octet-stream means a browser can never be talked into
        // executing an unrecognised file as script.
        assert_eq!(for_path("secrets.bin"), "application/octet-stream");
        assert_eq!(for_path("noextension"), "application/octet-stream");
        assert_eq!(for_path(""), "application/octet-stream");
    }

    #[test]
    fn only_the_final_extension_counts() {
        assert_eq!(for_path("archive.tar.gz"), "application/gzip");
        assert_eq!(for_path("app.min.js"), "text/javascript; charset=utf-8");
    }

    #[test]
    fn already_compressed_types_are_not_compressed_again() {
        assert!(!is_compressible(for_path("clip.mp4")));
        assert!(!is_compressible(for_path("segment.ts")));
        assert!(!is_compressible(for_path("photo.jpg")));
        assert!(!is_compressible(for_path("bundle.zip")));
    }

    #[test]
    fn text_like_types_are_compressed() {
        assert!(is_compressible(for_path("index.html")));
        assert!(is_compressible(for_path("app.js")));
        assert!(is_compressible(for_path("data.json")));
        assert!(is_compressible(for_path("logo.svg")));
        // A playlist is text and compresses well, unlike the segments it lists.
        assert!(is_compressible(for_path("master.m3u8")));
    }
}

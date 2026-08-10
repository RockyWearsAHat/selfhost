//! Writing out what was drawn, as a file something else can read.
//!
//! The toolkit's central claim is that it needs no display: layout, text, and
//! every widget are decided here, so a frame can be produced and asserted on
//! with nothing attached. That claim is only useful if the frame can also be
//! *looked* at — by a person checking an appearance, or by a packaging step
//! turning a drawing into an application icon.
//!
//! # Why PNG, and why there is no compressor here
//!
//! PNG because it is the one lossless format with an alpha channel that every
//! tool on every platform reads, including the ones that build a macOS icon.
//!
//! It carries its pixels in a zlib stream, which sounds like it needs a
//! compressor — and does not. Deflate defines a *stored* block: a length, its
//! complement, and the bytes themselves, uncompressed. A stream of those is a
//! valid deflate stream, so a valid zlib stream, so a valid PNG. What is
//! written here is therefore larger than a compressed PNG and is byte-for-byte
//! correct, from about sixty lines that implement no compression at all.
//!
//! The two checksums are the only real arithmetic: CRC-32 over each chunk,
//! which PNG requires, and Adler-32 over the pixels, which zlib requires.

use crate::canvas::Canvas;

/// The bytes of a PNG holding `width` by `height` pixels of 8-bit RGBA.
///
/// `rgba` is row-major, four bytes per pixel, red first and alpha last — the
/// order PNG itself stores. Answers `None` if `rgba` is not exactly
/// `width * height * 4` bytes long, which is the one way a caller can get this
/// wrong and the one thing that cannot be checked by looking at the result.
pub fn png(width: u32, height: u32, rgba: &[u8]) -> Option<Vec<u8>> {
    let expected = (width as usize).checked_mul(height as usize)?.checked_mul(4)?;
    if rgba.len() != expected || width == 0 || height == 0 {
        return None;
    }

    // Each scanline is prefixed with its filter type. Zero means "no filter",
    // which costs bytes and saves the decoder — and this writer — from having
    // to agree about a prediction.
    let mut raw = Vec::with_capacity(expected + height as usize);
    for row in rgba.chunks_exact(width as usize * 4) {
        raw.push(0);
        raw.extend_from_slice(row);
    }

    let mut out = Vec::new();
    out.extend_from_slice(&PNG_SIGNATURE);

    let mut header = Vec::with_capacity(13);
    header.extend_from_slice(&width.to_be_bytes());
    header.extend_from_slice(&height.to_be_bytes());
    header.push(8); // Bits per channel.
    header.push(6); // Colour type 6: truecolour with alpha.
    header.push(0); // The only compression method PNG defines.
    header.push(0); // The only filter method PNG defines.
    header.push(0); // Not interlaced.
    write_chunk(&mut out, b"IHDR", &header);
    write_chunk(&mut out, b"IDAT", &zlib(&raw));
    write_chunk(&mut out, b"IEND", &[]);
    Some(out)
}

/// A canvas's pixels as RGBA, every one of them opaque.
///
/// The canvas has no alpha channel — alpha is a property of the paint there,
/// not of the surface — so anything wanting transparency supplies it itself,
/// by writing over the fourth byte of each pixel this answers.
pub fn rgba(canvas: &Canvas) -> Vec<u8> {
    let mut out = Vec::with_capacity(canvas.pixels().len() * 4);
    for &pixel in canvas.pixels() {
        out.push((pixel >> 16) as u8);
        out.push((pixel >> 8) as u8);
        out.push(pixel as u8);
        out.push(0xff);
    }
    out
}

/// The eight bytes every PNG begins with.
const PNG_SIGNATURE: [u8; 8] = [0x89, b'P', b'N', b'G', 0x0d, 0x0a, 0x1a, 0x0a];

/// The largest a single deflate stored block may be.
const STORED_BLOCK_MAX: usize = u16::MAX as usize;

/// Appends one PNG chunk: its length, its type, its data, and its checksum.
fn write_chunk(out: &mut Vec<u8>, kind: &[u8; 4], data: &[u8]) {
    out.extend_from_slice(&(data.len() as u32).to_be_bytes());
    out.extend_from_slice(kind);
    out.extend_from_slice(data);
    let mut checksummed = Vec::with_capacity(4 + data.len());
    checksummed.extend_from_slice(kind);
    checksummed.extend_from_slice(data);
    out.extend_from_slice(&crc32(&checksummed).to_be_bytes());
}

/// `data` as a zlib stream of stored — that is, uncompressed — deflate blocks.
fn zlib(data: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(data.len() + data.len() / STORED_BLOCK_MAX * 5 + 16);
    // Deflate, 32K window, no preset dictionary, fastest level. The two bytes
    // are constrained to be a multiple of 31 when read as one big-endian
    // number, which these are.
    out.push(0x78);
    out.push(0x01);

    let mut blocks = data.chunks(STORED_BLOCK_MAX).peekable();
    // An empty input still needs one block, or the stream ends without ever
    // saying it has.
    if data.is_empty() {
        out.extend_from_slice(&[1, 0, 0, 0xff, 0xff]);
    }
    while let Some(block) = blocks.next() {
        out.push(u8::from(blocks.peek().is_none()));
        out.extend_from_slice(&(block.len() as u16).to_le_bytes());
        out.extend_from_slice(&(!(block.len() as u16)).to_le_bytes());
        out.extend_from_slice(block);
    }

    out.extend_from_slice(&adler32(data).to_be_bytes());
    out
}

/// The CRC-32 PNG checksums each chunk with.
fn crc32(data: &[u8]) -> u32 {
    let mut crc = 0xffff_ffffu32;
    for &byte in data {
        crc ^= byte as u32;
        for _ in 0..8 {
            // The reversed form of the polynomial, which is what PNG specifies.
            crc = if crc & 1 != 0 { (crc >> 1) ^ 0xedb8_8320 } else { crc >> 1 };
        }
    }
    !crc
}

/// The Adler-32 checksum a zlib stream ends with.
fn adler32(data: &[u8]) -> u32 {
    /// The largest prime below 65536, which is what the sums are taken modulo.
    const MODULUS: u32 = 65521;
    let mut low = 1u32;
    let mut high = 0u32;
    for &byte in data {
        low = (low + byte as u32) % MODULUS;
        high = (high + low) % MODULUS;
    }
    (high << 16) | low
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_checksums_match_the_values_their_specifications_publish() {
        // Both of these are the worked example in the relevant specification,
        // which is the only way to tell a correct checksum from a consistent
        // one — a wrong polynomial is self-consistent and rejected by every
        // reader.
        assert_eq!(crc32(b"123456789"), 0xcbf4_3926, "the CRC-32 check value");
        assert_eq!(adler32(b"Wikipedia"), 0x11e6_0398, "the Adler-32 worked example");
        assert_eq!(adler32(b""), 1, "the empty Adler-32 is the initial low word");
    }

    #[test]
    fn a_png_declares_the_size_and_format_it_was_asked_for() {
        let image = png(2, 1, &[0xff, 0x00, 0x00, 0xff, 0x00, 0xff, 0x00, 0x80])
            .expect("two pixels of RGBA");
        assert_eq!(&image[..8], &PNG_SIGNATURE, "every PNG starts the same way");
        assert_eq!(&image[12..16], b"IHDR");
        assert_eq!(&image[16..20], &2u32.to_be_bytes(), "the width it was given");
        assert_eq!(&image[20..24], &1u32.to_be_bytes(), "the height it was given");
        assert_eq!(image[24], 8, "eight bits a channel");
        assert_eq!(image[25], 6, "colour type 6 is the one with alpha");
        assert!(image.ends_with(b"IEND\xae\x42\x60\x82"), "and ends the same way");
    }

    #[test]
    fn pixels_that_do_not_fill_the_stated_size_are_refused() {
        // The one mistake a caller can make that the bytes cannot reveal: a
        // short buffer would otherwise produce a file that decodes to garbage.
        assert!(png(2, 2, &[0; 8]).is_none(), "half the pixels asked for");
        assert!(png(1, 1, &[0; 5]).is_none(), "not a whole number of pixels");
        assert!(png(0, 1, &[]).is_none(), "an image with no area");
    }

    #[test]
    fn the_stored_blocks_cover_every_byte_and_only_the_last_is_final() {
        // A scanline of a thousand-pixel image is four kilobytes, so a real
        // icon runs to many blocks. Getting the final-block flag wrong makes a
        // file that decodes to a fraction of the image, which is exactly the
        // kind of thing that looks fine until the image is big enough.
        let data = vec![7u8; STORED_BLOCK_MAX * 2 + 13];
        let stream = zlib(&data);

        let mut at = 2;
        let mut recovered = Vec::new();
        let mut finals = 0;
        while at < stream.len() - 4 {
            let is_final = stream[at] & 1 != 0;
            finals += usize::from(is_final);
            let length = u16::from_le_bytes([stream[at + 1], stream[at + 2]]) as usize;
            let complement = u16::from_le_bytes([stream[at + 3], stream[at + 4]]);
            assert_eq!(complement, !(length as u16), "a block's length must be repeated inverted");
            recovered.extend_from_slice(&stream[at + 5..at + 5 + length]);
            at += 5 + length;
            assert!(!is_final || at == stream.len() - 4, "nothing may follow the final block");
        }
        assert_eq!(recovered, data, "the blocks must reproduce the input exactly");
        assert_eq!(finals, 1, "exactly one block is the last one");
    }

    #[test]
    fn a_canvas_comes_out_opaque_with_its_channels_in_pngs_order() {
        let mut canvas = Canvas::new(1, 1, 1.0);
        canvas.fill_rect(canvas.bounds(), crate::Color::rgb(0x12, 0x34, 0x56));
        assert_eq!(rgba(&canvas), vec![0x12, 0x34, 0x56, 0xff]);
    }
}

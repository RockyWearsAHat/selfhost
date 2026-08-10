//! The tile codec: the whole bandwidth story, in one pure module.
//!
//! # Why tiles, and why this is honest about being worse
//!
//! There is no JPEG here and no H.264, and neither is importable under this
//! workspace's dependency policy — a video codec is not a protocol we could
//! write ourselves in any reasonable time, and importing one would mean
//! importing a large body of C into the process that also serves 80/443. Raw
//! BGRA at 1080p60 is about 500 MB/s, so streaming whole frames is not an option
//! either.
//!
//! What is left is the observation that a desktop is almost entirely still. So
//! the frame is cut into a grid of 64×64 tiles, each tile is compared with the
//! same tile of the previous frame, and only the ones that changed are sent —
//! each in whichever of four encodings is smallest. A still desktop costs
//! effectively nothing. A dragged window costs its own area. A typed line costs
//! the two tiles the caret crossed.
//!
//! And it is worse than any commercial remote desktop at video, at scrolling
//! text and at photographs, because those change every tile every frame and this
//! encoder has nothing clever to say about them. That is a stated cost of the
//! dependency policy rather than a bug to be reported: the way to fix it is to
//! change the policy, and the policy is worth more than the frame rate.
//!
//! # Why it is pure, and why the padded-row unpack lives here
//!
//! Every function in this file takes bytes and returns bytes. That matters most
//! for [`unpack`], which handles the fact that a captured surface's rows are
//! almost never `width * 4` bytes apart. On this Mac, a 3024-pixel-wide
//! `CGImage` has a 12160-byte row stride against a 12096-byte row, and a
//! 1512-pixel `IOSurface` has 6144 against 6048. Assuming `width * 4` does not
//! produce a black screen or a crash — it produces a *sheared* image, which
//! still looks like a picture of the desktop, passes a smoke test, and is
//! discovered weeks later by somebody who thinks their graphics driver is
//! broken. Exact figures from real surfaces are in this module's tests, so the
//! arithmetic is checked against measurements rather than against intuition.
//!
//! # The decode path is attacker-influenced
//!
//! [`decode_tile`] runs on bytes from the far end. It is a total parser: a run
//! length of zero is refused rather than looping, the accumulated pixel count is
//! `checked_add`ed, the payload must describe exactly the tile it claims and not
//! one pixel more or fewer, and the tile's own size is bounded before anything
//! is allocated. The fuzz-shaped test at the bottom of this file asserts that no
//! byte string reaches a panic.

use std::fmt;

/// The tile edges an operator may choose, matching `[desktop].tile`.
///
/// Four sizes rather than any integer, because the size is a trade the operator
/// makes between per-tile overhead and how much unchanged area rides along with
/// each change, and four points cover that trade. A closed set also means the
/// grid arithmetic has a known range: at the smallest edge and the largest
/// display the column count still fits a `u16`.
pub const LEGAL_TILE_EDGES: [u16; 4] = [16, 32, 64, 128];

/// The largest display edge this codec will describe, in pixels.
///
/// Well past 8K. Its purpose is to keep `width * height * 4` far inside a
/// `usize` on every platform this builds for, so that a peer's claimed geometry
/// is never the input to an overflow.
pub const MAX_EDGE: u32 = 32_768;

/// The most pixels one tile can contain — the largest legal edge, squared.
///
/// Every allocation in [`decode_tile`] is bounded by this before a byte is read.
pub const MAX_TILE_PIXELS: usize = 128 * 128;

/// Bytes per pixel. BGRA, which is the byte order both platforms hand us.
pub const BYTES_PER_PIXEL: usize = 4;

/// Why a tile operation failed.
///
/// Split finely because these errors are read in two very different situations:
/// a `SizeMismatch` between frames is a resolution change and the caller's
/// response is to send a keyframe, while a `RunOverruns` is a peer sending
/// nonsense and the caller's response is to close the channel.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TileError {
    /// A tile edge that is not one of [`LEGAL_TILE_EDGES`].
    BadTileSize {
        /// The edge that was offered.
        edge: u16,
    },
    /// A surface dimension of zero, or beyond [`MAX_EDGE`].
    BadDimension {
        /// The dimension that was offered.
        value: u32,
    },
    /// A pixel buffer whose length does not match the geometry it claims.
    SizeMismatch {
        /// How many bytes the geometry implies.
        expected: usize,
        /// How many were supplied.
        actual: usize,
    },
    /// A source row stride narrower than the row it must contain.
    StrideTooSmall {
        /// The stride that was offered.
        stride: usize,
        /// The stride the width requires.
        minimum: usize,
    },
    /// A buffer ended before the data it was supposed to contain.
    Truncated {
        /// How many bytes were needed.
        needed: usize,
        /// How many were available.
        available: usize,
    },
    /// A run-length of zero, which encodes nothing and would let a payload
    /// describe a tile without ever finishing it.
    ZeroRun,
    /// An RLE payload whose runs describe more pixels than the tile holds.
    RunOverruns {
        /// The tile's pixel count.
        tile: usize,
    },
    /// An encoded payload the size of which cannot describe the tile.
    PayloadMismatch {
        /// The encoding that was claimed.
        encoding: Encoding,
        /// How many bytes were supplied.
        actual: usize,
    },
    /// A tile larger than [`MAX_TILE_PIXELS`], or a pixel count of zero.
    BadTilePixels {
        /// The count that was offered.
        pixels: usize,
    },
    /// A rectangle that does not lie wholly inside the surface it addresses.
    OutsideSurface,
    /// A tile coordinate outside the grid.
    OutOfGrid {
        /// The column.
        col: u16,
        /// The row.
        row: u16,
    },
    /// An arithmetic result that would not fit. Reported rather than wrapped,
    /// because under `panic = "abort"` an overflow is not a wrong number, it is
    /// the daemon exiting.
    Overflow {
        /// What was being computed.
        what: &'static str,
    },
}

impl fmt::Display for TileError {
    fn fmt(&self, out: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::BadTileSize { edge } => {
                write!(out, "tile edge {edge} is not one of {LEGAL_TILE_EDGES:?}")
            }
            Self::BadDimension { value } => {
                write!(out, "dimension {value} is zero or beyond {MAX_EDGE}")
            }
            Self::SizeMismatch { expected, actual } => {
                write!(out, "pixel buffer is {actual} bytes, geometry implies {expected}")
            }
            Self::StrideTooSmall { stride, minimum } => {
                write!(out, "row stride {stride} is narrower than the {minimum}-byte row")
            }
            Self::Truncated { needed, available } => {
                write!(out, "needed {needed} bytes, {available} available")
            }
            Self::ZeroRun => out.write_str("a run length of zero encodes nothing"),
            Self::RunOverruns { tile } => {
                write!(out, "the runs describe more than the tile's {tile} pixels")
            }
            Self::PayloadMismatch { encoding, actual } => {
                write!(out, "a {encoding:?} payload cannot be {actual} bytes")
            }
            Self::BadTilePixels { pixels } => {
                write!(out, "a tile of {pixels} pixels is zero or beyond {MAX_TILE_PIXELS}")
            }
            Self::OutsideSurface => out.write_str("the rectangle is not wholly inside the surface"),
            Self::OutOfGrid { col, row } => write!(out, "tile ({col}, {row}) is outside the grid"),
            Self::Overflow { what } => write!(out, "{what} overflowed"),
        }
    }
}

impl std::error::Error for TileError {}

/// How a tile's pixels are encoded.
///
/// Four encodings, chosen per tile by [`encode_tile`] as whichever is smallest.
/// A closed set with stable codes, because it travels on the wire.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Encoding {
    /// The tile's pixels verbatim, in BGRA order.
    Raw,
    /// Runs of `[count][b][g][r][a]`, `count` in 1..=255. Cheap to produce and
    /// very effective on the flat colour that most of a desktop is.
    Rle,
    /// The tile is identical to the previous frame's. Zero payload.
    ///
    /// Never produced by [`diff`], which simply omits an unchanged tile. It
    /// exists for a keyframe, where the client must be told about every tile of
    /// the grid, including the ones that happen not to have changed.
    Unchanged,
    /// The whole tile is one colour, carried as four bytes.
    Solid,
}

impl Encoding {
    /// The stable wire code.
    pub const fn code(self) -> u8 {
        match self {
            Self::Raw => 0x00,
            Self::Rle => 0x01,
            Self::Unchanged => 0x02,
            Self::Solid => 0x03,
        }
    }

    /// Reads an encoding from its wire code.
    pub const fn from_code(code: u8) -> Option<Self> {
        match code {
            0x00 => Some(Self::Raw),
            0x01 => Some(Self::Rle),
            0x02 => Some(Self::Unchanged),
            0x03 => Some(Self::Solid),
            _ => None,
        }
    }
}

/// A validated tile edge.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TileSize(u16);

impl TileSize {
    /// 64 pixels, the documented default.
    pub const DEFAULT: Self = Self(64);

    /// Admits an edge, or refuses it by name.
    pub const fn new(edge: u16) -> Result<Self, TileError> {
        // A `match` rather than an iterator so this can be `const`, which lets a
        // caller write `TileSize::new(64)` in a constant position.
        match edge {
            16 | 32 | 64 | 128 => Ok(Self(edge)),
            other => Err(TileError::BadTileSize { edge: other }),
        }
    }

    /// The edge in pixels.
    pub const fn edge(self) -> u16 {
        self.0
    }

    /// Pixels in a full tile.
    pub const fn pixels(self) -> usize {
        (self.0 as usize) * (self.0 as usize)
    }

    /// Bytes in a full tile.
    pub const fn bytes(self) -> usize {
        self.pixels() * BYTES_PER_PIXEL
    }
}

impl Default for TileSize {
    fn default() -> Self {
        Self::DEFAULT
    }
}

/// A rectangle in pixels.
///
/// The origin is signed because a virtual desktop's is, and because a dirty rect
/// arriving from a capture API is a value we did not compute. Every consumer
/// widens to `i64` before adding, so a rectangle at `i32::MAX` clips rather than
/// wraps.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Rect {
    /// Left edge.
    pub x: i32,
    /// Top edge.
    pub y: i32,
    /// Width in pixels.
    pub width: u32,
    /// Height in pixels.
    pub height: u32,
}

impl Rect {
    /// A rectangle from its corner and size.
    pub const fn new(x: i32, y: i32, width: u32, height: u32) -> Self {
        Self { x, y, width, height }
    }

    /// The right edge, exclusive, widened so it cannot overflow.
    pub const fn right(self) -> i64 {
        self.x as i64 + self.width as i64
    }

    /// The bottom edge, exclusive, widened so it cannot overflow.
    pub const fn bottom(self) -> i64 {
        self.y as i64 + self.height as i64
    }

    /// Whether the rectangle covers no pixels.
    pub const fn is_empty(self) -> bool {
        self.width == 0 || self.height == 0
    }
}

/// A region the capture layer says moved rather than changed.
///
/// DXGI reports these separately from dirty rectangles, and the documented
/// reconstruction order is **moves first, then dirty**. [`Damage::tiles`] folds
/// them in that order so a client that can blit its own surface and a client
/// that simply redraws the destination arrive at the same picture.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MoveRect {
    /// Where the pixels came from.
    pub from: Rect,
    /// Where they went. Same extent as `from`; a mismatch is treated as damage
    /// to the destination, which is always correct if sometimes wasteful.
    pub to: Rect,
}

/// What changed in a frame, as the capture layer described it.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Damage {
    /// Regions that moved.
    pub moves: Vec<MoveRect>,
    /// Regions that changed.
    pub dirty: Vec<Rect>,
}

/// A tile's position in the grid.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct TileCoord {
    /// Column, counting from zero at the left.
    pub col: u16,
    /// Row, counting from zero at the top.
    pub row: u16,
}

/// The tile grid over one display.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Grid {
    size: TileSize,
    width: u32,
    height: u32,
}

impl Grid {
    /// Builds the grid for a display of this size.
    pub fn new(size: TileSize, width: u32, height: u32) -> Result<Self, TileError> {
        check_dimension(width)?;
        check_dimension(height)?;
        Ok(Self { size, width, height })
    }

    /// The tile edge.
    pub const fn size(self) -> TileSize {
        self.size
    }

    /// The display width.
    pub const fn width(self) -> u32 {
        self.width
    }

    /// The display height.
    pub const fn height(self) -> u32 {
        self.height
    }

    /// Columns, including a partial one at the right edge.
    pub fn cols(self) -> u16 {
        // `MAX_EDGE / 16` is 2048, so the count always fits a `u16`; the cast is
        // safe by construction because `width` was validated.
        self.width.div_ceil(self.size.0 as u32) as u16
    }

    /// Rows, including a partial one at the bottom edge.
    pub fn rows(self) -> u16 {
        self.height.div_ceil(self.size.0 as u32) as u16
    }

    /// How many tiles the grid holds.
    pub fn len(self) -> usize {
        self.cols() as usize * self.rows() as usize
    }

    /// Whether the grid holds no tiles. Impossible for a validated grid, and
    /// present because `len` without `is_empty` is a lint and, more usefully,
    /// because a caller reading `grid.is_empty()` should get `false` rather than
    /// a compile error.
    pub fn is_empty(self) -> bool {
        self.len() == 0
    }

    /// The pixel rectangle a tile covers, clipped to the display.
    ///
    /// Tiles at the right and bottom edges are partial, and are carried at their
    /// clipped size rather than padded: padding would mean the decoder needs to
    /// know which tiles are edge tiles in order to know what to throw away, and
    /// a decoder that has to know that is a decoder that can be told wrong.
    pub fn bounds(self, coord: TileCoord) -> Result<Rect, TileError> {
        if coord.col >= self.cols() || coord.row >= self.rows() {
            return Err(TileError::OutOfGrid { col: coord.col, row: coord.row });
        }
        let edge = u32::from(self.size.0);
        let x = u32::from(coord.col) * edge;
        let y = u32::from(coord.row) * edge;
        Ok(Rect {
            // Both products are below `MAX_EDGE`, which is far inside `i32`.
            x: x as i32,
            y: y as i32,
            width: edge.min(self.width - x),
            height: edge.min(self.height - y),
        })
    }

    /// Every tile in the grid, in row-major order.
    pub fn coords(self) -> impl Iterator<Item = TileCoord> {
        let (cols, rows) = (self.cols(), self.rows());
        (0..rows).flat_map(move |row| (0..cols).map(move |col| TileCoord { col, row }))
    }
}

impl Damage {
    /// The set of tiles this damage touches, sorted in row-major order.
    ///
    /// Move *destinations* are folded in before dirty rectangles, which is the
    /// documented reconstruction order; move sources are not, because a client
    /// that redraws the destination does not need them and a client that blits
    /// reads them from its own surface. Rectangles are clipped to the grid, so a
    /// capture API reporting a rectangle partly off-screen — which happens
    /// during a mode change — costs a clip rather than a refusal.
    pub fn tiles(&self, grid: Grid) -> Vec<TileCoord> {
        let mut touched = Vec::new();
        for moved in &self.moves {
            collect_tiles(grid, moved.to, &mut touched);
        }
        for dirty in &self.dirty {
            collect_tiles(grid, *dirty, &mut touched);
        }
        touched.sort_unstable_by_key(|coord| (coord.row, coord.col));
        touched.dedup();
        touched
    }
}

/// Adds every grid tile a rectangle overlaps to `out`.
fn collect_tiles(grid: Grid, rect: Rect, out: &mut Vec<TileCoord>) {
    if rect.is_empty() {
        return;
    }
    let edge = i64::from(grid.size.edge());
    let left = rect.x as i64;
    let top = rect.y as i64;
    let right = rect.right();
    let bottom = rect.bottom();

    // Clip to the display before dividing, so a negative or out-of-range origin
    // becomes an empty range rather than a negative tile index.
    let left = left.max(0).min(i64::from(grid.width));
    let top = top.max(0).min(i64::from(grid.height));
    let right = right.max(0).min(i64::from(grid.width));
    let bottom = bottom.max(0).min(i64::from(grid.height));
    if left >= right || top >= bottom {
        return;
    }

    let first_col = left / edge;
    let last_col = (right - 1) / edge;
    let first_row = top / edge;
    let last_row = (bottom - 1) / edge;

    for row in first_row..=last_row {
        for col in first_col..=last_col {
            // Both are below the grid's own column and row counts, which fit a
            // `u16` by construction.
            out.push(TileCoord { col: col as u16, row: row as u16 });
        }
    }
}

/// A tight BGRA image: rows exactly `width * 4` bytes apart.
///
/// "Tight" is the invariant, and it is why this is a type rather than a tuple.
/// Every captured surface arrives padded, in a per-surface amount that is not
/// derivable from the width, and every bug this module could have starts with a
/// padded buffer being treated as a tight one. [`unpack`] is the only way in
/// from a padded source.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Surface {
    width: u32,
    height: u32,
    pixels: Vec<u8>,
}

impl Surface {
    /// Wraps a tight BGRA buffer.
    ///
    /// Refuses a buffer whose length is not exactly `width * height * 4`.
    pub fn new(width: u32, height: u32, pixels: Vec<u8>) -> Result<Self, TileError> {
        let expected = tight_len(width, height)?;
        if pixels.len() != expected {
            return Err(TileError::SizeMismatch { expected, actual: pixels.len() });
        }
        Ok(Self { width, height, pixels })
    }

    /// A fully transparent surface of the given size, for a client that has not
    /// received its first keyframe.
    pub fn blank(width: u32, height: u32) -> Result<Self, TileError> {
        let len = tight_len(width, height)?;
        Ok(Self { width, height, pixels: vec![0; len] })
    }

    /// The width in pixels.
    pub const fn width(&self) -> u32 {
        self.width
    }

    /// The height in pixels.
    pub const fn height(&self) -> u32 {
        self.height
    }

    /// The tight BGRA bytes.
    pub fn pixels(&self) -> &[u8] {
        &self.pixels
    }

    /// Copies out one tile's pixels, row by row.
    ///
    /// The rectangle must lie inside the surface, which it does for every
    /// rectangle [`Grid::bounds`] produces for a grid built on this surface's
    /// dimensions.
    pub fn tile(&self, rect: Rect) -> Result<Vec<u8>, TileError> {
        let (start_x, start_y, width, height) = self.clip(rect)?;
        let row_bytes = width as usize * BYTES_PER_PIXEL;
        let mut out = Vec::with_capacity(row_bytes * height as usize);
        for row in 0..height {
            let offset = self.offset(start_x, start_y + row)?;
            let end = offset.checked_add(row_bytes).ok_or(TileError::Overflow { what: "tile row" })?;
            let slice =
                self.pixels.get(offset..end).ok_or(TileError::Overflow { what: "tile row" })?;
            out.extend_from_slice(slice);
        }
        Ok(out)
    }

    /// Writes one tile's pixels back into the surface, row by row.
    ///
    /// `pixels` must be exactly the tile's area in BGRA. This is what a client
    /// does with a decoded tile.
    pub fn put_tile(&mut self, rect: Rect, pixels: &[u8]) -> Result<(), TileError> {
        let (start_x, start_y, width, height) = self.clip(rect)?;
        let row_bytes = width as usize * BYTES_PER_PIXEL;
        let expected =
            row_bytes.checked_mul(height as usize).ok_or(TileError::Overflow { what: "tile" })?;
        if pixels.len() != expected {
            return Err(TileError::SizeMismatch { expected, actual: pixels.len() });
        }
        for row in 0..height {
            let offset = self.offset(start_x, start_y + row)?;
            let end = offset.checked_add(row_bytes).ok_or(TileError::Overflow { what: "tile row" })?;
            let source = row as usize * row_bytes;
            let destination =
                self.pixels.get_mut(offset..end).ok_or(TileError::Overflow { what: "tile row" })?;
            let taken = pixels
                .get(source..source + row_bytes)
                .ok_or(TileError::Overflow { what: "tile row" })?;
            destination.copy_from_slice(taken);
        }
        Ok(())
    }

    /// Validates a rectangle against this surface and returns it as unsigned.
    fn clip(&self, rect: Rect) -> Result<(u32, u32, u32, u32), TileError> {
        if rect.x < 0 || rect.y < 0 || rect.right() > i64::from(self.width) || rect.bottom() > i64::from(self.height) {
            return Err(TileError::OutsideSurface);
        }
        Ok((rect.x as u32, rect.y as u32, rect.width, rect.height))
    }

    /// The byte offset of a pixel.
    fn offset(&self, x: u32, y: u32) -> Result<usize, TileError> {
        let index = (y as usize)
            .checked_mul(self.width as usize)
            .and_then(|row| row.checked_add(x as usize))
            .and_then(|pixel| pixel.checked_mul(BYTES_PER_PIXEL))
            .ok_or(TileError::Overflow { what: "pixel offset" })?;
        Ok(index)
    }
}

/// One tile to send.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TileUpdate {
    /// Where it goes.
    pub coord: TileCoord,
    /// How it is encoded.
    pub encoding: Encoding,
    /// The encoded bytes.
    pub payload: Vec<u8>,
}

/// What a decoded tile turned out to be.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Decoded {
    /// The tile is the same as the client already holds; nothing to write.
    Unchanged,
    /// The tile's pixels, tight BGRA, exactly the tile's area.
    Pixels(Vec<u8>),
}

/// Checks a display dimension.
fn check_dimension(value: u32) -> Result<(), TileError> {
    if value == 0 || value > MAX_EDGE {
        return Err(TileError::BadDimension { value });
    }
    Ok(())
}

/// The byte length of a tight BGRA image, refusing anything that would overflow.
fn tight_len(width: u32, height: u32) -> Result<usize, TileError> {
    check_dimension(width)?;
    check_dimension(height)?;
    (width as usize)
        .checked_mul(height as usize)
        .and_then(|pixels| pixels.checked_mul(BYTES_PER_PIXEL))
        .ok_or(TileError::Overflow { what: "surface length" })
}

/// Converts a captured surface with padded rows into a tight [`Surface`].
///
/// `stride` is the number of bytes between the starts of consecutive rows, which
/// is what every capture API on both platforms reports and which is almost never
/// `width * 4`. The last row is allowed to be short — a surface's final row does
/// not need its padding present — which is why the requirement is
/// `stride * (height - 1) + width * 4` rather than `stride * height`.
///
/// This is the function that stands between a correct picture and a sheared one.
/// See the module documentation for the measured figures its tests use.
pub fn unpack(width: u32, height: u32, stride: usize, src: &[u8]) -> Result<Surface, TileError> {
    check_dimension(width)?;
    check_dimension(height)?;
    let tight_row = (width as usize)
        .checked_mul(BYTES_PER_PIXEL)
        .ok_or(TileError::Overflow { what: "row length" })?;

    if stride < tight_row {
        return Err(TileError::StrideTooSmall { stride, minimum: tight_row });
    }

    let needed = stride
        .checked_mul(height as usize - 1)
        .and_then(|full_rows| full_rows.checked_add(tight_row))
        .ok_or(TileError::Overflow { what: "source length" })?;
    if src.len() < needed {
        return Err(TileError::Truncated { needed, available: src.len() });
    }

    // Only now, with the source proven long enough, is anything allocated: the
    // capacity below is bounded by bytes that demonstrably exist.
    let mut pixels = Vec::with_capacity(tight_len(width, height)?);
    for row in 0..height as usize {
        let start = row * stride;
        let slice =
            src.get(start..start + tight_row).ok_or(TileError::Truncated {
                needed: start + tight_row,
                available: src.len(),
            })?;
        pixels.extend_from_slice(slice);
    }
    Surface::new(width, height, pixels)
}

/// Encodes one tile's pixels in whichever encoding is smallest.
///
/// `tile` is tight BGRA, exactly the tile's area. Never returns
/// [`Encoding::Unchanged`]: that decision belongs to [`diff`], which has both
/// frames.
pub fn encode_tile(tile: &[u8]) -> Result<(Encoding, Vec<u8>), TileError> {
    let pixels = tile.len() / BYTES_PER_PIXEL;
    if tile.is_empty() || tile.len() % BYTES_PER_PIXEL != 0 || pixels > MAX_TILE_PIXELS {
        return Err(TileError::BadTilePixels { pixels });
    }

    let first = tile.get(..BYTES_PER_PIXEL).ok_or(TileError::BadTilePixels { pixels })?;
    if tile.chunks_exact(BYTES_PER_PIXEL).all(|pixel| pixel == first) {
        return Ok((Encoding::Solid, first.to_vec()));
    }

    let runs = rle_encode(tile);
    if runs.len() < tile.len() {
        Ok((Encoding::Rle, runs))
    } else {
        // RLE can be *larger* than raw — 4096 distinct pixels is 20480 bytes of
        // runs against 16384 raw — which is exactly what a photograph looks
        // like, so the comparison is not theoretical.
        Ok((Encoding::Raw, tile.to_vec()))
    }
}

/// Run-length encodes tight BGRA into `[count][b][g][r][a]` records.
fn rle_encode(tile: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    let mut pixels = tile.chunks_exact(BYTES_PER_PIXEL);
    let Some(mut current) = pixels.next() else { return out };
    let mut count: u8 = 1;

    for pixel in pixels {
        if pixel == current && count < u8::MAX {
            count += 1;
            continue;
        }
        out.push(count);
        out.extend_from_slice(current);
        current = pixel;
        count = 1;
    }
    out.push(count);
    out.extend_from_slice(current);
    out
}

/// Decodes one tile payload.
///
/// `pixels` is how many pixels the tile holds — from [`Grid::bounds`] on the
/// client's own grid, never from the message, so a peer cannot make the decoder
/// size a buffer. Total: every payload produces a `Decoded` or a [`TileError`],
/// and never a panic.
pub fn decode_tile(
    encoding: Encoding,
    payload: &[u8],
    pixels: usize,
) -> Result<Decoded, TileError> {
    if pixels == 0 || pixels > MAX_TILE_PIXELS {
        return Err(TileError::BadTilePixels { pixels });
    }
    let expected = pixels
        .checked_mul(BYTES_PER_PIXEL)
        .ok_or(TileError::Overflow { what: "tile length" })?;

    match encoding {
        Encoding::Unchanged => {
            if payload.is_empty() {
                Ok(Decoded::Unchanged)
            } else {
                Err(TileError::PayloadMismatch { encoding, actual: payload.len() })
            }
        }
        Encoding::Raw => {
            if payload.len() != expected {
                return Err(TileError::PayloadMismatch { encoding, actual: payload.len() });
            }
            Ok(Decoded::Pixels(payload.to_vec()))
        }
        Encoding::Solid => {
            let colour = payload
                .get(..BYTES_PER_PIXEL)
                .filter(|_| payload.len() == BYTES_PER_PIXEL)
                .ok_or(TileError::PayloadMismatch { encoding, actual: payload.len() })?;
            let mut out = Vec::with_capacity(expected);
            for _ in 0..pixels {
                out.extend_from_slice(colour);
            }
            Ok(Decoded::Pixels(out))
        }
        Encoding::Rle => decode_rle(payload, pixels, expected),
    }
}

/// Decodes an RLE payload into exactly `pixels` pixels.
fn decode_rle(payload: &[u8], pixels: usize, expected: usize) -> Result<Decoded, TileError> {
    const RECORD: usize = 1 + BYTES_PER_PIXEL;
    if payload.len() % RECORD != 0 || payload.is_empty() {
        return Err(TileError::PayloadMismatch { encoding: Encoding::Rle, actual: payload.len() });
    }

    let mut out = Vec::with_capacity(expected);
    let mut produced = 0usize;
    for record in payload.chunks_exact(RECORD) {
        let count = usize::from(record[0]);
        if count == 0 {
            return Err(TileError::ZeroRun);
        }
        produced = produced.checked_add(count).ok_or(TileError::Overflow { what: "run total" })?;
        if produced > pixels {
            return Err(TileError::RunOverruns { tile: pixels });
        }
        for _ in 0..count {
            out.extend_from_slice(&record[1..RECORD]);
        }
    }

    if produced != pixels {
        // Short is as wrong as long: a payload that describes half a tile would
        // otherwise leave the other half holding whatever was there before, and
        // the difference between "stale pixels" and "the picture is correct" is
        // exactly what a remote desktop is for.
        return Err(TileError::RunOverruns { tile: pixels });
    }
    Ok(Decoded::Pixels(out))
}

/// The tiles that differ between two frames.
///
/// `previous` is `None` for a keyframe, in which case every tile is emitted.
/// A dimension change between the two frames is [`TileError::SizeMismatch`]
/// rather than a best-effort diff: the caller's correct response is to send a
/// keyframe, and a diff between differently shaped frames would be a picture
/// made of two resolutions.
///
/// An unchanged tile is **omitted**, not sent as [`Encoding::Unchanged`]. That
/// is the whole bandwidth argument: a still desktop produces an empty vector.
pub fn diff(
    previous: Option<&Surface>,
    current: &Surface,
    size: TileSize,
) -> Result<Vec<TileUpdate>, TileError> {
    if let Some(previous) = previous {
        if previous.width() != current.width() || previous.height() != current.height() {
            return Err(TileError::SizeMismatch {
                expected: previous.pixels().len(),
                actual: current.pixels().len(),
            });
        }
    }

    let grid = Grid::new(size, current.width(), current.height())?;
    let mut updates = Vec::new();
    for coord in grid.coords() {
        let bounds = grid.bounds(coord)?;
        let tile = current.tile(bounds)?;
        if let Some(previous) = previous {
            if previous.tile(bounds)? == tile {
                continue;
            }
        }
        let (encoding, payload) = encode_tile(&tile)?;
        updates.push(TileUpdate { coord, encoding, payload });
    }
    Ok(updates)
}

/// Applies one decoded tile to a client's surface.
///
/// The inverse of [`diff`]'s per-tile half: given the same grid, applying every
/// update of a frame reproduces the sender's surface exactly, which is what the
/// round-trip test asserts.
pub fn apply(surface: &mut Surface, size: TileSize, update: &TileUpdate) -> Result<(), TileError> {
    let grid = Grid::new(size, surface.width(), surface.height())?;
    let bounds = grid.bounds(update.coord)?;
    let pixels = bounds.width as usize * bounds.height as usize;
    match decode_tile(update.encoding, &update.payload, pixels)? {
        Decoded::Unchanged => Ok(()),
        Decoded::Pixels(decoded) => surface.put_tile(bounds, &decoded),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A solid-colour surface.
    fn solid(width: u32, height: u32, colour: [u8; 4]) -> Surface {
        let mut pixels = Vec::with_capacity(width as usize * height as usize * 4);
        for _ in 0..width as usize * height as usize {
            pixels.extend_from_slice(&colour);
        }
        Surface::new(width, height, pixels).expect("well-formed")
    }

    /// Paints a rectangle into a surface.
    fn paint(surface: &mut Surface, rect: Rect, colour: [u8; 4]) {
        let mut row = Vec::with_capacity(rect.width as usize * 4);
        for _ in 0..rect.width as usize * rect.height as usize {
            row.extend_from_slice(&colour);
        }
        surface.put_tile(rect, &row).expect("inside the surface");
    }

    #[test]
    fn only_the_four_documented_tile_sizes_are_admitted() {
        for edge in LEGAL_TILE_EDGES {
            assert_eq!(TileSize::new(edge).map(TileSize::edge), Ok(edge));
        }
        for edge in [0u16, 1, 8, 15, 17, 63, 65, 127, 129, 256, 1024, u16::MAX] {
            assert_eq!(TileSize::new(edge), Err(TileError::BadTileSize { edge }));
        }
        assert_eq!(TileSize::DEFAULT.edge(), 64);
        assert_eq!(TileSize::DEFAULT.pixels(), 4096);
        assert_eq!(TileSize::DEFAULT.bytes(), 16_384);
    }

    #[test]
    fn every_encoding_round_trips_through_its_wire_code() {
        for encoding in [Encoding::Raw, Encoding::Rle, Encoding::Unchanged, Encoding::Solid] {
            assert_eq!(Encoding::from_code(encoding.code()), Some(encoding));
        }
        assert_eq!(Encoding::from_code(0x04), None);
        assert_eq!(Encoding::from_code(0xFF), None);
    }

    #[test]
    fn a_macos_cgimage_row_stride_unpacks_to_a_tight_surface() {
        // Measured on this host: a 3024-pixel-wide CGImage has a 12160-byte row
        // stride against a 12096-byte row — 64 bytes of padding. Assuming
        // width * 4 shears the image by 16 pixels per row, which still looks
        // like a picture of the desktop.
        let width = 3024u32;
        let stride = 12_160usize;
        let height = 4u32;
        assert_eq!(width as usize * 4, 12_096);

        let mut src = vec![0u8; stride * height as usize];
        for row in 0..height as usize {
            // Mark each row with its own index in every pixel, and fill the
            // padding with a value that must never appear in the output.
            for byte in src[row * stride..row * stride + 12_096].iter_mut() {
                *byte = row as u8;
            }
            for byte in src[row * stride + 12_096..(row + 1) * stride].iter_mut() {
                *byte = 0xEE;
            }
        }

        let surface = unpack(width, height, stride, &src).expect("well-formed source");
        assert_eq!(surface.pixels().len(), 3024 * 4 * 4);
        assert!(!surface.pixels().contains(&0xEE), "row padding leaked into the image");
        for row in 0..height as usize {
            let start = row * 12_096;
            assert!(surface.pixels()[start..start + 12_096].iter().all(|byte| *byte == row as u8));
        }
    }

    #[test]
    fn a_macos_iosurface_row_stride_unpacks_to_a_tight_surface() {
        // The other measured figure: a 1512-pixel IOSurface has 6144 against
        // 6048. The two differ, on the same machine, for the same desktop —
        // which is the reason the stride is never derived from the width.
        let (width, stride, height) = (1512u32, 6144usize, 3u32);
        assert_eq!(width as usize * 4, 6048);
        let src = vec![0x7Fu8; stride * height as usize];
        let surface = unpack(width, height, stride, &src).expect("well-formed source");
        assert_eq!(surface.pixels().len(), 1512 * 3 * 4);
        assert!(surface.pixels().iter().all(|byte| *byte == 0x7F));
    }

    #[test]
    fn a_tight_source_needs_no_padding_and_the_last_row_may_be_short() {
        let (width, height) = (4u32, 3u32);
        let tight = width as usize * 4;
        // Exactly enough bytes: two padded rows and one unpadded final row.
        let stride = tight + 8;
        let src = vec![1u8; stride * (height as usize - 1) + tight];
        assert!(unpack(width, height, stride, &src).is_ok());
        // One byte fewer is a truncation, not a silently short last row.
        assert_eq!(
            unpack(width, height, stride, &src[..src.len() - 1]),
            Err(TileError::Truncated { needed: src.len(), available: src.len() - 1 })
        );
    }

    #[test]
    fn a_stride_narrower_than_the_row_is_refused() {
        assert_eq!(
            unpack(100, 2, 399, &[0; 10_000]),
            Err(TileError::StrideTooSmall { stride: 399, minimum: 400 })
        );
    }

    #[test]
    fn absurd_geometry_is_refused_rather_than_multiplied() {
        assert_eq!(unpack(0, 4, 16, &[0; 64]), Err(TileError::BadDimension { value: 0 }));
        assert_eq!(unpack(4, 0, 16, &[0; 64]), Err(TileError::BadDimension { value: 0 }));
        assert_eq!(
            unpack(MAX_EDGE + 1, 4, 1 << 20, &[0; 64]),
            Err(TileError::BadDimension { value: MAX_EDGE + 1 })
        );
        assert_eq!(Surface::new(4, 4, vec![0; 63]), Err(TileError::SizeMismatch { expected: 64, actual: 63 }));
    }

    #[test]
    fn a_completely_static_frame_produces_no_tiles_at_all() {
        // The single claim the whole encoder exists to make.
        let frame = solid(1920, 1080, [10, 20, 30, 255]);
        let previous = frame.clone();
        let updates = diff(Some(&previous), &frame, TileSize::DEFAULT).expect("same size");
        assert!(updates.is_empty(), "a still desktop cost {} tiles", updates.len());
    }

    #[test]
    fn a_changed_region_costs_roughly_its_own_area() {
        // 640x480 at 64px tiles is a 10x8 grid of 80 tiles. A 100x100 change at
        // (10, 10) spans columns 0-1 and rows 0-1: four tiles, not eighty.
        let previous = solid(640, 480, [0, 0, 0, 255]);
        let mut current = previous.clone();
        paint(&mut current, Rect::new(10, 10, 100, 100), [255, 255, 255, 255]);

        let updates = diff(Some(&previous), &current, TileSize::DEFAULT).expect("same size");
        assert_eq!(updates.len(), 4, "expected the four tiles the change touches");
        let touched: Vec<TileCoord> = updates.iter().map(|update| update.coord).collect();
        assert_eq!(
            touched,
            vec![
                TileCoord { col: 0, row: 0 },
                TileCoord { col: 1, row: 0 },
                TileCoord { col: 0, row: 1 },
                TileCoord { col: 1, row: 1 },
            ]
        );

        // And the bytes: a full raw frame is 1,228,800 bytes. Four tiles of
        // mostly-flat colour must cost a small fraction of that.
        let sent: usize = updates.iter().map(|update| update.payload.len()).sum();
        let whole_frame = 640 * 480 * 4;
        assert!(sent * 20 < whole_frame, "sent {sent} bytes for a 100x100 change");
    }

    #[test]
    fn a_keyframe_emits_every_tile_including_the_partial_edge_ones() {
        let frame = solid(100, 100, [1, 2, 3, 255]);
        let grid = Grid::new(TileSize::DEFAULT, 100, 100).expect("valid");
        assert_eq!((grid.cols(), grid.rows()), (2, 2));
        assert!(!grid.is_empty());

        let updates = diff(None, &frame, TileSize::DEFAULT).expect("valid");
        assert_eq!(updates.len(), grid.len());
        // The bottom-right tile is 36x36, not 64x64.
        let corner = grid.bounds(TileCoord { col: 1, row: 1 }).expect("in grid");
        assert_eq!(corner, Rect::new(64, 64, 36, 36));
    }

    #[test]
    fn applying_every_tile_of_a_frame_reproduces_it_exactly() {
        let mut current = solid(200, 150, [5, 5, 5, 255]);
        paint(&mut current, Rect::new(3, 7, 41, 23), [200, 100, 50, 255]);
        paint(&mut current, Rect::new(150, 120, 50, 30), [0, 255, 0, 255]);
        // A patch of noise, so at least one tile chooses Raw over RLE.
        let mut noisy = Vec::new();
        for index in 0..40 * 40 {
            noisy.extend_from_slice(&[(index % 251) as u8, (index % 253) as u8, 7, 255]);
        }
        current.put_tile(Rect::new(80, 80, 40, 40), &noisy).expect("inside");

        let updates = diff(None, &current, TileSize::DEFAULT).expect("valid");
        let mut client = Surface::blank(200, 150).expect("valid");
        for update in &updates {
            apply(&mut client, TileSize::DEFAULT, update).expect("valid update");
        }
        assert_eq!(client, current);

        // All four encodings should have been exercised by the frames above,
        // minus Unchanged which `diff` never emits.
        let used: Vec<Encoding> = {
            let mut seen: Vec<Encoding> = updates.iter().map(|update| update.encoding).collect();
            seen.sort_unstable_by_key(|encoding| encoding.code());
            seen.dedup();
            seen
        };
        assert!(used.contains(&Encoding::Solid));
        assert!(used.contains(&Encoding::Raw) || used.contains(&Encoding::Rle));
        assert!(!used.contains(&Encoding::Unchanged));
    }

    #[test]
    fn a_resolution_change_between_frames_is_refused_rather_than_diffed() {
        let previous = solid(640, 480, [0; 4]);
        let current = solid(800, 600, [0; 4]);
        assert!(matches!(
            diff(Some(&previous), &current, TileSize::DEFAULT),
            Err(TileError::SizeMismatch { .. })
        ));
    }

    #[test]
    fn a_solid_tile_costs_four_bytes_and_a_noisy_one_falls_back_to_raw() {
        let flat = vec![9u8; TileSize::DEFAULT.bytes()];
        assert_eq!(encode_tile(&flat), Ok((Encoding::Solid, vec![9, 9, 9, 9])));

        // 4096 distinct pixels: RLE would be 20480 bytes against 16384 raw.
        let mut noisy = Vec::new();
        for index in 0..4096u32 {
            noisy.extend_from_slice(&index.to_be_bytes());
        }
        let (encoding, payload) = encode_tile(&noisy).expect("well-formed");
        assert_eq!(encoding, Encoding::Raw);
        assert_eq!(payload.len(), noisy.len());
    }

    #[test]
    fn a_run_longer_than_a_byte_can_count_is_split() {
        // 4096 identical pixels cannot be one run of 4096; the encoder must emit
        // runs of at most 255 and the decoder must reassemble them. This is only
        // reachable through `rle_encode` directly, since `encode_tile` would
        // pick Solid for a uniform tile.
        let flat = vec![3u8; 4096 * 4];
        let runs = rle_encode(&flat);
        assert_eq!(runs.len(), 4096usize.div_ceil(255) * 5);
        assert_eq!(decode_tile(Encoding::Rle, &runs, 4096), Ok(Decoded::Pixels(flat)));
    }

    #[test]
    fn every_encoding_round_trips_through_encode_and_decode() {
        let cases: Vec<Vec<u8>> = vec![
            vec![1, 2, 3, 4],
            vec![7u8; 4 * 16],
            {
                let mut mixed = vec![0u8; 4 * 100];
                for index in 0..25 {
                    mixed[index * 4] = index as u8;
                }
                mixed
            },
        ];
        for tile in cases {
            let pixels = tile.len() / 4;
            let (encoding, payload) = encode_tile(&tile).expect("well-formed");
            assert_eq!(decode_tile(encoding, &payload, pixels), Ok(Decoded::Pixels(tile)));
        }
    }

    #[test]
    fn an_unchanged_tile_decodes_to_nothing_and_refuses_a_payload() {
        assert_eq!(decode_tile(Encoding::Unchanged, &[], 4096), Ok(Decoded::Unchanged));
        assert_eq!(
            decode_tile(Encoding::Unchanged, &[0], 4096),
            Err(TileError::PayloadMismatch { encoding: Encoding::Unchanged, actual: 1 })
        );
    }

    #[test]
    fn a_zero_run_is_refused_rather_than_looping_forever() {
        // The classic RLE denial of service: a zero-length run consumes payload
        // without producing pixels, so a naive decoder never terminates.
        assert_eq!(decode_tile(Encoding::Rle, &[0, 1, 2, 3, 4], 4), Err(TileError::ZeroRun));
    }

    #[test]
    fn an_rle_payload_must_describe_the_tile_exactly() {
        // Too many pixels.
        assert_eq!(
            decode_tile(Encoding::Rle, &[255, 1, 2, 3, 4], 4),
            Err(TileError::RunOverruns { tile: 4 })
        );
        // Too few.
        assert_eq!(
            decode_tile(Encoding::Rle, &[2, 1, 2, 3, 4], 4),
            Err(TileError::RunOverruns { tile: 4 })
        );
        // Exactly right.
        assert!(decode_tile(Encoding::Rle, &[4, 1, 2, 3, 4], 4).is_ok());
        // A payload that is not a whole number of records.
        assert_eq!(
            decode_tile(Encoding::Rle, &[4, 1, 2, 3], 4),
            Err(TileError::PayloadMismatch { encoding: Encoding::Rle, actual: 4 })
        );
        assert_eq!(
            decode_tile(Encoding::Rle, &[], 4),
            Err(TileError::PayloadMismatch { encoding: Encoding::Rle, actual: 0 })
        );
    }

    #[test]
    fn raw_and_solid_payloads_must_be_exactly_the_right_length() {
        assert_eq!(
            decode_tile(Encoding::Raw, &[0; 15], 4),
            Err(TileError::PayloadMismatch { encoding: Encoding::Raw, actual: 15 })
        );
        assert_eq!(
            decode_tile(Encoding::Raw, &[0; 17], 4),
            Err(TileError::PayloadMismatch { encoding: Encoding::Raw, actual: 17 })
        );
        assert_eq!(
            decode_tile(Encoding::Solid, &[0; 3], 4),
            Err(TileError::PayloadMismatch { encoding: Encoding::Solid, actual: 3 })
        );
        assert_eq!(
            decode_tile(Encoding::Solid, &[0; 5], 4),
            Err(TileError::PayloadMismatch { encoding: Encoding::Solid, actual: 5 })
        );
    }

    #[test]
    fn a_tile_size_the_client_could_not_hold_is_refused_before_allocating() {
        // The pixel count is supplied by the client from its own grid, but a
        // bug there must not become an allocation the size of a claim.
        for pixels in [0, MAX_TILE_PIXELS + 1, usize::MAX] {
            assert_eq!(
                decode_tile(Encoding::Solid, &[1, 2, 3, 4], pixels),
                Err(TileError::BadTilePixels { pixels })
            );
        }
    }

    #[test]
    fn damage_rectangles_map_onto_the_tiles_they_touch() {
        let grid = Grid::new(TileSize::DEFAULT, 640, 480).expect("valid");
        let damage = Damage {
            moves: vec![MoveRect {
                from: Rect::new(0, 0, 64, 64),
                to: Rect::new(128, 128, 64, 64),
            }],
            dirty: vec![Rect::new(10, 10, 100, 100)],
        };
        assert_eq!(
            damage.tiles(grid),
            vec![
                TileCoord { col: 0, row: 0 },
                TileCoord { col: 1, row: 0 },
                TileCoord { col: 0, row: 1 },
                TileCoord { col: 1, row: 1 },
                TileCoord { col: 2, row: 2 },
            ]
        );
    }

    #[test]
    fn damage_outside_the_display_is_clipped_rather_than_refused() {
        // A capture API reporting a rectangle partly off-screen is an ordinary
        // event during a mode change, and every arithmetic hazard in this module
        // is in this one function.
        let grid = Grid::new(TileSize::DEFAULT, 640, 480).expect("valid");
        let cases = [
            Rect::new(-1000, -1000, 100, 100),
            Rect::new(i32::MIN, i32::MIN, u32::MAX, u32::MAX),
            Rect::new(i32::MAX, i32::MAX, u32::MAX, u32::MAX),
            Rect::new(639, 479, u32::MAX, u32::MAX),
            Rect::new(0, 0, 0, 0),
            Rect::new(10, 10, 0, 50),
        ];
        for rect in cases {
            let damage = Damage { moves: Vec::new(), dirty: vec![rect] };
            let tiles = damage.tiles(grid);
            for coord in tiles {
                assert!(coord.col < grid.cols() && coord.row < grid.rows(), "{coord:?} for {rect:?}");
            }
        }

        // A rectangle covering everything touches every tile, exactly once.
        let all = Damage { moves: Vec::new(), dirty: vec![Rect::new(-50, -50, 5000, 5000)] };
        assert_eq!(all.tiles(grid).len(), grid.len());
    }

    #[test]
    fn a_tile_outside_the_grid_is_refused() {
        let grid = Grid::new(TileSize::DEFAULT, 100, 100).expect("valid");
        assert_eq!(
            grid.bounds(TileCoord { col: 2, row: 0 }),
            Err(TileError::OutOfGrid { col: 2, row: 0 })
        );
        assert_eq!(
            grid.bounds(TileCoord { col: 0, row: 9 }),
            Err(TileError::OutOfGrid { col: 0, row: 9 })
        );
    }

    #[test]
    fn every_error_prints_something_useful() {
        let errors = [
            TileError::BadTileSize { edge: 7 },
            TileError::BadDimension { value: 0 },
            TileError::SizeMismatch { expected: 1, actual: 2 },
            TileError::StrideTooSmall { stride: 1, minimum: 2 },
            TileError::Truncated { needed: 2, available: 1 },
            TileError::ZeroRun,
            TileError::RunOverruns { tile: 4 },
            TileError::PayloadMismatch { encoding: Encoding::Rle, actual: 3 },
            TileError::BadTilePixels { pixels: 0 },
            TileError::OutOfGrid { col: 1, row: 2 },
            TileError::OutsideSurface,
            TileError::Overflow { what: "x" },
        ];
        for error in errors {
            assert!(!error.to_string().is_empty(), "{error:?}");
        }
    }

    /// The same six-line generator [`crate::wire`]'s fuzz test uses; a real
    /// fuzzer is not importable under this workspace's dependency policy.
    struct Noise(u64);

    impl Noise {
        fn next(&mut self) -> u64 {
            let mut state = self.0;
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            self.0 = state;
            state.wrapping_mul(0x2545_F491_4F6C_DD1D)
        }
    }

    /// A payload that legitimately encodes `pixels` pixels in `encoding`.
    fn valid_payload(encoding: Encoding, pixels: usize) -> Vec<u8> {
        match encoding {
            Encoding::Unchanged => Vec::new(),
            Encoding::Solid => vec![1, 2, 3, 4],
            Encoding::Raw => vec![9; pixels * BYTES_PER_PIXEL],
            Encoding::Rle => {
                let mut out = Vec::new();
                let mut left = pixels;
                while left > 0 {
                    let run = left.min(255);
                    out.push(run as u8);
                    out.extend_from_slice(&[5, 6, 7, 8]);
                    left -= run;
                }
                out
            }
        }
    }

    #[test]
    fn decoding_random_tile_payloads_never_panics() {
        // Half the inputs start from a payload that is genuinely valid for the
        // encoding and tile size, so the success path is exercised as heavily as
        // the refusal paths; the other half is unstructured noise. Without the
        // first half, a purely random generator would essentially never produce
        // a decodable payload and the loop would assert nothing about decoding.
        let mut noise = Noise(0xFEED_FACE_DEAD_BEEF);
        let encodings = [Encoding::Raw, Encoding::Rle, Encoding::Unchanged, Encoding::Solid];
        let sizes = [0usize, 1, 4, 16, 255, 256, 4096, MAX_TILE_PIXELS, MAX_TILE_PIXELS + 1];
        let mut decoded = 0usize;

        for round in 0..20_000u32 {
            let encoding = encodings[(noise.next() as usize) % encodings.len()];
            let pixels = sizes[(noise.next() as usize) % sizes.len()];

            let mut payload = if round % 2 == 0 && pixels <= MAX_TILE_PIXELS {
                valid_payload(encoding, pixels)
            } else {
                let length = (noise.next() % 200) as usize;
                (0..length).map(|_| (noise.next() >> 24) as u8).collect()
            };
            // Corrupt a quarter of them, which is what reaches the validators
            // that a wholly random payload never gets past.
            if round % 4 == 1 && !payload.is_empty() {
                let index = (noise.next() as usize) % payload.len();
                payload[index] = (noise.next() >> 24) as u8;
            }

            if let Ok(Decoded::Pixels(out)) = decode_tile(encoding, &payload, pixels) {
                decoded += 1;
                assert_eq!(out.len(), pixels * BYTES_PER_PIXEL);
            }
        }
        assert!(decoded > 0, "the generator never produced a decodable payload");
    }

    #[test]
    fn unpacking_random_geometry_never_panics() {
        let mut noise = Noise(0x0BAD_C0DE_1234_5678);
        let src = vec![0x11u8; 4096];
        for _ in 0..20_000 {
            let width = (noise.next() % 40) as u32;
            let height = (noise.next() % 40) as u32;
            let stride = (noise.next() % 400) as usize;
            let take = (noise.next() as usize) % src.len();
            let _ = unpack(width, height, stride, &src[..take]);
        }
        // And the extremes, which a small random range never reaches.
        let _ = unpack(MAX_EDGE, MAX_EDGE, usize::MAX, &src);
        let _ = unpack(1, MAX_EDGE, usize::MAX / 2, &src);
        let _ = unpack(u32::MAX, u32::MAX, usize::MAX, &src);
    }
}

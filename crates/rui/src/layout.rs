//! Turning a description into rectangles.
//!
//! Two passes, and no constraint solver. The first asks every element how big it
//! would like to be given the room on offer; the second hands out the room that
//! actually exists and tells each element where it is. Both run top to bottom
//! over the tree once, so laying out a frame costs what walking it costs.
//!
//! # The model
//!
//! It is the useful half of flexbox and nothing else. A container stacks its
//! children along one axis; each child asks for a [`Length`] along it —
//! [`Length::Auto`] for what its content needs, [`Length::Fixed`] for an exact
//! size, [`Length::Fill`] for a share of what is left over — and the leftover
//! room is divided between the fillers in proportion to what they asked for.
//! Across the other axis a child is either sized to its content or stretched.
//!
//! What is deliberately missing is wrapping, floating, absolute positioning, and
//! anything that can push a rectangle outside the box that owns it. Every
//! interface built from stacked and side-by-side boxes is expressible, which is
//! every interface, and in exchange the position of a thing is always decided by
//! exactly one parent — so drawing and hit testing cannot come to disagree about
//! where something is.

use crate::element::{El, Node};
use crate::geom::{Point, Rect, Size};
use crate::memory::{Id, Memory};
use crate::style::{Align, Anchor, Axis, Ink, Justify, Length};
use crate::text::Fonts;
use crate::theme::Theme;

/// Everything the layout has to consult that is not the tree itself.
pub(crate) struct Ctx<'a> {
    /// The faces text is measured in.
    pub(crate) fonts: &'a Fonts,
    /// The metrics that control heights and default gaps come from.
    pub(crate) theme: &'a Theme,
    /// The whole window, which a layer is held inside so that a menu opened
    /// near an edge cannot open off the screen.
    pub(crate) bounds: Rect,
}

/// How much room a scrolling area offers its children along its own axis.
///
/// Not infinity: a length has to survive being added to and subtracted from
/// without becoming a NaN that then propagates into every rectangle below it.
const UNBOUNDED: f32 = 1.0e6;

/// Lays the whole tree out inside `bounds`.
///
/// Assigns every element its identity as well as its rectangle, because the two
/// are decided by the same walk — an element's identity is its path through the
/// tree, and its rectangle is what its parent gave it.
pub(crate) fn solve<S>(root: &mut El<S>, bounds: Rect, ctx: &Ctx<'_>, memory: &mut Memory) {
    debug_assert_eq!(ctx.bounds, bounds, "layers are held inside the bounds laid out in");
    root.id = Id::ROOT;
    root.ink = root.style.ink.over(Ink::default());
    place(root, bounds, ctx, memory);
}

/// The size an element would like to be, given the room on offer.
fn measure<S>(el: &mut El<S>, avail: Size, ctx: &Ctx<'_>) -> Size {
    let padding = el.style.padding;
    // A box that states its own size hands *that* down to its contents rather
    // than the room it was offered. The two differ whenever a narrow box sits
    // in a wide one, and everything that reflows — a wrapped paragraph, a flow
    // of tags — is as tall as the width it was measured against. Measuring
    // against the offer and then shrinking to the stated width is how a
    // paragraph comes out one line tall and three lines long.
    let stated = Size::new(
        stated_length(el.style.width, avail.w)
            .map_or(avail.w, |width| width.clamp(el.style.min_width, el.style.max_width)),
        stated_length(el.style.height, avail.h)
            .map_or(avail.h, |height| height.clamp(el.style.min_height, el.style.max_height)),
    );
    let inner = Size::new(
        (stated.w - padding.horizontal()).max(0.0),
        (stated.h - padding.vertical()).max(0.0),
    );

    let content = match &el.node {
        Node::Text(text) => measure_text(text, el, inner, ctx),
        Node::Field { .. } => {
            Size::new(inner.w.min(FIELD_WIDTH), ctx.theme.metrics.control_height)
        }
        Node::Draw { intrinsic, .. } => *intrinsic,
        Node::Stack => measure_stack(el, inner, ctx),
    };

    let width = resolve(el.style.width, content.w + padding.horizontal(), avail.w)
        .clamp(el.style.min_width, el.style.max_width);
    let height = resolve(el.style.height, content.h + padding.vertical(), avail.h)
        .clamp(el.style.min_height, el.style.max_height);
    Size::new(width, height)
}

/// How wide a field asks to be before anything stretches it.
const FIELD_WIDTH: f32 = 180.0;

/// The size a run of text takes, wrapped if the element wraps.
fn measure_text<S>(text: &str, el: &El<S>, inner: Size, ctx: &Ctx<'_>) -> Size {
    let style = el.ink.style(ctx.theme);
    let line_height = ctx.fonts.metrics(&style).line_height();
    if !el.style.wrap {
        return Size::new(ctx.fonts.measure(&style, text), line_height);
    }
    let width = wrap_width(el, inner);
    let lines = ctx.fonts.wrap(&style, text, width).len().max(1);
    Size::new(width.min(ctx.fonts.measure(&style, text)), lines as f32 * line_height)
}

/// The width wrapped text is measured against.
///
/// A wrapping element that was told how wide to be wraps to that; one that was
/// not wraps to what its parent offered. Wrapping to the text's own preferred
/// width would be circular, and is the reason a paragraph must be given a width
/// by something.
fn wrap_width<S>(el: &El<S>, inner: Size) -> f32 {
    match el.style.width {
        Length::Fixed(width) => width - el.style.padding.horizontal(),
        _ => inner.w,
    }
    .max(0.0)
}

/// The size a container's children come to, stacked.
///
/// Children lifted out of the flow by [`El::layer`](crate::El::layer) are not
/// counted: a menu that made the button it hangs from wider would be a menu
/// that changed the layout by opening, which is the thing a layer exists to
/// avoid.
fn measure_stack<S>(el: &mut El<S>, inner: Size, ctx: &Ctx<'_>) -> Size {
    if el.style.flow {
        return measure_flow(el, inner, ctx);
    }
    let axis = el.style.axis;
    let offered = if el.scrolls { Size::new(inner.w, UNBOUNDED) } else { inner };

    let ink = el.ink;
    let mut order = Vec::new();
    let mut sizes = Vec::new();
    let mut mains = Vec::new();
    let mut grows = Vec::new();
    for (index, child) in el.children.iter_mut().enumerate() {
        child.ink = child.style.ink.over(ink);
        if child.style.layer.is_some() {
            continue;
        }
        let size = measure(child, offered, ctx);
        let length = main_length(child, axis);
        let grow = child.style.grow.unwrap_or_else(|| length.grow());
        let main = if grow > 0.0 && !child.style.grow_from_content {
            0.0
        } else {
            main_of(size, axis)
        };
        order.push(index);
        mains.push(clamp_main(child, main, axis));
        grows.push(grow);
        sizes.push(size);
    }
    let gaps = el.style.gap * order.len().saturating_sub(1) as f32;

    // What the stack asks for along its axis: everything's content, gaps
    // included — a grower counts its words here even though the place pass
    // deals it the leftover, because an unconstrained stack should still ask
    // for what is in it.
    let asked: f32 = sizes.iter().map(|size| main_of(*size, axis)).sum::<f32>() + gaps;

    // The cross size answers to the room each grower will actually be dealt,
    // not to the whole offer: a wrapped paragraph in a growing column of a row
    // is as tall as its share is narrow, and reading its height off a
    // full-width measurement is how a bank measured one line tall came to be
    // placed two lines full. Same division, same clamps as [`stack`].
    let taken: f32 = mains.iter().sum::<f32>() + gaps;
    let spare = (main_of(inner, axis) - taken).max(0.0);
    if grows.iter().any(|&grow| grow > 0.0) {
        distribute(&el.children, &order, &mut mains, &grows, axis, spare);
    }
    let mut cross = 0.0_f32;
    for (position, &index) in order.iter().enumerate() {
        let dealt = mains[position];
        let size = if grows[position] > 0.0
            && (dealt - main_of(sizes[position], axis)).abs() > 0.5
        {
            let share = match axis {
                Axis::Row => Size::new(dealt, offered.h),
                Axis::Column => Size::new(offered.w, dealt),
            };
            measure(&mut el.children[index], share, ctx)
        } else {
            sizes[position]
        };
        cross = cross.max(cross_of(size, axis));
    }

    match axis {
        Axis::Row => Size::new(asked, cross),
        Axis::Column => Size::new(cross, asked),
    }
}

/// The size a flowing container's children come to, once they have been broken
/// into lines.
///
/// As wide as its longest line and as tall as its lines stacked, which is why a
/// flowing container has to be measured against the width it will actually be
/// given: how many lines there are is a function of that width.
fn measure_flow<S>(el: &mut El<S>, inner: Size, ctx: &Ctx<'_>) -> Size {
    let gap = el.style.gap;
    let ink = el.ink;
    let mut sizes = Vec::with_capacity(el.children.len());
    for child in &mut el.children {
        child.ink = child.style.ink.over(ink);
        if child.style.layer.is_some() {
            continue;
        }
        sizes.push(measure(child, inner, ctx));
    }

    let lines = break_into_lines(&sizes, inner.w, gap);
    let widest = lines
        .iter()
        .map(|line| line_width(&sizes[line.clone()], gap))
        .fold(0.0_f32, f32::max);
    let height: f32 = lines.iter().map(|line| line_height(&sizes[line.clone()])).sum();
    let gaps = gap * lines.len().saturating_sub(1) as f32;
    Size::new(widest, height + gaps)
}

/// Splits children into the lines they fall onto, given a width to fill.
///
/// A child wider than the whole line still gets a line of its own rather than
/// none: refusing to place something that does not fit is how a layout comes to
/// draw nothing at all on a narrow window.
fn break_into_lines(sizes: &[Size], width: f32, gap: f32) -> Vec<std::ops::Range<usize>> {
    let mut lines = Vec::new();
    let mut start = 0;
    let mut used = 0.0_f32;
    for (index, size) in sizes.iter().enumerate() {
        let extra = if index == start { size.w } else { gap + size.w };
        if index > start && used + extra > width {
            lines.push(start..index);
            start = index;
            used = size.w;
        } else {
            used += extra;
        }
    }
    if start < sizes.len() {
        lines.push(start..sizes.len());
    }
    lines
}

/// How wide one line of a flow comes to, gaps included.
fn line_width(sizes: &[Size], gap: f32) -> f32 {
    sizes.iter().map(|size| size.w).sum::<f32>() + gap * sizes.len().saturating_sub(1) as f32
}

/// How tall one line of a flow is: as tall as the tallest thing on it.
fn line_height(sizes: &[Size]) -> f32 {
    sizes.iter().map(|size| size.h).fold(0.0_f32, f32::max)
}

/// Puts an element in `rect`, and everything inside it in what is left.
fn place<S>(el: &mut El<S>, rect: Rect, ctx: &Ctx<'_>, memory: &mut Memory) {
    el.rect = rect;
    if el.children.is_empty() {
        return;
    }

    // Identity and inherited text first, for every child at once. Both are
    // needed before a child can be measured, and a layer needs them exactly as
    // much as a child in the flow does.
    let (parent, ink) = (el.id, el.ink);
    for (index, child) in el.children.iter_mut().enumerate() {
        child.id = match &child.key {
            Some(key) => parent.with(key),
            None => parent.index(index),
        };
        child.ink = child.style.ink.over(ink);
    }

    let content = rect.inset(el.style.padding);
    if el.style.flow {
        flow(el, content, ctx, memory);
    } else {
        stack(el, content, ctx, memory);
    }
    layers(el, rect, ctx, memory);
}

/// Which children take part in their parent's stacking.
///
/// Everything except the layers, which are placed against the parent's edge
/// afterwards and take no room from it.
fn in_flow<S>(el: &El<S>) -> Vec<usize> {
    (0..el.children.len()).filter(|&index| el.children[index].style.layer.is_none()).collect()
}

/// Divides `content` between the children along the container's own axis.
fn stack<S>(el: &mut El<S>, content: Rect, ctx: &Ctx<'_>, memory: &mut Memory) {
    let (axis, gap, justify, align) = (el.style.axis, el.style.gap, el.style.justify, el.style.align);
    let offered = if el.scrolls {
        Size::new(content.w, UNBOUNDED)
    } else {
        Size::new(content.w, content.h)
    };
    let order = in_flow(el);

    // What each child asks for along the stacking axis, and what share of the
    // leftover it wants. A child that fills contributes nothing to the total,
    // which is what makes the leftover the thing there is to divide.
    let mut mains = Vec::with_capacity(order.len());
    let mut grows = Vec::with_capacity(order.len());
    for &index in &order {
        let child = &mut el.children[index];
        let length = main_length(child, axis);
        let grow = child.style.grow.unwrap_or_else(|| length.grow());
        let main = match length {
            // A grower's base is nothing — its share is its size — unless it
            // said its content comes first, in which case the share is only
            // ever added on top of what its words already need.
            _ if grow > 0.0 && child.style.grow_from_content => {
                main_of(measure(child, offered, ctx), axis)
            }
            _ if grow > 0.0 => 0.0,
            Length::Fixed(units) => units,
            Length::Fraction(share) => main_of(offered, axis) * share,
            Length::Auto | Length::Fill(_) => main_of(measure(child, offered, ctx), axis),
        };
        mains.push(clamp_main(child, main, axis));
        grows.push(grow);
    }

    let gaps = gap * order.len().saturating_sub(1) as f32;
    let taken: f32 = mains.iter().sum::<f32>() + gaps;
    let room = main_of(Size::new(content.w, content.h), axis);
    let spare = (room - taken).max(0.0);
    let total_grow: f32 = grows.iter().sum();

    if total_grow > 0.0 {
        distribute(&el.children, &order, &mut mains, &grows, axis, spare);
    }

    // A scrolling container is *expected* to hold more than it can show, so it
    // is the one place overflow is not a problem to be solved.
    let overflow = mains.iter().sum::<f32>() + gaps - room;
    if !el.scrolls && overflow > 0.0 {
        shrink(&el.children, &order, &mut mains, &grows, axis, overflow);
    }

    // Where the first child starts, and how much extra falls between each pair.
    let (mut cursor, spread) = match (justify, total_grow > 0.0) {
        (_, true) | (Justify::Start, _) => (0.0, 0.0),
        (Justify::Center, _) => (spare / 2.0, 0.0),
        (Justify::End, _) => (spare, 0.0),
        (Justify::Between, _) if order.len() > 1 => (0.0, spare / (order.len() - 1) as f32),
        (Justify::Between, _) => (0.0, 0.0),
    };
    cursor -= scroll_offset(el, content, &mains, gaps, memory);

    for (position, &index) in order.iter().enumerate() {
        let main = mains[position];
        let child = &mut el.children[index];
        let cross = cross_size(child, content, align, axis, offered, ctx);
        let across = child_align(child, align).offset(cross_of_rect(content, axis), cross);

        let child_rect = match axis {
            Axis::Row => Rect::new(content.x + cursor, content.y + across, main, cross),
            Axis::Column => Rect::new(content.x + across, content.y + cursor, cross, main),
        };
        cursor += main + gap + spread;
        place(child, child_rect, ctx, memory);
    }
}

/// Places children left to right, onto as many lines as they need.
///
/// Each child takes the size it asked for and nothing is stretched along the
/// line, because a flow is what you reach for when the *content* decides the
/// shape — a row of tags, a grid of cards. Growing is a statement about one
/// line's leftover room, and in a flow there is no such thing until the line
/// has been decided.
fn flow<S>(el: &mut El<S>, content: Rect, ctx: &Ctx<'_>, memory: &mut Memory) {
    let (gap, justify, align) = (el.style.gap, el.style.justify, el.style.align);
    let offered = Size::new(content.w, content.h);
    let order = in_flow(el);

    let mut sizes = Vec::with_capacity(order.len());
    for &index in &order {
        sizes.push(measure(&mut el.children[index], offered, ctx));
    }

    let mut y = content.y;
    for line in break_into_lines(&sizes, content.w, gap) {
        let height = line_height(&sizes[line.clone()]);
        let spare = (content.w - line_width(&sizes[line.clone()], gap)).max(0.0);
        let count = line.len();
        let (mut x, spread) = match justify {
            Justify::Start => (content.x, 0.0),
            Justify::Center => (content.x + spare / 2.0, 0.0),
            Justify::End => (content.x + spare, 0.0),
            Justify::Between if count > 1 => (content.x, spare / (count - 1) as f32),
            Justify::Between => (content.x, 0.0),
        };

        for position in line {
            let size = sizes[position];
            let child = &mut el.children[order[position]];
            // A child that states no height of its own is stretched to its
            // line, so a row of tags of different text sizes still comes out as
            // a row rather than as a ragged edge.
            let tall = match child_align(child, align) {
                Align::Stretch => height,
                _ => size.h,
            };
            let down = child_align(child, align).offset(height, tall);
            place(child, Rect::new(x, y + down, size.w, tall), ctx, memory);
            x += size.w + gap + spread;
        }
        y += height + gap;
    }
}

/// Places the children that were lifted out of the flow.
fn layers<S>(el: &mut El<S>, anchor: Rect, ctx: &Ctx<'_>, memory: &mut Memory) {
    let window = ctx.bounds;
    for index in 0..el.children.len() {
        let Some(placement) = el.children[index].style.layer else {
            continue;
        };
        let child = &mut el.children[index];
        // Measured against the whole window rather than against the anchor: a
        // menu is as wide as its longest item, and the button it hangs from has
        // nothing to say about that.
        let size = match placement {
            Anchor::Over => anchor.size(),
            _ => measure(child, window.size(), ctx),
        };
        place(child, anchored(placement, anchor, size, window), ctx, memory);
    }
}

/// Where a layer of this size sits against its anchor, held inside the window.
///
/// Held rather than allowed off the edge, because the alternative is a menu
/// opened next to the right-hand edge of a window drawing half of itself
/// outside it, which is a bug the application cannot fix from where it is.
fn anchored(placement: Anchor, anchor: Rect, size: Size, window: Rect) -> Rect {
    let origin = match placement {
        Anchor::Over => anchor.origin(),
        Anchor::Below => Point::new(anchor.x, anchor.max_y()),
        Anchor::Above => Point::new(anchor.x, anchor.y - size.h),
        Anchor::After => Point::new(anchor.max_x(), anchor.y),
        Anchor::Before => Point::new(anchor.x - size.w, anchor.y),
        Anchor::Center => Point::new(
            window.x + (window.w - size.w) / 2.0,
            window.y + (window.h - size.h) / 2.0,
        ),
    };
    let x = origin.x.min(window.max_x() - size.w).max(window.x);
    let y = origin.y.min(window.max_y() - size.h).max(window.y);
    Rect::new(x, y, size.w, size.h)
}

/// How many passes dividing room may take before the remainder is let be.
const PASSES: usize = 4;

/// Below this a remainder is not worth another pass, or another pixel.
const SETTLED: f32 = 0.5;

/// Deals `spare` out to the children that grow, honouring each one's maximum.
///
/// Dealt repeatedly rather than in one round: a grower that hits its stated
/// maximum leaves the rest of its share unclaimed, and one round would strand
/// that remainder as dead room in the middle of the row — a gap after a capped
/// button that the rule beside it was drawn to fill. The siblings that still
/// have headroom are offered it again, so the only way room goes unspent is
/// every grower being at its cap, which is the one case where it truly is
/// spare.
fn distribute<S>(
    children: &[El<S>],
    order: &[usize],
    mains: &mut [f32],
    grows: &[f32],
    axis: Axis,
    spare: f32,
) {
    let mut left = spare;
    for _ in 0..PASSES {
        let open: Vec<usize> = (0..order.len())
            .filter(|&position| {
                grows[position] > 0.0
                    && mains[position] < maximum(&children[order[position]], axis)
            })
            .collect();
        let weight: f32 = open.iter().map(|&position| grows[position]).sum();
        if left <= SETTLED || open.is_empty() || weight <= 0.0 {
            return;
        }

        let mut given = 0.0;
        for &position in &open {
            let share = left * grows[position] / weight;
            let headroom = maximum(&children[order[position]], axis) - mains[position];
            let taken = share.min(headroom);
            mains[position] += taken;
            given += taken;
        }
        left -= given;
    }
}

/// Takes `deficit` back off the children that can afford to give it up.
///
/// The ones sized to their content give first: a control that asked for a
/// height in units asked for it because that is how tall it has to be, and a
/// row of buttons squashed to nineteen units is worse than a list showing one
/// fewer row. What shrinks first is what was going to be scrolled or wrapped
/// anyway. Only when they are spent do the growers give back what they were
/// dealt, down to their own minimums — room they were sharing anyway, taken
/// back by the same rule it was handed out under.
///
/// Taken proportionally, so a block twice the size of another gives up twice as
/// much, and repeated: a child that hits its own minimum stops giving, and what
/// it could not give has to come from the others rather than being dropped.
fn shrink<S>(
    children: &[El<S>],
    order: &[usize],
    mains: &mut [f32],
    grows: &[f32],
    axis: Axis,
    deficit: f32,
) {
    // The all-or-nothing children go first, and entirely. An element that
    // said `whole` is never drawn squeezed, so the moment there is a deficit
    // at all it hands over everything it measured — and if that is more than
    // the deficit asked for, the surplus is dealt back out to the growers
    // rather than stranded as a hole where the element stood.
    let mut left = deficit;
    for position in 0..order.len() {
        if left <= SETTLED {
            break;
        }
        if children[order[position]].style.whole && mains[position] > 0.0 {
            left -= mains[position];
            mains[position] = 0.0;
        }
    }
    if left < -SETTLED {
        distribute(children, order, mains, grows, axis, -left);
        return;
    }

    let content_sized = |position: usize| {
        let child = &children[order[position]];
        grows[position] == 0.0 && matches!(main_length(child, axis), Length::Auto)
    };
    let left = reclaim(children, order, mains, axis, left, content_sized);
    if left > SETTLED {
        reclaim(children, order, mains, axis, left, |position| grows[position] > 0.0);
    }
}

/// Takes up to `deficit` off the `eligible` children, floored at each one's
/// minimum, and answers what could not be taken.
fn reclaim<S>(
    children: &[El<S>],
    order: &[usize],
    mains: &mut [f32],
    axis: Axis,
    deficit: f32,
    eligible: impl Fn(usize) -> bool,
) -> f32 {
    let mut left = deficit;
    for _ in 0..PASSES {
        let flexible: Vec<usize> = (0..order.len())
            .filter(|&position| {
                eligible(position)
                    && mains[position] > minimum(&children[order[position]], axis)
            })
            .collect();
        let total: f32 = flexible.iter().map(|&position| mains[position]).sum();
        if left <= SETTLED || flexible.is_empty() || total <= 0.0 {
            return left;
        }

        let mut given = 0.0;
        for &position in &flexible {
            let share = left * mains[position] / total;
            let floor = minimum(&children[order[position]], axis);
            let taken = share.min(mains[position] - floor);
            mains[position] -= taken;
            given += taken;
        }
        left -= given;
    }
    left
}

/// The smallest a child may be laid out along `axis`.
fn minimum<S>(child: &El<S>, axis: Axis) -> f32 {
    match axis {
        Axis::Row => child.style.min_width,
        Axis::Column => child.style.min_height,
    }
}

/// The largest it may be.
fn maximum<S>(child: &El<S>, axis: Axis) -> f32 {
    match axis {
        Axis::Row => child.style.max_width,
        Axis::Column => child.style.max_height,
    }
}

/// How far a scrolling container has been scrolled, clamped to its content.
///
/// Answers zero for everything else. The content's height is measured here and
/// remembered, because that is the only moment it is known: an interface
/// described afresh each frame does not know how tall a list is until it has
/// laid it out.
fn scroll_offset<S>(
    el: &El<S>,
    content: Rect,
    mains: &[f32],
    gaps: f32,
    memory: &mut Memory,
) -> f32 {
    if !el.scrolls {
        return 0.0;
    }
    let height: f32 = mains.iter().sum::<f32>() + gaps;
    memory.set_content_height(el.id, height);
    let overflow = (height - content.h).max(0.0);

    // An area that follows its content sits at the end for as long as the reader
    // has not scrolled away from it. Deciding that here is what makes the tail
    // keep up as lines arrive: the end moves every time the content grows, and
    // an offset the application set a frame ago would already be short of it.
    let offset = if el.follows && memory.is_following(el.id) {
        whole_child_at_top(mains, el.style.gap, overflow)
    } else {
        memory.scroll_offset(el.id).clamp(0.0, overflow)
    };
    memory.set_scroll_offset(el.id, offset);
    offset
}

/// Where a tail sits so that the child at the top of the view is a whole one.
///
/// The end of the content is a distance in pixels, and it almost never falls on
/// the join between two children — so an area anchored exactly there puts the
/// bottom of its content against the bottom of the frame and pays for it at the
/// top, where whatever is left over is a child sliced through. In a log that is
/// half a line: the descenders of a message whose own text is above the frame,
/// which reads as a rendering fault rather than as more output.
///
/// So the tail is pulled down to the next join instead. What that costs is a
/// strip under the newest line, never taller than one child, which is the shape
/// a terminal has for the same reason — and a gap where the next line will
/// appear says something true, while half a line says nothing at all.
///
/// Falls back to `overflow` when a single child is taller than the frame, where
/// there is no join to sit on and showing the end of it is the whole point.
fn whole_child_at_top(mains: &[f32], gap: f32, overflow: f32) -> f32 {
    let mut start = 0.0;
    for main in mains {
        if start >= overflow {
            return start;
        }
        start += main + gap;
    }
    overflow
}

/// How wide, or tall, a child is across the direction it was stacked in.
fn cross_size<S>(
    child: &mut El<S>,
    content: Rect,
    align: Align,
    axis: Axis,
    offered: Size,
    ctx: &Ctx<'_>,
) -> f32 {
    let available = cross_of_rect(content, axis);
    let length = cross_length(child, axis);
    let size = match length {
        Length::Fixed(units) => units,
        Length::Fraction(share) => available * share,
        Length::Fill(_) => available,
        Length::Auto if child_align(child, align) == Align::Stretch => available,
        // Held to the room there is. A child sized to its content and wider
        // than what holds it would be a rectangle outside the box that owns
        // it, which is the one thing this layout does not allow — a label
        // overrunning its panel is drawn cut short, not drawn over the panel
        // beside it. A child that *stated* a size keeps it, exactly as a
        // stated size is what shrinking never takes from.
        Length::Auto => cross_of(measure(child, offered, ctx), axis).min(available),
    };
    clamp_cross(child, size, axis)
}

/// Which alignment applies to a child: its own, or its parent's.
fn child_align<S>(child: &El<S>, parent: Align) -> Align {
    child.style.self_align.unwrap_or(parent)
}

/// The length a child asks for along `axis`.
fn main_length<S>(child: &El<S>, axis: Axis) -> Length {
    match axis {
        Axis::Row => child.style.width,
        Axis::Column => child.style.height,
    }
}

/// The length it asks for across `axis`.
fn cross_length<S>(child: &El<S>, axis: Axis) -> Length {
    match axis {
        Axis::Row => child.style.height,
        Axis::Column => child.style.width,
    }
}

/// Holds a main-axis size within the child's own bounds.
fn clamp_main<S>(child: &El<S>, size: f32, axis: Axis) -> f32 {
    match axis {
        Axis::Row => size.clamp(child.style.min_width, child.style.max_width),
        Axis::Column => size.clamp(child.style.min_height, child.style.max_height),
    }
}

/// The same, across the axis.
fn clamp_cross<S>(child: &El<S>, size: f32, axis: Axis) -> f32 {
    match axis {
        Axis::Row => size.clamp(child.style.min_height, child.style.max_height),
        Axis::Column => size.clamp(child.style.min_width, child.style.max_width),
    }
}

/// The component of a size that lies along `axis`.
fn main_of(size: Size, axis: Axis) -> f32 {
    match axis {
        Axis::Row => size.w,
        Axis::Column => size.h,
    }
}

/// The component that lies across it.
fn cross_of(size: Size, axis: Axis) -> f32 {
    match axis {
        Axis::Row => size.h,
        Axis::Column => size.w,
    }
}

/// The extent of a rectangle across `axis`.
fn cross_of_rect(rect: Rect, axis: Axis) -> f32 {
    match axis {
        Axis::Row => rect.h,
        Axis::Column => rect.w,
    }
}

/// What a length says without having to ask the content, or `None` when it can
/// only be answered by measuring.
fn stated_length(length: Length, avail: f32) -> Option<f32> {
    match length {
        Length::Fixed(units) => Some(units),
        Length::Fraction(share) => Some(avail * share),
        Length::Auto | Length::Fill(_) => None,
    }
}

/// What a length comes to, given what the content needs and what is on offer.
fn resolve(length: Length, content: f32, avail: f32) -> f32 {
    match length {
        Length::Auto => content,
        Length::Fixed(units) => units,
        Length::Fraction(share) => avail * share,
        Length::Fill(_) => avail.max(content),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::style::Tone;
    use crate::text::FontId;
    use crate::{col, row, spacer, text};

    /// A state for trees that do nothing.
    struct Nothing;

    /// A context with no faces loaded.
    ///
    /// Text measures as nothing wide, which is exactly what is wanted here: what
    /// these assert is how room is *divided*, and a division that depended on
    /// which font the machine running the test happens to have is not a property
    /// worth asserting.
    fn context() -> (Fonts, Theme) {
        (Fonts::new(), Theme::new(crate::theme::Appearance::Dark, FontId::FIRST, FontId::FIRST))
    }

    /// Lays a tree out in a rectangle and answers it, ready to be inspected.
    fn laid_out(mut tree: El<Nothing>, width: f32, height: f32) -> El<Nothing> {
        let (fonts, theme) = context();
        let bounds = Rect::new(0.0, 0.0, width, height);
        let ctx = Ctx { fonts: &fonts, theme: &theme, bounds };
        let mut memory = Memory::new();
        solve(&mut tree, bounds, &ctx, &mut memory);
        tree
    }

    #[test]
    fn fixed_children_take_exactly_what_they_asked_for() {
        let tree = laid_out(
            col((spacer().h(30.0), spacer().h(50.0))).gap(10.0),
            100.0,
            200.0,
        );
        assert_eq!(tree.children[0].rect, Rect::new(0.0, 0.0, 100.0, 30.0));
        assert_eq!(tree.children[1].rect, Rect::new(0.0, 40.0, 100.0, 50.0));
    }

    #[test]
    fn what_is_left_over_is_divided_between_the_fillers_in_proportion() {
        let tree = laid_out(
            row((spacer().w(40.0), spacer().grow(), spacer().grow_by(3.0))),
            240.0,
            50.0,
        );
        // 200 spare, split one part to three.
        assert_eq!(tree.children[1].rect.w, 50.0);
        assert_eq!(tree.children[2].rect.w, 150.0);
        assert_eq!(tree.children[2].rect.max_x(), 240.0, "the row should be filled exactly");
    }

    #[test]
    fn padding_is_taken_off_before_children_are_placed() {
        let tree = laid_out(col(spacer().grow()).pad(12.0), 100.0, 100.0);
        assert_eq!(tree.children[0].rect, Rect::new(12.0, 12.0, 76.0, 76.0));
    }

    #[test]
    fn a_child_that_grows_leaves_nothing_for_justification_to_move() {
        let packed = laid_out(row((spacer().w(20.0), spacer().w(20.0))).justify(Justify::End), 100.0, 10.0);
        assert_eq!(packed.children[0].rect.x, 60.0);

        let filled = laid_out(row((spacer().grow(), spacer().w(20.0))).justify(Justify::End), 100.0, 10.0);
        assert_eq!(filled.children[0].rect.x, 0.0, "a filler already took the spare room");
    }

    #[test]
    fn spare_room_is_spread_between_children_rather_than_around_them() {
        let tree = laid_out(
            row((spacer().w(20.0), spacer().w(20.0), spacer().w(20.0))).justify(Justify::Between),
            120.0,
            10.0,
        );
        assert_eq!(tree.children[0].rect.x, 0.0);
        assert_eq!(tree.children[1].rect.x, 50.0);
        assert_eq!(tree.children[2].rect.max_x(), 120.0);
    }

    #[test]
    fn a_child_is_stretched_across_the_axis_unless_it_says_otherwise() {
        let stretched = laid_out(col(spacer().h(10.0)), 100.0, 100.0);
        assert_eq!(stretched.children[0].rect.w, 100.0);

        let sized = laid_out(col(spacer().size(30.0, 10.0)), 100.0, 100.0);
        assert_eq!(sized.children[0].rect.w, 30.0);
    }

    #[test]
    fn alignment_places_a_child_across_the_stacking_axis() {
        let tree = laid_out(col(spacer().size(20.0, 10.0)).align(Align::Center), 100.0, 100.0);
        assert_eq!(tree.children[0].rect.x, 40.0);

        let tree = laid_out(col(spacer().size(20.0, 10.0)).align(Align::End), 100.0, 100.0);
        assert_eq!(tree.children[0].rect.x, 80.0);
    }

    #[test]
    fn a_minimum_is_honoured_even_when_the_room_is_not_there() {
        let tree = laid_out(row(spacer().grow().min_w(200.0)), 100.0, 40.0);
        assert_eq!(tree.children[0].rect.w, 200.0);
    }

    #[test]
    fn a_maximum_stops_a_filler_from_taking_everything() {
        let tree = laid_out(row(spacer().grow().max_w(60.0)), 400.0, 40.0);
        assert_eq!(tree.children[0].rect.w, 60.0);
    }

    #[test]
    fn identity_follows_the_key_rather_than_the_position() {
        let first = laid_out(col((text("a").key("alpha"), text("b").key("beta"))), 100.0, 100.0);
        let swapped = laid_out(col((text("b").key("beta"), text("a").key("alpha"))), 100.0, 100.0);
        assert_eq!(first.children[0].id, swapped.children[1].id, "the keyed row kept its identity");
    }

    #[test]
    fn identity_without_a_key_is_the_path_through_the_tree() {
        let tree = laid_out(col((text("a"), col(text("b")))), 100.0, 100.0);
        assert_ne!(tree.children[0].id, tree.children[1].id);
        assert_ne!(tree.children[1].id, tree.children[1].children[0].id);
    }

    #[test]
    fn a_scrolling_area_remembers_how_tall_its_contents_came_out() {
        let (fonts, theme) = context();
        let ctx = Ctx { fonts: &fonts, theme: &theme, bounds: Rect::new(0.0, 0.0, 100.0, 100.0) };
        let mut memory = Memory::new();
        let mut tree: El<Nothing> =
            col((0..10).map(|_| spacer().h(30.0)).collect::<Vec<_>>()).scroll();

        solve(&mut tree, Rect::new(0.0, 0.0, 100.0, 100.0), &ctx, &mut memory);
        assert_eq!(memory.content_height(tree.id), 300.0);

        // Scrolled further than there is content: the offset is held at the end
        // rather than letting the list be dragged off the top of its own frame.
        memory.set_scroll_offset(tree.id, 900.0);
        solve(&mut tree, Rect::new(0.0, 0.0, 100.0, 100.0), &ctx, &mut memory);
        assert_eq!(memory.scroll_offset(tree.id), 200.0);
        assert_eq!(tree.children[0].rect.y, -200.0);
    }

    #[test]
    fn a_tail_stops_on_a_whole_child_rather_than_slicing_the_one_at_the_top() {
        let (fonts, theme) = context();
        let ctx = Ctx { fonts: &fonts, theme: &theme, bounds: Rect::new(0.0, 0.0, 100.0, 100.0) };
        let mut memory = Memory::new();
        let mut tree: El<Nothing> =
            col((0..10).map(|_| spacer().h(30.0)).collect::<Vec<_>>()).follow();

        // Three hundred units of content in a hundred-unit frame. Anchored to
        // the pixel the tail would sit at 200 and cut the fourth-from-last child
        // through the middle; the join above it is at 210.
        solve(&mut tree, Rect::new(0.0, 0.0, 100.0, 100.0), &ctx, &mut memory);
        assert_eq!(memory.scroll_offset(tree.id), 210.0);
        assert_eq!(tree.children[7].rect.y, 0.0, "the top of the frame is the top of a child");
        assert_eq!(tree.children[9].rect.max_y(), 90.0, "and what it costs is under the last");
    }

    #[test]
    fn a_tail_whose_content_is_one_tall_child_still_shows_the_end_of_it() {
        let (fonts, theme) = context();
        let ctx = Ctx { fonts: &fonts, theme: &theme, bounds: Rect::new(0.0, 0.0, 100.0, 100.0) };
        let mut memory = Memory::new();
        let mut tree: El<Nothing> = col(spacer().h(250.0)).follow();

        // No join to sit on. Snapping to the only one there is would put the
        // start of the child at the top, which is the opposite of following it.
        solve(&mut tree, Rect::new(0.0, 0.0, 100.0, 100.0), &ctx, &mut memory);
        assert_eq!(memory.scroll_offset(tree.id), 150.0);
    }

    #[test]
    fn text_that_wraps_is_as_tall_as_the_lines_it_takes() {
        // Without a face loaded every glyph is nothing wide, so a wrapped run is
        // one line; what this pins is that the height comes from the line count
        // and the tree still lays out rather than producing a NaN.
        let tree = laid_out(col(text("a paragraph of prose").wrap()).pad(8.0), 120.0, 200.0);
        let paragraph = &tree.children[0];
        assert!(paragraph.rect.h >= 0.0);
        assert_eq!(paragraph.rect.w, 104.0, "a wrapping run fills the width it was offered");
    }

    #[test]
    fn a_tone_set_on_a_container_reaches_the_text_inside_it() {
        let tree = laid_out(col(col(text("deep"))).color(Tone::Muted), 100.0, 100.0);
        assert_eq!(tree.children[0].children[0].ink.tone, Tone::Muted);
    }
}

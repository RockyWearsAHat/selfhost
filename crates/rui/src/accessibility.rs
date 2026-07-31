//! What an interface *means*, for anything that cannot see it.
//!
//! The decision this module exists to hold, stated once so it can be pushed and
//! kept:
//!
//! > **Every [`El`] carries a [`Role`]. The tree of elements *is* the
//! > accessibility tree — no parallel structure, and no annotations bolted on
//! > afterwards. A screen reader and a mouse reach the same handlers by the
//! > same path.**
//!
//! Nothing here is a second description of the interface. Everything an
//! assistive technology is told is read off the description that was already
//! built, laid out, and drawn:
//!
//! | fact | where it already was |
//! |---|---|
//! | identity | [`Id`], derived from the element's path, named by [`El::key`] |
//! | role | set by every constructor in [`widgets`](crate::widgets); [`El::role`] is the escape |
//! | name | the words in the subtree — see *name from contents* below |
//! | value | a field's own text, or whatever [`El::value`] was told |
//! | state | [`El::is_disabled`], `focusable` + [`Memory::focused`](crate::Memory::focused), [`El::selected`] |
//! | bounds | the rectangle the layout gave it |
//! | structure | which roles contain which — a [`Role::Tab`] inside a [`Role::TabList`] |
//!
//! # The name comes from the hierarchy, not from the author
//!
//! An interactive element's accessible name is the concatenated text of its
//! subtree, which is exactly HTML's *accessible name computation from
//! contents*. `button("Restart")` is named "Restart" with nothing written at
//! the call site, and a row of a dot, a service's name, and its state is named
//! after the words it shows. [`El::label`] is the override, and is needed only
//! for a control with no words of its own — an icon button, a switch, a slider
//! built out of [`draw`](crate::widgets::draw).
//!
//! A field is the exception: its own text is its *value*, never its name, so a
//! field is named by [`El::label`] — which [`field_row`](crate::field_row)
//! applies for it, because a row that pairs a heading with a value is what a
//! `<label for>` is.
//!
//! # The structure comes from role containment
//!
//! A [`Role::Tab`] whose parent is a [`Role::TabList`] gets its position in the
//! set and the size of that set for free, and [`tabs`](crate::tabs) already
//! builds exactly that shape. The parent already knows what its children are;
//! hierarchy does here what ARIA attributes do by hand on the web.
//!
//! # Emission is a frame-to-frame diff
//!
//! [`AccessTree`] is built each frame through the observer in
//! [`App::frame_observed`](crate::App), compared against the previous frame's,
//! and only the difference is emitted. That is philosophically the same
//! decision the renderer makes when it presents a frame only if it differs from
//! the one on screen: *compare the finished result, do not track what you think
//! is dirty*. A system that works out which node changed can work it out
//! wrongly, and the symptom is a screen reader announcing something that is no
//! longer true.
//!
//! # One path from intent to handler
//!
//! **Invariant.** An activation from an assistive technology resolves an [`Id`]
//! to a node and runs the same [`El::click_action`] a click would; an edit runs
//! the same [`El::input_action`] typing would; a key runs the same
//! [`El::key_action`]. There is no second dispatch, so an interface can never
//! behave differently for a screen reader than it does for a mouse. Anything
//! that would need a separate handler for assistive technology is a defect in
//! this seam, not a feature.
//!
//! ## How that is held, rather than promised
//!
//! An activation arrives as [`Event::Activated`](crate::Event::Activated),
//! carrying the [`Id`] the platform was given here. A backend pushes it through
//! `pump` the way it pushes a click — so the seam did not have to widen for
//! this, and a backend still only ever reports what happened.
//! [`Input`](crate::Input) folds
//! it into the frame beside the pointer and the keys, and the frame answers it
//! in the *one* place a click is decided: an element is clicked if a press
//! ended on it, or Space or Enter reached it while focused, or an assistive
//! technology named it. All three set the same flag and reach the same
//! `on_click`, which is why `tests/accessibility.rs` can assert that both
//! routes leave the application in the same state.
//!
//! What deliberately does *not* have a route, and why — each of these would
//! have to invent something the interface never said:
//!
//! - **Increment and decrement**, which a platform offers for a
//!   [`Role::Slider`]. A slider here is [`draw`](crate::widgets::draw) with an
//!   [`El::on_drag`] on it: the value lives in the application's state, this
//!   library never sees it, and a [`Drag`](crate::Drag) reports a *position*.
//!   Answering an increment would mean choosing a step, and then a position
//!   that produces it — a value decided in this module rather than by the
//!   control. That is a second interaction wearing the first one's name. The
//!   route becomes honest the day an element tells the library its range, and
//!   not before.
//! - **Setting a value** on a [`Role::Field`]. [`El::input_action`] would take
//!   it faithfully — a platform hands over a whole new string and so does
//!   typing — but it would buy no capability that is missing: a field is
//!   already reachable, focusable, and typable through routes that exist, and
//!   an assistive technology edits one by focusing it and typing. A second way
//!   into the same handler is exactly what this seam is for avoiding.
//!
//! [`AccessActions`] still reports both `set_value` and `drag`, because they
//! say what the *node* carries. What a platform may ask for is narrower, and
//! each backend is what decides that.
//!
//! # The platform seam
//!
//! [`AccessUpdate`] is defined here, above the backend, and is plain data.
//! The platform layer implements exactly one method against it, whose contract
//! is:
//!
//! ```ignore
//! /// Hands the platform the accessibility nodes that changed since the last frame.
//! ///
//! /// A diff and not the whole tree, for the reason `present` sends a frame only
//! /// when it differs: an interface spends most of its life unchanged, and pushing
//! /// an identical tree every frame costs the assistive technology, not us.
//! fn update_accessibility(&self, update: &AccessUpdate) -> Result<(), Error>;
//! ```
//!
//! A backend receives [`AccessUpdate::changed`] (nodes that are new or
//! different, each carrying its own parent), [`AccessUpdate::removed`] (nodes
//! that are gone), and the focus, and maintains its own map from [`Id`] to
//! whatever the platform's object model needs. When
//! [`AccessUpdate::structure_changed`] is set, the shape of the tree moved and
//! not merely its contents — which is when macOS wants
//! `NSAccessibilityLayoutChangedNotification` posted.
//!
//! # What this deliberately does not do
//!
//! - **It does not name pictures.** A [`Role::Image`] with no label is left
//!   alone rather than reported, because most drawing in an interface is
//!   decorative — the box beside a checkbox's word, the rule under a tab — and
//!   a rule that demanded a name for each would be answered with noise. A
//!   picture that carries meaning must be given [`El::label`] by its author.
//! - **It does not describe.** There is a name and a value and no separate
//!   description field, because a second string that nobody is required to fill
//!   in is a second string nobody fills in.

use crate::element::{El, Node};
use crate::geom::Rect;
use crate::memory::Id;
use std::collections::HashMap;
use std::fmt;

/// What an element *is*, as far as anything that cannot see it is concerned.
///
/// Defaulted from the kind of element — a stack is a [`Role::Group`], a run of
/// text is [`Role::Text`], an editable line is [`Role::Field`], and an
/// application's own drawing is [`Role::Image`] — and then set deliberately by
/// every constructor in [`widgets`](crate::widgets). [`El::role`] is the escape
/// for anything hand-built out of [`draw`](crate::widgets::draw).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub enum Role {
    /// A box that holds other things and means nothing on its own.
    ///
    /// The default, and the one role an interactive element may never keep:
    /// a group that answers a click is a control nobody has named.
    #[default]
    Group,
    /// A run of words.
    Text,
    /// Words that name something beside them.
    Label,
    /// The name of a section, a pane, or the thing a screen is about.
    Heading,
    /// Something that does what it says when it is activated.
    Button,
    /// An editable line of text.
    Field,
    /// A sequence of items of the same kind.
    List,
    /// One item of such a sequence.
    ListItem,
    /// A row of tabs, one of which is chosen.
    TabList,
    /// One tab of such a row.
    Tab,
    /// A quantity shown against a scale.
    Meter,
    /// A rule dividing what is above it from what is below.
    Separator,
    /// How something is doing, shown as a word, a tag, or a dot.
    Status,
    /// A window within the window, which holds attention until it is answered.
    Dialog,
    /// A list of commands that has opened.
    Menu,
    /// One command of such a list.
    MenuItem,
    /// A picture, a diagram, a mark.
    Image,
    /// Something that is either on or off.
    Checkbox,
    /// One of several alternatives, exactly one of which is taken.
    Radio,
    /// A value chosen from a continuous range.
    Slider,
}

impl Role {
    /// Whether this role takes its name from the words inside it.
    ///
    /// HTML's own division: a button, a tab, or a heading is named by what it
    /// says, and a field or a picture is not — a field's words are its value,
    /// and a picture has none.
    pub fn names_from_contents(self) -> bool {
        matches!(
            self,
            Self::Text
                | Self::Label
                | Self::Heading
                | Self::Button
                | Self::ListItem
                | Self::Tab
                | Self::Status
                | Self::MenuItem
                | Self::Checkbox
                | Self::Radio
                | Self::Dialog
        )
    }

    /// The role this one has to sit inside, if it only means something there.
    ///
    /// A tab outside a tab list, or an item outside a list, is a structure that
    /// says one thing to the eye and another to a screen reader. Containment is
    /// also where a position in a set comes from, so the two questions have one
    /// answer.
    pub fn container(self) -> Option<Self> {
        match self {
            Self::Tab => Some(Self::TabList),
            Self::ListItem => Some(Self::List),
            Self::MenuItem => Some(Self::Menu),
            _ => None,
        }
    }
}

/// What is true of a node right now, as against what it is.
///
/// Every field is read from state the library already keeps, so none of it can
/// drift out of step with what is drawn.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct AccessState {
    /// It is drawn dimmed and ignores every event.
    pub disabled: bool,
    /// It takes the keyboard, and a place in the tab order.
    pub focusable: bool,
    /// It has the keyboard right now.
    pub focused: bool,
    /// Whether it is the chosen one of its group, when that is a question that
    /// applies to it at all.
    ///
    /// Set by [`El::selected`] and never inferred from a colour: a selected row
    /// and a hovered row can be drawn the same way in a theme somebody writes
    /// tomorrow, and a colour was never a semantic.
    pub selected: Option<bool>,
}

/// Which of the library's handlers a node actually carries.
///
/// The outer bound on what an assistive technology may ask of this node:
/// nothing outside this list resolves to a handler at all. What a platform may
/// actually ask for today is narrower — see the module's invariant for which
/// of these have a route and why the rest deliberately do not.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct AccessActions {
    /// It can be activated: [`El::click_action`].
    pub press: bool,
    /// Its text can be replaced: [`El::input_action`].
    pub set_value: bool,
    /// It answers keys of its own: [`El::key_action`].
    pub keys: bool,
    /// It answers a pointer held and moved within it: [`El::drag_action`].
    pub drag: bool,
}

impl AccessActions {
    /// Whether a person can do anything to this node at all.
    pub fn any(self) -> bool {
        self.press || self.set_value || self.keys || self.drag
    }
}

/// One node of the accessibility tree: plain data, and nothing borrowed.
///
/// The same five facts every platform's accessibility interface asks for —
/// role, name, value, state, bounds — plus the parent link the tree is rebuilt
/// from and the actions the node answers to.
#[derive(Debug, Clone, PartialEq)]
pub struct AccessNode {
    /// Its identity, stable from frame to frame; see [`Id`].
    pub id: Id,
    /// What holds it, or `None` for the root.
    pub parent: Option<Id>,
    /// What it is.
    pub role: Role,
    /// What it is called, computed from its subtree or set by [`El::label`].
    pub name: String,
    /// What it holds, for the roles that hold something.
    pub value: Option<String>,
    /// What is true of it right now.
    pub state: AccessState,
    /// Where the layout put it, in logical units.
    pub bounds: Rect,
    /// Which of its containing set it is, counting from one.
    pub position_in_set: Option<usize>,
    /// How many are in that set.
    pub set_size: Option<usize>,
    /// What it can be asked to do.
    pub actions: AccessActions,
}

impl AccessNode {
    /// Whether a person can reach this node with a pointer or the keyboard.
    ///
    /// What the enforcement in [`audit`] is about: everything true here has to
    /// have a role of its own and a name, or it is a control that exists for
    /// people who can see it and for nobody else.
    pub fn is_interactive(&self) -> bool {
        !self.state.disabled && (self.actions.any() || self.state.focusable)
    }
}

/// Every node of one frame, in the order the frame drew them.
///
/// Parents come before their children, so a platform can rebuild the tree by
/// walking this once. Built by the observer in
/// [`App::frame_observed`](crate::App) rather than by a traversal of its own —
/// there is one walk of the tree per frame and everything reads off it.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct AccessTree {
    nodes: Vec<AccessNode>,
    focused: Option<Id>,
}

impl AccessTree {
    /// An empty tree: what an interface that has never been drawn amounts to.
    pub fn new() -> Self {
        Self::default()
    }

    /// Every node, parents before children.
    pub fn nodes(&self) -> &[AccessNode] {
        &self.nodes
    }

    /// The node with this identity, if the last frame drew it.
    pub fn node(&self, id: Id) -> Option<&AccessNode> {
        self.nodes.iter().find(|node| node.id == id)
    }

    /// What is inside the node with this identity, in order.
    pub fn children_of(&self, parent: Id) -> impl Iterator<Item = &AccessNode> {
        self.nodes.iter().filter(move |node| node.parent == Some(parent))
    }

    /// What has the keyboard, if anything.
    pub fn focused(&self) -> Option<Id> {
        self.focused
    }

    /// Records one laid-out element and its parent.
    ///
    /// Called for every element of the frame, in drawing order. The name is
    /// computed here because this is the one moment the subtree is still alive.
    pub(crate) fn push<S>(&mut self, el: &El<S>, parent: Option<Id>) {
        let role = el.accessibility_role();
        self.nodes.push(AccessNode {
            id: el.id,
            parent,
            role,
            name: el.accessible_name(),
            value: value_of(el),
            state: AccessState {
                disabled: el.is_disabled(),
                focusable: el.focusable,
                focused: false,
                selected: el.is_selected(),
            },
            bounds: el.rect,
            position_in_set: None,
            set_size: None,
            actions: AccessActions {
                press: el.click_action().is_some(),
                set_value: el.input_action().is_some(),
                keys: el.key_action().is_some(),
                drag: el.drag_action().is_some(),
            },
        });
    }

    /// Settles what only the finished frame knows: focus, and set positions.
    ///
    /// A position in a set is not a property of a node but of its place among
    /// its siblings, so it cannot be known until they have all been seen.
    pub(crate) fn finish(&mut self, focused: Option<Id>) {
        self.focused = focused;
        if let Some(id) = focused {
            if let Some(node) = self.nodes.iter_mut().find(|node| node.id == id) {
                node.state.focused = true;
            }
        }

        let mut totals: HashMap<(Id, Role), usize> = HashMap::new();
        for node in self.nodes.iter().filter(|node| node.role.container().is_some()) {
            if let Some(parent) = node.parent {
                *totals.entry((parent, node.role)).or_default() += 1;
            }
        }

        let mut seen: HashMap<(Id, Role), usize> = HashMap::new();
        for node in self.nodes.iter_mut().filter(|node| node.role.container().is_some()) {
            let Some(parent) = node.parent else { continue };
            let position = seen.entry((parent, node.role)).or_default();
            *position += 1;
            node.position_in_set = Some(*position);
            node.set_size = totals.get(&(parent, node.role)).copied();
        }
    }

    /// What changed between the frame before this one and this one.
    ///
    /// The whole of the emission policy: an interface spends most of its life
    /// unchanged, and an assistive technology handed an identical tree sixty
    /// times a second pays for it. See the module's note on why this is the
    /// same decision as presenting a frame only when it differs.
    pub fn diff(&self, previous: &Self) -> AccessUpdate {
        let before: HashMap<Id, &AccessNode> =
            previous.nodes.iter().map(|node| (node.id, node)).collect();

        let mut changed = Vec::new();
        let mut structure_changed = false;
        for node in &self.nodes {
            match before.get(&node.id) {
                Some(was) if *was == node => {}
                Some(was) => {
                    structure_changed |= was.parent != node.parent || was.role != node.role;
                    changed.push(node.clone());
                }
                None => {
                    structure_changed = true;
                    changed.push(node.clone());
                }
            }
        }

        let now: HashMap<Id, ()> = self.nodes.iter().map(|node| (node.id, ())).collect();
        let removed: Vec<Id> =
            previous.nodes.iter().map(|node| node.id).filter(|id| !now.contains_key(id)).collect();
        structure_changed |= !removed.is_empty();

        AccessUpdate {
            changed,
            removed,
            focused: self.focused,
            focus_moved: self.focused != previous.focused,
            structure_changed,
        }
    }
}

/// What a field or a meter holds, as an assistive technology would read it.
fn value_of<S>(el: &El<S>) -> Option<String> {
    if let Some(value) = &el.value {
        return Some(value.clone());
    }
    match &el.node {
        Node::Field { value, .. } => Some(value.clone()),
        _ => None,
    }
}

/// Everything that changed about the accessibility tree in one frame.
///
/// What crosses the platform seam; see the module's note for the exact
/// `Backend` contract a backend implements against it. Plain data, so a
/// platform layer can keep it, queue it, or answer it later without borrowing
/// anything from the frame that produced it.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct AccessUpdate {
    /// Nodes that are new, or that differ from the frame before.
    ///
    /// Each carries its own parent, so a backend that has lost track can
    /// rebuild from these alone.
    pub changed: Vec<AccessNode>,
    /// Nodes the last frame drew and this one did not.
    pub removed: Vec<Id>,
    /// What has the keyboard now.
    pub focused: Option<Id>,
    /// Whether that is different from the frame before.
    ///
    /// Separate from [`AccessUpdate::focused`] because *nothing is focused* is
    /// a change worth announcing and is not distinguishable from *focus did not
    /// move* by the value alone.
    pub focus_moved: bool,
    /// Whether the shape of the tree moved, rather than only its contents.
    ///
    /// When this is set a platform has to tell its assistive technology that
    /// the layout changed — on macOS, `NSAccessibilityLayoutChangedNotification`
    /// — because an object model built from the previous shape is now wrong.
    pub structure_changed: bool,
}

impl AccessUpdate {
    /// Whether there is nothing at all to tell the platform.
    ///
    /// The common case, and the one that makes the diff worth doing.
    pub fn is_empty(&self) -> bool {
        self.changed.is_empty() && self.removed.is_empty() && !self.focus_moved
    }
}

/// A place where the convention this module states has been broken.
#[derive(Debug, Clone, PartialEq)]
pub struct Violation {
    /// The node it was found on.
    pub id: Id,
    /// What that node claimed to be.
    pub role: Role,
    /// What it was called, which is often empty — that being the whole problem.
    pub name: String,
    /// Where it was drawn, which is how a person finds it again.
    ///
    /// A control with no role and no name cannot be named in a failure any
    /// other way, and "the third row of the second panel" is a rectangle.
    pub bounds: Rect,
    /// What is wrong with it.
    pub fault: Fault,
}

/// What is wrong with a node.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Fault {
    /// It answers a person and is still a plain [`Role::Group`].
    NoRole,
    /// It answers a person and has no words to be called by.
    NoName,
    /// Its role only means something inside another, and it is not in one.
    OutsideContainer {
        /// The role it should have been inside.
        wanted: Role,
    },
    /// Two things inside the same parent came out with one identity, so they
    /// share a hover, a focus, and a caret.
    SharedIdentity,
}

impl fmt::Display for Violation {
    fn fmt(&self, out: &mut fmt::Formatter<'_>) -> fmt::Result {
        let Self { role, name, bounds, .. } = self;
        let at = format!("at {:.0},{:.0} {:.0}x{:.0}", bounds.x, bounds.y, bounds.w, bounds.h);
        match &self.fault {
            Fault::NoRole => write!(
                out,
                "something {at} answers a pointer or the keyboard and is still a {role:?}; \
                 give it a role with .role(…)"
            ),
            Fault::NoName => write!(
                out,
                "a {role:?} {at} answers a pointer or the keyboard and has no name; \
                 put words inside it, or name it with .label(…)"
            ),
            Fault::OutsideContainer { wanted } => write!(
                out,
                "{name:?} is a {role:?} with no {wanted:?} above it; \
                 a {role:?} only means anything inside a {wanted:?}"
            ),
            Fault::SharedIdentity => write!(
                out,
                "{name:?} shares its identity with a sibling; \
                 name them apart with .key(…)"
            ),
        }
    }
}

/// Every way `tree` breaks the convention, in the order the frame drew them.
///
/// The enforcement itself, kept here rather than in a test so that an
/// application built on this library can hold its own interface to the same
/// standard — `crates/console` does. [`Harness::assert_accessible`] is this
/// with a failure attached.
///
/// [`Harness::assert_accessible`]: crate::testing::Harness::assert_accessible
pub fn audit(tree: &AccessTree) -> Vec<Violation> {
    let by_id: HashMap<Id, &AccessNode> = tree.nodes().iter().map(|node| (node.id, node)).collect();
    let mut violations = Vec::new();
    let mut seen: HashMap<Id, usize> = HashMap::new();

    for node in tree.nodes() {
        let fault = |fault| Violation {
            id: node.id,
            role: node.role,
            name: node.name.clone(),
            bounds: node.bounds,
            fault,
        };

        // An identity is a path through the tree, so a repeat means two
        // siblings were named the same with `.key`.
        let count = seen.entry(node.id).or_default();
        *count += 1;
        if *count == 2 {
            violations.push(fault(Fault::SharedIdentity));
        }

        if node.is_interactive() {
            // One defect, one line. A group has no name because a group is not
            // named from its contents, so saying it is unnamed as well would be
            // reporting the same mistake twice and advising the wrong fix.
            if node.role == Role::Group {
                violations.push(fault(Fault::NoRole));
            } else if node.name.trim().is_empty() {
                violations.push(fault(Fault::NoName));
            }
        }

        if let Some(wanted) = node.role.container() {
            if !has_ancestor(node, wanted, &by_id) {
                violations.push(fault(Fault::OutsideContainer { wanted }));
            }
        }
    }
    violations
}

/// Whether anything above `node` plays `wanted`.
fn has_ancestor(node: &AccessNode, wanted: Role, by_id: &HashMap<Id, &AccessNode>) -> bool {
    let mut parent = node.parent;
    // Bounded by the tree's own depth: every step moves to a parent, and a
    // parent was pushed before its child, so the walk cannot cycle.
    while let Some(id) = parent {
        let Some(above) = by_id.get(&id) else { return false };
        if above.role == wanted {
            return true;
        }
        parent = above.parent;
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::geom::Rect;

    /// A node with the given role and name, hanging off `parent`.
    fn node(id: &str, parent: Option<Id>, role: Role, name: &str) -> AccessNode {
        AccessNode {
            id: Id::new(id),
            parent,
            role,
            name: name.to_owned(),
            value: None,
            state: AccessState::default(),
            bounds: Rect::new(0.0, 0.0, 10.0, 10.0),
            position_in_set: None,
            set_size: None,
            actions: AccessActions::default(),
        }
    }

    /// A tree of the given nodes, settled.
    fn tree(nodes: Vec<AccessNode>) -> AccessTree {
        let mut tree = AccessTree { nodes, focused: None };
        tree.finish(None);
        tree
    }

    #[test]
    fn a_tab_finds_its_place_from_the_list_it_is_in() {
        let list = Id::new("list");
        let settled = tree(vec![
            node("list", None, Role::TabList, ""),
            node("first", Some(list), Role::Tab, "Overview"),
            node("second", Some(list), Role::Tab, "Output"),
        ]);

        let tabs: Vec<_> = settled.children_of(list).collect();
        assert_eq!(tabs[0].position_in_set, Some(1));
        assert_eq!(tabs[1].position_in_set, Some(2));
        assert!(tabs.iter().all(|tab| tab.set_size == Some(2)));
        assert!(audit(&settled).is_empty(), "a tab inside its list breaks nothing");
    }

    #[test]
    fn a_tab_with_no_list_above_it_is_reported() {
        let settled = tree(vec![node("stray", None, Role::Tab, "Overview")]);
        assert_eq!(
            audit(&settled).first().map(|violation| violation.fault.clone()),
            Some(Fault::OutsideContainer { wanted: Role::TabList })
        );
    }

    #[test]
    fn an_unchanged_frame_produces_an_empty_update() {
        let settled = tree(vec![node("root", None, Role::Group, "")]);
        assert!(settled.diff(&settled).is_empty());
    }

    #[test]
    fn a_node_that_went_away_is_reported_as_a_change_of_structure() {
        let before = tree(vec![
            node("root", None, Role::Group, ""),
            node("row", Some(Id::new("root")), Role::Text, "mongod"),
        ]);
        let after = tree(vec![node("root", None, Role::Group, "")]);

        let update = after.diff(&before);
        assert_eq!(update.removed, vec![Id::new("row")]);
        assert!(update.structure_changed);
        assert!(update.changed.is_empty(), "what stayed the same is not worth saying again");
    }

    #[test]
    fn only_the_node_that_changed_is_emitted() {
        let before = tree(vec![
            node("root", None, Role::Group, ""),
            node("count", Some(Id::new("root")), Role::Text, "1"),
        ]);
        let mut after = before.clone();
        after.nodes[1].name = "2".to_owned();

        let update = after.diff(&before);
        assert_eq!(update.changed.len(), 1);
        assert_eq!(update.changed[0].name, "2");
        assert!(!update.structure_changed, "a word changed, not the shape of the tree");
    }

    #[test]
    fn focus_moving_is_a_change_even_when_no_node_did() {
        let before = tree(vec![node("field", None, Role::Field, "NAME")]);
        let mut after = before.clone();
        after.finish(Some(Id::new("field")));

        let update = after.diff(&before);
        assert!(update.focus_moved);
        assert!(!update.is_empty());
    }
}

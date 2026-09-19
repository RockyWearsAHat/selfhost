//! The SITES screen: web domains and their access configuration.
//!
//! Each Site shows its domains, exposure level (public/people/private), owner,
//! and a button to manage access grants for that Site.

use super::style;
use super::Console;
use rui::style::Justify;
use rui::{
    Align, El, Length, Role, Status, caption, col, code, micro, row, spacer, text,
};
use selfhost_json::Json;

/// The share of a site row each column takes.
const NAME_W: f32 = 0.2;
/// See [`NAME_W`].
const DOMAINS_W: f32 = 0.3;
/// See [`NAME_W`].
const EXPOSURE_W: f32 = 0.15;
/// See [`NAME_W`].
const OWNER_W: f32 = 0.2;
/// See [`NAME_W`].
const ACTIONS_W: f32 = 0.15;

/// How tall one site row is.
const ROW: f32 = 24.0;

/// A Site from the API response.
#[derive(Debug, Clone)]
pub struct Site {
    pub name: String,
    pub domains: Vec<String>,
    pub exposure: Option<String>,
    pub owner: Option<String>,
}

impl Site {
    /// Parse a Site from JSON.
    pub fn from_json(json: &Json) -> Option<Self> {
        Some(Site {
            name: json.get("name")?.as_str()?.to_string(),
            domains: json
                .get("domains")?
                .as_array()?
                .iter()
                .filter_map(|d| d.as_str())
                .map(String::from)
                .collect(),
            exposure: json.get("exposure")?.as_str().map(String::from),
            owner: json.get("owner")?.as_str().map(String::from),
        })
    }
}

/// The whole SITES screen: the roster of sites.
pub fn view(console: &Console) -> El<Console> {
    let snapshot = console.snapshot();
    let sites = &snapshot.sites;

    let body: El<Console> = match (sites.sites.as_ref(), sites.trouble.as_deref()) {
        (_, Some(reason)) => col((
            row((style::lamp(Status::Warn), caption(reason.to_owned()).wrap().grow()))
                .gap(6.0)
                .align(Align::Center),
            caption(
                "The site registry is available to the owner and those with site.admin \
                 grants. This credential does not hold them.",
            )
            .wrap(),
        ))
        .gap(4.0)
        .pad_y(12.0),
        (None, None) => col(caption("Reading sites…").wrap().center_text()).pad_y(24.0),
        (Some(site_list), None) if site_list.is_empty() => {
            col(caption("No sites configured.").wrap().center_text()).pad_y(24.0)
        }
        (Some(site_list), None) => {
            let mut rows = vec![head_row()];
            rows.extend(site_list.iter().map(site_row));
            col(rows).gap(2.0).scroll().role(Role::List)
        }
    };

    style::plate((
        style::section_rule("SITES", sites.sites.as_ref().map(|s| s.len().to_string())),
        body.grow(),
        caption("Each site's exposure level and owner, and who may access it.").wrap(),
    ))
    .gap(8.0)
}

/// The header naming the columns.
fn head_row() -> El<Console> {
    row((
        micro("NAME").tracking(1.2).w(Length::Fraction(NAME_W)),
        micro("DOMAINS").tracking(1.2).w(Length::Fraction(DOMAINS_W)),
        micro("EXPOSURE").tracking(1.2).w(Length::Fraction(EXPOSURE_W)),
        micro("OWNER").tracking(1.2).w(Length::Fraction(OWNER_W)),
        spacer().w(Length::Fraction(ACTIONS_W)),
    ))
    .min_h(14.0)
}

/// One site: its name, domains, exposure, and owner.
fn site_row(site: &Site) -> El<Console> {
    row((
        text(site.name.clone()).w(Length::Fraction(NAME_W)),
        code(site.domains.join(", ")).w(Length::Fraction(DOMAINS_W)).whole(),
        text(site.exposure.as_deref().unwrap_or("—")).w(Length::Fraction(EXPOSURE_W)),
        text(site.owner.as_deref().unwrap_or("—")).w(Length::Fraction(OWNER_W)),
        spacer().w(Length::Fraction(ACTIONS_W)),
    ))
    .min_h(ROW)
    .align(Align::Center)
    .justify(Justify::Start)
    .hover_fill(rui::Tone::Raised)
    .gap(6.0)
    .key(site.name.clone())
    .role(Role::ListItem)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn site_parses_from_json() {
        let json = Json::object([
            ("name", Json::string("blog")),
            ("domains", Json::array(vec![Json::string("blog.example.com")])),
            ("exposure", Json::string("people")),
            ("owner", Json::string("alex")),
        ]);
        let site = Site::from_json(&json).unwrap();
        assert_eq!(site.name, "blog");
        assert_eq!(site.domains, vec!["blog.example.com"]);
        assert_eq!(site.exposure, Some("people".to_string()));
        assert_eq!(site.owner, Some("alex".to_string()));
    }

    #[test]
    fn site_parses_null_exposure_and_owner() {
        let json = Json::object([
            ("name", Json::string("public")),
            ("domains", Json::array(vec![Json::string("public.example.com")])),
            ("exposure", Json::Null),
            ("owner", Json::Null),
        ]);
        let site = Site::from_json(&json).unwrap();
        assert_eq!(site.exposure, None);
        assert_eq!(site.owner, None);
    }
}

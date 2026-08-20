//! The house API on loopback, for driving by hand.
//!
//! ```text
//! cargo run -p selfhost-home --example house_api -- 127.0.0.1:8791 /tmp/registry
//! ```
//!
//! Exactly what `selfhost home` runs inside a deployment, minus the proxy and
//! the TLS in front of it: one [`Hub`] sweeping the real network, and the JSON
//! surface the dashboard reads. It exists so the API can be exercised against
//! the real house without standing a whole deployment up, which is how the two
//! seam defects in home-lab.dx were both found.

use std::sync::Arc;
use std::time::Duration;

use selfhost_home::Hub;

#[tokio::main]
async fn main() -> std::io::Result<()> {
    let mut arguments = std::env::args().skip(1);
    let bind = arguments.next().unwrap_or_else(|| "127.0.0.1:8791".to_owned());
    let registry = arguments.next().unwrap_or_else(|| "home-registry".to_owned());

    let hub = Arc::new(Hub::new(registry.into()));
    tokio::spawn(Arc::clone(&hub).run(Duration::from_secs(5), Duration::from_secs(60)));
    eprintln!("the house is on http://{bind}/api/home");
    selfhost_home::serve(&bind, hub).await
}

//! Mail, spawned alongside the proxy: SMTP receiving, authenticated
//! submission, IMAP, and the outbound queue runner.
//!
//! Mirrors `acme_task` — a background job the `run` command starts when its
//! config section is present, reusing the same [`CertificateStore`] the proxy
//! already opened rather than provisioning trust material of its own. Mail is
//! opt-in (see [`selfhost_config::Mail`]); [`run`] does nothing when the
//! config carries no `[mail]` section.

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{ClientConfig, DigitallySignedStruct, ServerConfig, SignatureScheme};
use selfhost_config::Config;
use selfhost_dns::Resolver;
use selfhost_mail::{
    deliver, Address, Authenticator, ConfigAuthenticator, Dkim, IConfig, ImapServer, Maildir,
    OutboundQueue, Policy, Receiver, SendContext, SigningIdentity, Submission, serve_imap,
    serve_smtp, serve_submission,
};
use selfhost_proxy::CertificateStore;
use tokio::net::TcpListener;
use tokio_rustls::TlsConnector;

/// How often the outbound queue is swept for messages to send.
const QUEUE_INTERVAL: Duration = Duration::from_secs(15);

/// Starts every mail listener `config.mail` asks for, and the outbound queue
/// runner, then returns — each piece keeps running in its own spawned task.
///
/// A listener that fails to bind is logged and skipped; the rest still start,
/// since inbound and outbound mail are independently useful. Called once from
/// `run`'s `serve`, after the certificate store is open, so a certificate for
/// `mail.hostname` can be generated the same way the proxy generates one for
/// a site on first start.
pub async fn run(config: Config, project_dir: PathBuf, store: CertificateStore) {
    let Some(mail) = config.mail.clone() else { return };

    let data_dir = project_dir.join(&config.server.data_dir);
    if let Err(error) = std::fs::create_dir_all(&data_dir) {
        log(format!("cannot create {}: {error} — mail is not running", data_dir.display()));
        return;
    }

    // One pass over the config mailboxes yields both the store's mailbox list
    // and the (alias, target) routes, so an alias can never pair with anything
    // but its own mailbox's parsed address.
    let mut mailboxes = Vec::new();
    let mut aliases = Vec::new();
    for mailbox in &mail.mailboxes {
        let target = match Address::parse(&mailbox.address) {
            Ok(address) => address,
            Err(error) => {
                log(format!("a configured mailbox address does not parse ({error:?}) — mail is not running"));
                return;
            }
        };
        for alias in &mailbox.aliases {
            match Address::parse(alias) {
                Ok(alias) => aliases.push((alias, target.clone())),
                Err(error) => {
                    log(format!("a configured alias does not parse ({error:?}) — mail is not running"));
                    return;
                }
            }
        }
        mailboxes.push(target);
    }

    let maildir = match Maildir::open(&data_dir, &mailboxes, &aliases) {
        Ok(maildir) => maildir,
        Err(error) => {
            log(format!("could not open the mail store ({error}) — mail is not running"));
            return;
        }
    };

    let tls_config = match server_tls(&store, &mail.hostname) {
        Ok(config) => config,
        Err(error) => {
            log(format!("could not prepare TLS for {} ({error}) — mail is not running", mail.hostname));
            return;
        }
    };

    let policy = Policy {
        hostname: mail.hostname.clone(),
        local_domains: mail.domains.clone(),
        tls_available: true,
        allow_auth_without_tls: !mail.require_tls_for_auth,
        max_message_bytes: mail.max_message_bytes,
    };
    let authenticator: Arc<dyn Authenticator> = Arc::new(ConfigAuthenticator::new(&mail.mailboxes));
    let queue = match OutboundQueue::open(&data_dir) {
        Ok(queue) => queue,
        Err(error) => {
            log(format!("could not open the outbound queue ({error}) — mail is not running"));
            return;
        }
    };

    for (role, address) in mail.socket_binds() {
        match role {
            "smtp" => {
                let Some(listener) = bind(role, address).await else { continue };
                let receiver = Receiver::new(policy.clone(), maildir.clone(), Some(Arc::clone(&tls_config)));
                log(format!("smtp listening on {address}"));
                tokio::spawn(async move {
                    if let Err(error) = serve_smtp(listener, receiver).await {
                        log(format!("smtp: listener stopped ({error})"));
                    }
                });
            }
            "submission" => {
                let Some(listener) = bind(role, address).await else { continue };
                let submission = Submission::new(
                    policy.clone(),
                    Arc::clone(&tls_config),
                    Arc::clone(&authenticator),
                    queue.clone(),
                );
                log(format!("submission listening on {address}"));
                tokio::spawn(async move {
                    if let Err(error) = serve_submission(listener, submission).await {
                        log(format!("submission: listener stopped ({error})"));
                    }
                });
            }
            "imap" | "imaps" => {
                let Some(listener) = bind(role, address).await else { continue };
                let imap_config = IConfig {
                    hostname: mail.hostname.clone(),
                    tls_available: true,
                    require_tls_for_auth: mail.require_tls_for_auth,
                };
                let imap = ImapServer {
                    config: imap_config,
                    store: maildir.clone(),
                    authenticator: Arc::clone(&authenticator),
                    tls: Some(Arc::clone(&tls_config)),
                    implicit_tls: role == "imaps",
                };
                log(format!("{role} listening on {address}"));
                tokio::spawn(async move {
                    if let Err(error) = serve_imap(listener, imap).await {
                        log(format!("{role}: listener stopped ({error})"));
                    }
                });
            }
            other => log(format!("{other} on {address}: unrecognised bind role — skipped")),
        }
    }

    let dkim = mail.dkim.as_ref().and_then(|dkim_config| {
        match Dkim::load_or_generate(&data_dir.join(&dkim_config.private_key)) {
            Ok(dkim) => Some((dkim, dkim_config.selector.clone())),
            Err(error) => {
                log(format!(
                    "{}: could not load or generate the DKIM key ({error}) — outbound mail will be unsigned",
                    dkim_config.selector
                ));
                None
            }
        }
    });

    tokio::spawn(run_queue(queue, mail.hostname, dkim, mail.relay.clone()));
}

/// Binds one mail listener, logging and returning `None` on failure so the
/// caller can start the others rather than aborting the whole daemon.
async fn bind(role: &str, address: std::net::SocketAddr) -> Option<TcpListener> {
    match TcpListener::bind(address).await {
        Ok(listener) => Some(listener),
        Err(error) => {
            log(format!("{role}: cannot bind {address} ({error}) — skipped"));
            None
        }
    }
}

/// Sweeps the outbound queue forever, signing, routing, and delivering each
/// spooled message and removing it once every recipient has accepted it.
///
/// A message that only partially delivers is left in the queue rather than
/// removed: the next sweep re-attempts every destination, including the ones
/// that already accepted it. That is safe — a receiving MTA treats a repeat
/// delivery exactly like the retry it would see anyway over plain SMTP — and
/// simpler than tracking per-destination progress across sweeps.
async fn run_queue(
    queue: OutboundQueue,
    helo: String,
    dkim: Option<(Dkim, String)>,
    relay: Option<selfhost_config::Relay>,
) {
    let resolver = Resolver::system();
    let tls = outbound_tls_connector();

    loop {
        tokio::time::sleep(QUEUE_INTERVAL).await;

        let ids = match queue.list() {
            Ok(ids) => ids,
            Err(error) => {
                log(format!("outbound queue: could not list the spool ({error})"));
                continue;
            }
        };

        for id in ids {
            let queued = match queue.load(&id) {
                Ok(queued) => queued,
                Err(error) => {
                    log(format!("outbound queue: {id}: could not load it ({error}) — skipped"));
                    continue;
                }
            };

            let context = SendContext {
                resolver: &resolver,
                helo: &helo,
                signing: dkim
                    .as_ref()
                    .map(|(dkim, selector)| SigningIdentity { dkim, selector }),
                tls: Some(&tls),
                relay: relay.as_ref(),
            };
            let report = deliver(&context, &queued).await;

            if report.all_delivered() {
                if let Err(error) = queue.remove(&id) {
                    log(format!("outbound queue: {id}: delivered but could not remove it ({error})"));
                }
            } else {
                for (domain, result) in &report.results {
                    if let Err(reason) = result {
                        log(format!("outbound queue: {id}: {domain}: deferred — {reason}"));
                    }
                }
            }
        }
    }
}

/// Builds a plain (non-SNI) TLS server configuration for one hostname,
/// generating a self-signed pair on first use exactly as the proxy does for a
/// site with no certificate yet.
fn server_tls(store: &CertificateStore, hostname: &str) -> Result<Arc<ServerConfig>, String> {
    let (chain, key) =
        store.load_or_generate_self_signed(hostname, &[]).map_err(|error| error.to_string())?;
    ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(chain, key)
        .map(Arc::new)
        .map_err(|error| error.to_string())
}

/// A TLS client configuration for outbound MX delivery that accepts whatever
/// certificate the far end presents.
///
/// This is opportunistic transport encryption, not authentication: MX records
/// are not authenticated by DNSSEC here, so a certificate chain proves
/// nothing about whether the host answering really holds the recipient
/// domain's mail — verifying it would only turn a receiver's self-signed or
/// expired certificate into a hard delivery failure, trading working mail for
/// a guarantee this connection was never positioned to make. This is the
/// "opportunistic" TLS level Postfix and Exim default to for direct delivery.
fn outbound_tls_connector() -> TlsConnector {
    let config = ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(AcceptAnyServerCert))
        .with_no_client_auth();
    TlsConnector::from(Arc::new(config))
}

/// The verifier behind [`outbound_tls_connector`]; see its doc for why
/// accepting any certificate is the correct choice for opportunistic MX TLS.
#[derive(Debug)]
struct AcceptAnyServerCert;

impl ServerCertVerifier for AcceptAnyServerCert {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        rustls::crypto::CryptoProvider::get_default()
            .map(|provider| provider.signature_verification_algorithms.supported_schemes())
            .unwrap_or_default()
    }
}

/// Writes one clearly-tagged line to stderr, matching `acme_task`'s `log`.
fn log(message: impl AsRef<str>) {
    eprintln!("mail: {}", message.as_ref());
}

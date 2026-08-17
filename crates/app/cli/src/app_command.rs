//! `selfhost app` — deploying applications from Git repositories.
//!
//! Applications are backend services that run from a watched Git repository and
//! are exposed through the proxy on one or more domains. An [`AppSpec`] composes
//! a backend service and a proxy route, keeping the port they share consistent
//! and building before the running version is disturbed.
//!
//! ```text
//! selfhost app list                List deployed applications
//! selfhost app show <name>         Show an application's configuration
//! selfhost app deploy <name>       Deploy it now
//! ```
//!
//! # Why `deploy` has two paths, and why the choice is not the operator's
//!
//! A [`Supervisor`] owns the processes it starts and knows nothing about anyone
//! else's — it is an in-memory table of children of *this* process. So the same
//! deployment means two different things depending on whether a daemon is up,
//! and the difference is not cosmetic:
//!
//! * **A daemon is running.** It already holds the backend as a child process.
//!   If this command built an `AppSpec` and installed it into a supervisor of
//!   its own, it would spawn a *second* copy of the server against the port the
//!   first one is already bound to, orphan it at exit, and print that the
//!   deployment succeeded while the old code kept serving. So the swap is asked
//!   for through the daemon's own API — the one process entitled to perform it.
//! * **No daemon is running.** Nothing is serving and nothing else is managing
//!   the tree, so [`selfhost_app_deploy::deploy`] runs here: update, build, and
//!   swap only if the build succeeded, rolling the working copy back if it did
//!   not. The backend it starts is stopped again before this command exits,
//!   because a process started by a command line cannot be supervised by one.
//!
//! Both paths are stated in the output as they happen. The failure this arrangement
//! exists to prevent is the quiet one: reporting a deployment that did not replace
//! what is actually running.

use selfhost_admin::{Store, Token};
use selfhost_app_deploy::{AppSpec, Deployment};
use selfhost_config::{Config, ServiceCatalog, ServiceSpec, Site};
use selfhost_supervisor::Supervisor;
use std::net::SocketAddr;
use std::path::Path;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

/// How long a locally deployed backend is watched for before this command gives
/// up on seeing it come up.
///
/// Long enough for a server that opens a socket and prints, short enough that
/// the operator is not left staring at a command that has already done its work.
const START_WINDOW: Duration = Duration::from_secs(5);

/// How long a started backend is left alone before it is asked again whether it
/// is still there.
///
/// A server that cannot bind its port exits within milliseconds, so a short
/// pause separates "it started" from "it started and immediately died" — the
/// difference between a deployment and a deployment that only looks like one.
const SETTLE: Duration = Duration::from_millis(500);

/// How long the loopback exchange with a running daemon may take.
///
/// The daemon answers this route without waiting for the deployment (it is a
/// `202`), so anything slower than this is a wedged daemon rather than a long
/// build.
const DAEMON_DEADLINE: Duration = Duration::from_secs(5);

/// The words this command accepts after `app`, and what each one is for.
pub const USAGE: &str = "\
Usage
  selfhost app list              All deployed applications and their domains
  selfhost app show <name>       One application's configuration and status
  selfhost app deploy <name>     Deploy this application now

With the daemon running, `deploy` asks it to check the branch and deploy if the
tip has moved — the daemon owns the running process, so it performs the swap.
With no daemon running, the deployment happens here: the repository is updated
and built while nothing is disturbed, the swap happens only if the build
succeeded, and a failed build rolls the working copy back to the commit the last
good version was built from.

`list` and `show` also work against another machine: selfhost --remote <host> app list
";

/// Runs the command. `arguments[0]` is the word `app`.
pub fn run(arguments: &[String], config: &Config, project_dir: &Path) -> Result<(), String> {
    let data_dir = project_dir.join(&config.server.data_dir);
    let store = Store::new(&data_dir);
    let node_names: Vec<&str> = config.nodes.iter().map(|n| n.name.as_str()).collect();
    let catalog = store.load(&node_names).map_err(|e| e.to_string())?;

    match arguments.get(1).map(String::as_str) {
        None | Some("list") => list(&catalog),
        Some("show") => show(arguments, &catalog, None),
        Some("deploy") => deploy(arguments, config, project_dir, &data_dir, &catalog),
        Some(other) => Err(format!("unknown app subcommand \"{other}\"\n\n{USAGE}")),
    }
}

/// Lists all installed applications.
pub fn list(catalog: &ServiceCatalog) -> Result<(), String> {
    let apps: Vec<_> = catalog.services.iter().filter(|s| s.git.is_some()).collect();

    if apps.is_empty() {
        println!("no applications deployed yet");
        return Ok(());
    }

    println!("  {:<20}  {:<30}  NODE", "NAME", "PATH/BRANCH");
    for app in apps {
        // Applications are services with a git watch configured.
        let git = app.git.as_ref().unwrap();
        let branch = &git.branch;
        println!(
            "  {:<20}  {:<30}  {}",
            app.name,
            format!("{} ({})", git.path.display(), branch),
            app.node.as_deref().unwrap_or("owner")
        );
    }
    Ok(())
}

/// Shows details about one application.
///
/// `on` names the machine the answer came from when it did not come from this
/// one, so the closing advice names a command that would act on *that* box. A
/// `--remote` reader told to "run `selfhost app deploy`" without being told
/// where would run it here, which is the mistake this whole flag exists to make
/// impossible.
pub fn show(
    arguments: &[String],
    catalog: &ServiceCatalog,
    on: Option<&str>,
) -> Result<(), String> {
    let name = arguments
        .get(2)
        .ok_or_else(|| format!("app show needs an application name\n\n{USAGE}"))?;

    let app = catalog
        .services
        .iter()
        .find(|s| &s.name == name && s.git.is_some())
        .ok_or_else(|| format!("no application named \"{name}\""))?;

    let git = app.git.as_ref().unwrap();
    println!("application: {}", app.name);
    println!("  program      {}", app.program.display());
    if !app.args.is_empty() {
        println!("  args         {:?}", app.args);
    }
    println!("  node         {}", app.node.as_deref().unwrap_or("owner"));
    println!("  working copy {}", git.path.display());
    println!("  repository   {}", git.repository);
    println!("  branch       {}", git.branch);
    println!("  check interval {}s", git.interval_secs);
    if git.auto_update {
        println!("  auto-update  enabled");
    }
    if let Some(post) = &git.post_pull {
        println!("  build step   {:?}", post);
    }
    if git.webhook_secret.is_some() {
        println!("  webhook      configured");
    }

    if !app.env.is_empty() {
        println!("  environment:");
        for (key, value) in &app.env {
            // Do not display sensitive values in full — a token appearing
            // in a terminal log or shell history defeats the whole point of
            // keeping it in a file and off the command line.
            if key.to_uppercase().contains("TOKEN") || key.to_uppercase().contains("SECRET") {
                println!("    {}=***", key);
            } else {
                println!("    {}={}", key, value);
            }
        }
    }

    println!(
        "\nTo deploy or update: push to the {} branch and wait for the watch interval,",
        git.branch
    );
    match on {
        Some(host) => println!("or run `selfhost app deploy {}` on {host}.", app.name),
        None => println!("or run `selfhost app deploy {}` to deploy immediately.", app.name),
    }

    Ok(())
}

/// Deploys an application: through the running daemon if there is one, and in
/// this process if there is not.
///
/// See the module note for why that is not a preference. The composed
/// [`AppSpec`] is built and checked before either path is taken, so a
/// misconfigured application is refused before anything touches a working copy.
fn deploy(
    arguments: &[String],
    config: &Config,
    project_dir: &Path,
    data_dir: &Path,
    catalog: &ServiceCatalog,
) -> Result<(), String> {
    let name = arguments
        .get(2)
        .ok_or_else(|| format!("app deploy needs an application name\n\n{USAGE}"))?;

    let spec = catalog
        .services
        .iter()
        .find(|s| &s.name == name && s.git.is_some())
        .ok_or_else(|| {
            format!(
                "no application named \"{name}\" — `selfhost app list` shows the applications \
                 this deployment knows about. A service with no [git] watch is a service, not an \
                 application; deploy it by reinstalling it."
            )
        })?;
    let site = config.sites.iter().find(|s| &s.name == name);
    let app = compose(spec, site, config)?;

    println!("application: {}", app.name);
    println!("  repository   {} ({})", app.repository, app.branch);
    println!("  working copy {}", app.checkout_path().display());
    match site {
        Some(site) => println!("  route        {} → 127.0.0.1:{}", site.domains.join(", "), app.port),
        None => println!(
            "  route        none — no [[sites]] entry is named \"{}\", so nothing forwards to it",
            app.name
        ),
    }
    match &app.build {
        Some(build) => println!("  build step   {build:?}"),
        None => println!("  build step   none"),
    }
    println!();

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .map_err(|e| format!("could not start the async runtime: {e}"))?;

    runtime.block_on(carry_out(&app, config, project_dir, data_dir))
}

/// Rebuilds one application, on whichever of the two paths applies.
async fn carry_out(
    app: &AppSpec,
    config: &Config,
    project_dir: &Path,
    data_dir: &Path,
) -> Result<(), String> {
    let address: SocketAddr = config
        .server
        .admin_bind
        .parse()
        .map_err(|e| format!("server.admin_bind {}: {e}", config.server.admin_bind))?;

    match ask_daemon(&app.name, address, data_dir).await {
        Ok(()) => {
            println!("✓ the daemon on {address} accepted a deployment of \"{}\"", app.name);
            println!(
                "  It compares {} {} with the working copy and, if the tip has moved, stops the\n  \
                 service, updates the tree, runs the build step and starts it again.",
                app.repository, app.branch
            );
            println!(
                "  A branch that has not moved deploys nothing: the daemon deploys a commit, not\n  \
                 a request. Push first, then run this."
            );
            println!("  The outcome lands in that service's log — `selfhost app show {}`.", app.name);
            Ok(())
        }
        Err(Daemon::Absent) => {
            println!("nothing is answering on {address}, so this deployment is not running.");
            println!("Deploying in this process instead — build first, swap only on success.\n");
            here(app, project_dir).await
        }
        Err(Daemon::Said(message)) => Err(message),
    }
}

/// Why the running daemon did not take the deployment.
enum Daemon {
    /// Nothing is listening on the admin address at all.
    ///
    /// Kept apart from every other failure because it is the only one that means
    /// "there is no running version to protect", which is what makes deploying
    /// in this process safe rather than a way to start a second copy.
    Absent,
    /// It is there, and this is what it said. Never a reason to deploy locally.
    Said(String),
}

/// Asks a running daemon to deploy one service, over loopback.
///
/// The same shape `doctor`'s `ask_daemon` uses and for the same reason: one
/// request, `Connection: close`, read to the end. The bearer token is read from
/// the data directory rather than the environment because this is the *local*
/// daemon, whose token is a file this machine owns.
///
/// `name` goes into the request line unescaped, which is safe for exactly one
/// reason worth stating: it is a name read back out of the catalogue, and
/// `Store::load` refuses a catalogue whose service names are not the portable
/// alphabet `ServiceSpec::check` demands. It is never a string the caller typed.
async fn ask_daemon(name: &str, address: SocketAddr, data_dir: &Path) -> Result<(), Daemon> {
    let exchange = async {
        let mut stream = match TcpStream::connect(address).await {
            Ok(stream) => stream,
            // A refused connection is the one honest "no daemon here". A timeout
            // or a permission error means something *is* there, or something is
            // wrong with the machine, and deploying locally on the strength of
            // either could start a second copy of a running backend.
            Err(error) if error.kind() == std::io::ErrorKind::ConnectionRefused => {
                return Err(Daemon::Absent);
            }
            Err(error) => {
                return Err(Daemon::Said(format!("cannot reach the daemon on {address}: {error}")));
            }
        };

        let path = Token::path_in(data_dir);
        let token = std::fs::read_to_string(&path).map_err(|error| {
            Daemon::Said(format!(
                "the daemon on {address} is running but its token at {} could not be read \
                 ({error}), so this deployment cannot be asked for",
                path.display()
            ))
        })?;
        let token = crate::remote_client::usable(token.trim(), &path.display().to_string())
            .map_err(Daemon::Said)?;

        let request = format!(
            "POST /api/services/{name}/deploy HTTP/1.1\r\nHost: {address}\r\n\
             Authorization: Bearer {token}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
        );
        stream
            .write_all(request.as_bytes())
            .await
            .map_err(|error| Daemon::Said(format!("the daemon closed the connection: {error}")))?;

        let mut raw = Vec::new();
        stream
            .read_to_end(&mut raw)
            .await
            .map_err(|error| Daemon::Said(format!("the daemon's answer stopped: {error}")))?;
        Ok(raw)
    };

    let raw = tokio::time::timeout(DAEMON_DEADLINE, exchange)
        .await
        .map_err(|_| {
            Daemon::Said(format!("the daemon on {address} did not answer within {}s", DAEMON_DEADLINE.as_secs()))
        })??;

    accepted(&raw).map_err(Daemon::Said)
}

/// Reads the daemon's answer to a deployment request.
///
/// Pure, so the statuses can be exercised without a daemon. A `404` is called
/// out by name: it means the daemon is running a catalogue that does not have
/// this service in it, which is a different problem from a bad token and sends
/// the operator somewhere else entirely.
fn accepted(raw: &[u8]) -> Result<(), String> {
    let parsed = selfhost_http::IncomingResponse::parse(raw)
        .map_err(|error| format!("the daemon's answer is not a response: {error}"))?;
    let status = parsed.response.status;
    if (200..300).contains(&status.0) {
        return Ok(());
    }

    let body = String::from_utf8_lossy(raw.get(parsed.consumed..).unwrap_or_default());
    let said = selfhost_json::parse(body.trim())
        .ok()
        .and_then(|value| value.get("error").and_then(selfhost_json::Json::as_str).map(str::to_owned))
        .unwrap_or_else(|| status.reason().to_owned());

    Err(match status.0 {
        404 => format!(
            "the running daemon has no service by that name ({said}). Its catalogue is what it \
             loaded at start, so a service added to data/services.toml by hand is not there yet"
        ),
        401 | 403 => format!("the daemon refused this deployment ({said}) — the admin token did not match"),
        _ => format!("the daemon refused this deployment: {} {said}", status.0),
    })
}

/// Deploys in this process, with no daemon in the way.
///
/// This is [`selfhost_app_deploy::deploy`]'s guarantee end to end: the working
/// copy is brought to the branch tip, the build runs, and only a build that
/// succeeded is allowed to swap the service. The supervisor is rooted at the
/// project directory because that is what the daemon roots its own at, so
/// `checkouts/<name>` is one directory rather than two.
async fn here(app: &AppSpec, project_dir: &Path) -> Result<(), String> {
    let supervisor = Supervisor::new(project_dir);
    let outcome = selfhost_app_deploy::deploy(&supervisor, app).await;

    let verdict = match &outcome {
        Deployment::Installed { commit } | Deployment::Updated { commit } => {
            let installed = matches!(outcome, Deployment::Installed { .. });
            println!(
                "✓ {} onto {commit}",
                if installed { "cloned, built and installed" } else { "rebuilt and swapped" }
            );
            started(&supervisor, &app.name, commit).await
        }
        Deployment::BuildFailed { previous_serving, reason } => Err(format!(
            "the build failed, so nothing was swapped{}. The working copy has been rolled back to \
             the commit the last good version was built from.\n\n{reason}",
            if *previous_serving { " and the previous version is still serving" } else { "" }
        )),
        Deployment::Failed { step, reason } => {
            Err(format!("the {step} step failed before anything was built:\n\n{reason}"))
        }
    };

    // Whatever happened, nothing this command started may be left behind: this
    // process is about to exit, and a backend it spawned would be an unsupervised
    // orphan holding the port the daemon needs when it starts.
    supervisor.shutdown().await;
    if verdict.is_ok() {
        println!(
            "  stopped again — a server started by a command line has no supervisor once that \
             command exits.\n  Start the daemon (`selfhost daemon`) to serve it."
        );
    }
    verdict
}

/// Says whether the version just swapped in actually runs.
///
/// Waiting for `Running` rather than merely "live" is the point: `Starting` is
/// set before the spawn is even attempted, so a command that accepted it would
/// call a program that does not exist a successful deployment. The settle pause
/// afterwards catches the other half of the same lie — a server that starts,
/// fails to bind its port and exits within the same second, which is what a bad
/// build usually looks like from outside.
async fn started(supervisor: &Supervisor, name: &str, commit: &str) -> Result<(), String> {
    use selfhost_supervisor::state::ServiceState;

    let spawned =
        selfhost_supervisor::await_state(supervisor, name, START_WINDOW, |state| {
            matches!(state, ServiceState::Running { .. })
        })
        .await;

    let Some(ServiceState::Running { pid, .. }) = spawned else {
        let state = supervisor.status(name).await;
        return Err(format!(
            "the build succeeded and the working copy is on {commit}, but the server did not \
             start within {}s ({}). The tree is deployed; the program is not running.",
            START_WINDOW.as_secs(),
            state.map(|s| s.state.label()).unwrap_or("it was never installed")
        ));
    };

    tokio::time::sleep(SETTLE).await;
    match supervisor.status(name).await.map(|status| status.state) {
        Some(ServiceState::Running { .. }) => {
            println!("  it starts · pid {pid}");
            Ok(())
        }
        other => Err(format!(
            "the build succeeded and the working copy is on {commit}, but the server exited \
             within {}ms of starting ({}). The tree is deployed; nothing is serving from it.",
            SETTLE.as_millis(),
            other.map(|state| state.label().to_owned()).unwrap_or_else(|| "gone".to_owned())
        )),
    }
}

/// Rebuilds the [`AppSpec`] for an installed application from the two objects
/// the deployment actually stores it as.
///
/// The catalogue holds the backend and the config holds the route, which is the
/// split `selfhost_app_deploy` composes *into*; deploying an application that is
/// already installed therefore means putting the two back together rather than
/// asking the operator to restate them. The port is taken from the route when
/// there is one, because that is the number the proxy forwards to — falling back
/// to the injected `PORT`, which is where it came from in the first place.
fn compose(spec: &ServiceSpec, site: Option<&Site>, config: &Config) -> Result<AppSpec, String> {
    let watch = spec.git.as_ref().ok_or_else(|| {
        format!("\"{}\" has no Git watch, so there is nothing to deploy from", spec.name)
    })?;

    let mut serve = vec![spec.program.display().to_string()];
    serve.extend(spec.args.iter().cloned());

    // An empty `node` on a service means the owner, and `AppSpec::check` insists
    // on a real one — so the implicit answer is made explicit here rather than
    // failing a check the operator never wrote.
    let node = spec
        .node
        .clone()
        .or_else(|| site.and_then(|s| s.instances.first().map(|i| i.node.clone())))
        .or_else(|| config.owner().map(|n| n.name.clone()))
        .unwrap_or_default();

    let port = site
        .and_then(|s| s.instances.first().map(|i| i.port))
        .or_else(|| spec.env.get("PORT").and_then(|value| value.parse().ok()))
        .unwrap_or(0);

    let mut app = AppSpec::new(
        &spec.name,
        site.map(|s| s.domains.clone()).unwrap_or_default(),
        watch.repository.clone(),
        serve,
        node,
        port,
    );
    app.branch = watch.branch.clone();
    app.build = watch.post_pull.clone();
    app.interval_secs = watch.interval_secs;
    app.checkout = Some(watch.path.clone());
    app.env = spec.env.clone();
    if let Some(site) = site {
        app.health = site.health.clone();
        app.canonical_redirect = site.canonical_redirect;
    }

    let node_names: Vec<&str> = config.nodes.iter().map(|n| n.name.as_str()).collect();
    let problems: Vec<String> = app
        .check(&node_names)
        .into_iter()
        // A route this deployment does not have cannot be wrong. An application
        // with no `[[sites]]` entry is a backend nobody forwards to — worth
        // saying once, above, and not a reason to refuse to rebuild it.
        .filter(|problem| site.is_some() || !matches!(problem.field.as_str(), "app.domains" | "app.port"))
        .map(|problem| format!("  {}: {}", problem.field, problem.message))
        .collect();
    if !problems.is_empty() {
        return Err(format!(
            "\"{}\" cannot be deployed as it stands:\n{}",
            spec.name,
            problems.join("\n")
        ));
    }

    Ok(app)
}

#[cfg(test)]
mod tests {
    use super::*;
    use selfhost_config::{GitWatch, Instance};

    /// A deployment with one owner node and one application route, parsed from
    /// TOML so the test exercises the loader rather than a struct literal that
    /// would keep passing when a required field appears.
    fn config() -> Config {
        Config::parse(
            "version = 1\n\n\
             [server]\nacme_email = \"a@b.com\"\nacme = \"self-signed\"\n\n\
             [[nodes]]\nname = \"home\"\nrole = \"owner\"\n\n\
             [[sites]]\nname = \"blog\"\ndomains = [\"blog.example.com\"]\n\
             instances = [{ node = \"home\", port = 5050 }]\n",
        )
        .expect("the config parses")
    }

    /// The backend as the daemon's catalogue stores it.
    fn installed() -> ServiceSpec {
        let mut spec = ServiceSpec::new("blog", "node");
        spec.args = vec!["server.js".into()];
        let mut watch = GitWatch::new("https://github.com/owner/blog.git", "checkouts/blog");
        watch.branch = "release".into();
        watch.post_pull = Some(vec!["npm".into(), "ci".into()]);
        spec.git = Some(watch);
        spec.env.insert("PORT".into(), "5050".into());
        spec
    }

    #[test]
    fn an_installed_application_composes_back_into_the_spec_it_was_deployed_from() {
        let config = config();
        let site = config.sites.iter().find(|s| s.name == "blog");
        let app = compose(&installed(), site, &config).expect("a well-formed application");

        assert_eq!(app.serve, vec!["node".to_owned(), "server.js".to_owned()]);
        assert_eq!(app.repository, "https://github.com/owner/blog.git");
        assert_eq!(app.branch, "release");
        assert_eq!(app.build, Some(vec!["npm".to_owned(), "ci".to_owned()]));
        assert_eq!(app.checkout_path(), std::path::PathBuf::from("checkouts/blog"));
        assert_eq!(app.domains, vec!["blog.example.com".to_owned()]);
        // The port comes from the route, because that is the number the proxy
        // forwards to; the backend's own environment agrees with it here.
        assert_eq!(app.port, 5050);
        assert_eq!(app.node, "home");
    }

    #[test]
    fn a_service_with_no_watch_is_not_an_application() {
        let mut spec = installed();
        spec.git = None;
        let error = compose(&spec, None, &config()).expect_err("nothing to deploy from");
        assert!(error.contains("no Git watch"), "{error}");
    }

    #[test]
    fn an_application_with_no_route_still_deploys_and_takes_its_port_from_the_backend() {
        // A backend with no `[[sites]]` entry is a service nobody forwards to.
        // Refusing to rebuild it would make a missing route a deployment error,
        // which it is not — the code still needs building.
        let app = compose(&installed(), None, &config()).expect("no route is not a refusal");
        assert!(app.domains.is_empty());
        assert_eq!(app.port, 5050, "the injected PORT is where the number came from");
    }

    #[test]
    fn an_application_whose_node_does_not_exist_is_refused_before_anything_is_touched() {
        let mut spec = installed();
        spec.node = Some("shed".into());
        let config = config();
        let site = config.sites.iter().find(|s| s.name == "blog");
        let error = compose(&spec, site, &config).expect_err("an unknown node is refused");
        assert!(error.contains("app.node"), "{error}");
    }

    #[test]
    fn a_service_with_no_node_of_its_own_is_deployed_to_the_owner() {
        // `ServiceSpec::node` is `None` for "the owner node", and `AppSpec::check`
        // insists on naming one. Without this the ordinary case would be refused.
        let app = compose(&installed(), None, &config()).expect("composes");
        assert_eq!(app.node, "home");
    }

    #[test]
    fn the_daemons_acceptance_is_read_from_the_status_line() {
        let accepted_answer = b"HTTP/1.1 202 Accepted\r\nContent-Length: 16\r\n\r\n{\"accepted\":true}";
        assert!(accepted(accepted_answer).is_ok());
    }

    #[test]
    fn a_daemon_that_does_not_know_the_service_says_so_rather_than_blaming_the_token() {
        let answer = b"HTTP/1.1 404 Not Found\r\nContent-Length: 24\r\n\r\n{\"error\":\"no such service\"}";
        let error = accepted(answer).expect_err("a 404 is a failure");
        assert!(error.contains("no service by that name"), "{error}");

        let answer = b"HTTP/1.1 401 Unauthorized\r\nContent-Length: 2\r\n\r\n{}";
        let error = accepted(answer).expect_err("a 401 is a failure");
        assert!(error.contains("token"), "{error}");
    }

    #[test]
    fn the_route_is_where_the_port_comes_from_when_the_two_disagree() {
        // The proxy forwards to the route's port; a backend whose injected PORT
        // has drifted from it is a bug to be deployed *against* the route, not a
        // reason to deploy against the stale number.
        let mut config = config();
        config.sites[0].instances = vec![Instance { node: "home".into(), port: 6060 }];
        let site = config.sites.iter().find(|s| s.name == "blog");
        let app = compose(&installed(), site, &config).expect("composes");
        assert_eq!(app.port, 6060);
    }
}

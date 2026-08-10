//! Registering the daemon with the operating system's service manager.
//!
//! # Why this is generated, not a shipped script
//!
//! `scripts/launchd.sh` and `scripts/install-service.ps1` each hard-code one
//! machine's paths — a repository directory, a user's home. A service that must
//! survive a reboot has to name *this* installation's executable and *this*
//! project's directory, and those are only known at the moment `selfhost service
//! install` is run. So the registration is computed from
//! [`std::env::current_exe`] and the directory holding `selfhost.config.toml`,
//! not copied from a template with a placeholder somebody has to remember to
//! edit.
//!
//! # The shape: plan, confirm, carry out
//!
//! This mirrors [`crate::teardown`]. [`plan`] is pure — it computes exactly what
//! would be written and which commands would register it, and touches nothing —
//! so the whole registration can be shown to a person before a single file is
//! created. [`carry_out`] then writes the unit and runs the loader. The same
//! split lets the three platform builders ([`launchd_plist`],
//! [`scheduled_task_xml`], [`systemd_unit`]) be tested on any host with no
//! service manager present, exactly as `desired_rules` is tested with no
//! firewall.
//!
//! # What each platform gets
//!
//! - **macOS** — a launchd job, mirroring `scripts/launchd.sh`: `RunAtLoad`,
//!   `KeepAlive`, and `selfhost daemon` as its program. A per-user LaunchAgent by
//!   default; `--system` promotes it to a LaunchDaemon under
//!   `/Library/LaunchDaemons` so it runs with nobody logged in.
//! - **Windows** — a Task Scheduler task triggered at boot, running as the
//!   `SYSTEM` account (`S-1-5-18`) at the highest run level, restarted three
//!   times a minute apart if it dies and with no execution-time limit — the same
//!   policy `scripts/install-service.ps1` sets, expressed as task XML.
//! - **Linux** — a systemd unit, a `--user` unit by default and a system unit
//!   under `/etc/systemd/system` with `--system`.

use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::Command;

/// The launchd label / systemd unit stem the daemon is registered under.
const LABEL: &str = "com.selfhost.daemon";

/// The Windows scheduled-task name. Distinct from the proxy's `selfhost` task
/// so installing one never overwrites the other.
const TASK_NAME: &str = "selfhost-daemon";

/// The systemd unit file name.
const SYSTEMD_UNIT: &str = "selfhost-daemon.service";

/// One external command a plan runs, and whether its failure is fatal.
///
/// The unload-first step of a repeatable install fails cleanly the first time,
/// when there is nothing loaded to remove — the same reason `scripts/launchd.sh`
/// writes `launchctl bootout … || true`. That tolerance is carried as data here
/// rather than as a special case in the runner.
pub struct Step {
    /// The program and its arguments, program first.
    pub argv: Vec<String>,
    /// Whether a non-zero exit should be ignored rather than reported.
    pub ignore_failure: bool,
}

impl Step {
    /// A step whose failure aborts the install.
    fn required(argv: Vec<String>) -> Self {
        Self { argv, ignore_failure: false }
    }

    /// A step whose failure is expected and ignored (an unload with nothing
    /// loaded).
    fn ignoring(argv: Vec<String>) -> Self {
        Self { argv, ignore_failure: true }
    }
}

/// The service manager this build targets, chosen at runtime.
///
/// `cfg!` rather than `#[cfg]` so every arm of the `match`es below is compiled
/// on every platform: the three unit builders and their tests then travel with
/// the binary and are checked by one `cargo test` wherever it runs, even though
/// only one of them is ever selected on a given host.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Target {
    Launchd,
    ScheduledTask,
    Systemd,
    Unsupported,
}

/// Picks the service manager for this operating system.
fn target() -> Target {
    if cfg!(target_os = "macos") {
        Target::Launchd
    } else if cfg!(target_os = "linux") {
        Target::Systemd
    } else if cfg!(windows) {
        Target::ScheduledTask
    } else {
        Target::Unsupported
    }
}

/// Everything an install would write and run, computed without touching the
/// system.
pub struct Plan {
    /// The mechanism, named for the summary ("launchd", "systemd", …).
    pub mechanism: &'static str,
    /// What the daemon is registered under.
    pub label: String,
    /// Where the unit is written.
    pub path: PathBuf,
    /// Exactly what is written there.
    pub contents: String,
    /// Whether the unit must be written as UTF-16 (the Windows task XML).
    pub wide: bool,
    /// The command the unit runs: `selfhost daemon`.
    pub argv: Vec<String>,
    /// Where that command runs — the directory holding `selfhost.config.toml`.
    pub working_dir: PathBuf,
    /// The commands that register and start it, in order.
    pub activate: Vec<Step>,
}

/// What an uninstall would remove and run, computed without touching the system.
pub struct UninstallPlan {
    /// The mechanism, for the summary.
    pub mechanism: &'static str,
    /// What was registered.
    pub label: String,
    /// The unit file to delete, if the mechanism uses one.
    pub path: Option<PathBuf>,
    /// The commands that unregister it, in order.
    pub steps: Vec<Step>,
}

/// Builds the install plan for this host from the daemon executable and the
/// project directory.
///
/// `exe` is [`std::env::current_exe`]; `project_dir` is the parent of the
/// `selfhost.config.toml` this command was run beside, so the unit's working
/// directory resolves `data/` the same way the daemon does. `system` promotes a
/// per-user registration to a system one where the platform distinguishes them.
pub fn plan(exe: &Path, project_dir: &Path, system: bool) -> Result<Plan, String> {
    let argv = vec![exe.display().to_string(), "daemon".to_string()];
    let working_dir = project_dir.to_path_buf();

    match target() {
        Target::Launchd => {
            let path = plist_path(system)?;
            let domain = launchd_domain(system)?;
            Ok(Plan {
                mechanism: "launchd",
                label: LABEL.to_string(),
                contents: launchd_plist(exe, project_dir),
                wide: false,
                argv,
                working_dir,
                activate: vec![
                    Step::ignoring(vec![
                        "launchctl".into(),
                        "bootout".into(),
                        format!("{domain}/{LABEL}"),
                    ]),
                    Step::required(vec![
                        "launchctl".into(),
                        "bootstrap".into(),
                        domain,
                        path.display().to_string(),
                    ]),
                ],
                path,
            })
        }
        Target::ScheduledTask => {
            // The task XML is registered from a file rather than assembled on the
            // command line: schtasks cannot express a restart policy or a working
            // directory as flags, and those are exactly what makes this a server
            // rather than a program that ran once at boot.
            let path = project_dir.join("data").join("selfhost-daemon.task.xml");
            Ok(Plan {
                mechanism: "Windows scheduled task",
                label: TASK_NAME.to_string(),
                contents: scheduled_task_xml(exe, project_dir),
                wide: true,
                argv,
                working_dir,
                activate: vec![Step::required(vec![
                    "schtasks".into(),
                    "/Create".into(),
                    "/TN".into(),
                    TASK_NAME.into(),
                    "/XML".into(),
                    path.display().to_string(),
                    "/F".into(),
                ])],
                path,
            })
        }
        Target::Systemd => {
            let path = systemd_path(system)?;
            let mut reload = vec!["systemctl".to_string()];
            let mut enable = vec!["systemctl".to_string()];
            if !system {
                reload.push("--user".into());
                enable.push("--user".into());
            }
            reload.push("daemon-reload".into());
            enable.extend(["enable".into(), "--now".into(), SYSTEMD_UNIT.into()]);
            Ok(Plan {
                mechanism: "systemd",
                label: SYSTEMD_UNIT.to_string(),
                contents: systemd_unit(exe, project_dir, system),
                wide: false,
                argv,
                working_dir,
                activate: vec![Step::required(reload), Step::required(enable)],
                path,
            })
        }
        Target::Unsupported => Err(unsupported()),
    }
}

/// Builds the uninstall plan for this host.
///
/// Independent of the executable and project directory: a launchd label, a task
/// name and a systemd unit name are enough to unregister, and asking for a
/// config that may already be gone would make removal need the very thing an
/// operator is trying to remove.
pub fn uninstall_plan(system: bool) -> Result<UninstallPlan, String> {
    match target() {
        Target::Launchd => {
            let domain = launchd_domain(system)?;
            Ok(UninstallPlan {
                mechanism: "launchd",
                label: LABEL.to_string(),
                path: Some(plist_path(system)?),
                steps: vec![Step::ignoring(vec![
                    "launchctl".into(),
                    "bootout".into(),
                    format!("{domain}/{LABEL}"),
                ])],
            })
        }
        Target::ScheduledTask => Ok(UninstallPlan {
            mechanism: "Windows scheduled task",
            label: TASK_NAME.to_string(),
            path: None,
            steps: vec![Step::required(vec![
                "schtasks".into(),
                "/Delete".into(),
                "/TN".into(),
                TASK_NAME.into(),
                "/F".into(),
            ])],
        }),
        Target::Systemd => {
            let mut disable = vec!["systemctl".to_string()];
            let mut reload = vec!["systemctl".to_string()];
            if !system {
                disable.push("--user".into());
                reload.push("--user".into());
            }
            disable.extend(["disable".into(), "--now".into(), SYSTEMD_UNIT.into()]);
            reload.push("daemon-reload".into());
            Ok(UninstallPlan {
                mechanism: "systemd",
                label: SYSTEMD_UNIT.to_string(),
                path: Some(systemd_path(system)?),
                // Disable first (it stops and unlinks the unit), remove the file,
                // then reload so systemd forgets the unit that is now gone.
                steps: vec![Step::ignoring(disable), Step::required(reload)],
            })
        }
        Target::Unsupported => Err(unsupported()),
    }
}

/// Writes the unit and runs the commands that register and start it.
pub fn carry_out(plan: &Plan) -> Result<(), String> {
    if let Some(parent) = plan.path.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|error| format!("cannot create {}: {error}", parent.display()))?;
    }
    // The launchd job writes its log into data/; create it now so the first
    // start does not fail on a missing directory.
    let _ = std::fs::create_dir_all(plan.working_dir.join("data"));

    write_unit(&plan.path, &plan.contents, plan.wide)?;
    println!("  wrote    {}", plan.path.display());

    for step in &plan.activate {
        run(step)?;
    }
    Ok(())
}

/// Runs the commands that unregister the service, then removes its unit file.
pub fn carry_out_uninstall(plan: &UninstallPlan) -> Result<(), String> {
    for step in &plan.steps {
        run(step)?;
    }
    if let Some(path) = &plan.path {
        match std::fs::remove_file(path) {
            Ok(()) => println!("  removed  {}", path.display()),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(format!("cannot remove {}: {error}", path.display())),
        }
    }
    Ok(())
}

/// Reports whether the daemon is currently registered, by asking the service
/// manager directly.
///
/// Read-only: it runs the manager's own query command with inherited output, so
/// what the operator sees is `launchctl`/`schtasks`/`systemctl`'s own words. A
/// non-zero exit means "not registered", which is reported as guidance rather
/// than as an error, so `service status` never fails a script for the ordinary
/// answer of "not installed".
pub fn status(system: bool) -> Result<(), String> {
    let query = match target() {
        Target::Launchd => {
            vec!["launchctl".into(), "print".into(), format!("{}/{LABEL}", launchd_domain(system)?)]
        }
        Target::ScheduledTask => vec![
            "schtasks".into(),
            "/Query".into(),
            "/TN".into(),
            TASK_NAME.into(),
            "/V".into(),
            "/FO".into(),
            "LIST".into(),
        ],
        Target::Systemd => {
            let mut query = vec!["systemctl".to_string()];
            if !system {
                query.push("--user".into());
            }
            query.extend(["status".into(), SYSTEMD_UNIT.into()]);
            query
        }
        Target::Unsupported => return Err(unsupported()),
    };

    let (program, args) = query.split_first().expect("a query always names a program");
    println!("$ {}\n", query.join(" "));
    let status = Command::new(program)
        .args(args)
        .status()
        .map_err(|error| format!("could not run {program}: {error}"))?;

    if !status.success() {
        println!("\nThe daemon is not registered as a service here.");
        println!("Install it with:  selfhost service install");
    }
    Ok(())
}

/// Asks, on the terminal, whether to go ahead.
///
/// Anything other than a typed `yes` is a no, matching [`crate::teardown::confirmed`]:
/// registering a boot service is not something a stray keystroke should do.
pub fn confirm(prompt: &str) -> bool {
    print!("\n{prompt} Type yes to confirm: ");
    if std::io::stdout().flush().is_err() {
        return false;
    }
    let mut answer = String::new();
    if std::io::stdin().read_line(&mut answer).is_err() {
        return false;
    }
    answer.trim().eq_ignore_ascii_case("yes")
}

/// The launchd plist for `selfhost daemon`, mirroring `scripts/launchd.sh`.
fn launchd_plist(exe: &Path, working_dir: &Path) -> String {
    let exe = xml_escape(&exe.display().to_string());
    let dir = xml_escape(&working_dir.display().to_string());
    format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n\
<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n\
<plist version=\"1.0\">\n\
<dict>\n\
    <key>Label</key><string>{LABEL}</string>\n\
    <key>ProgramArguments</key>\n\
    <array>\n\
        <string>{exe}</string>\n\
        <string>daemon</string>\n\
    </array>\n\
    <key>WorkingDirectory</key><string>{dir}</string>\n\
    <key>RunAtLoad</key><true/>\n\
    <key>KeepAlive</key><true/>\n\
    <key>StandardOutPath</key><string>{dir}/data/launchd-daemon.log</string>\n\
    <key>StandardErrorPath</key><string>{dir}/data/launchd-daemon.log</string>\n\
</dict>\n\
</plist>\n"
    )
}

/// The Windows Task Scheduler XML for `selfhost daemon`.
///
/// A boot trigger, the `SYSTEM` account at the highest run level, and the
/// restart policy `scripts/install-service.ps1` sets: three retries a minute
/// apart, no execution-time limit. Declared UTF-16 because that is how Task
/// Scheduler stores and re-exports its XML, and [`write_unit`] writes it as
/// UTF-16 to match.
fn scheduled_task_xml(exe: &Path, working_dir: &Path) -> String {
    let exe = xml_escape(&exe.display().to_string());
    let dir = xml_escape(&working_dir.display().to_string());
    format!(
        "<?xml version=\"1.0\" encoding=\"UTF-16\"?>\n\
<Task version=\"1.2\" xmlns=\"http://schemas.microsoft.com/windows/2004/02/mit/task\">\n\
  <RegistrationInfo>\n\
    <Description>selfhost daemon — supervised services and the control API</Description>\n\
  </RegistrationInfo>\n\
  <Triggers>\n\
    <BootTrigger><Enabled>true</Enabled></BootTrigger>\n\
  </Triggers>\n\
  <Principals>\n\
    <Principal id=\"Author\">\n\
      <UserId>S-1-5-18</UserId>\n\
      <RunLevel>HighestAvailable</RunLevel>\n\
    </Principal>\n\
  </Principals>\n\
  <Settings>\n\
    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>\n\
    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>\n\
    <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>\n\
    <StartWhenAvailable>true</StartWhenAvailable>\n\
    <ExecutionTimeLimit>PT0S</ExecutionTimeLimit>\n\
    <RestartOnFailure>\n\
      <Interval>PT1M</Interval>\n\
      <Count>3</Count>\n\
    </RestartOnFailure>\n\
  </Settings>\n\
  <Actions Context=\"Author\">\n\
    <Exec>\n\
      <Command>{exe}</Command>\n\
      <Arguments>daemon</Arguments>\n\
      <WorkingDirectory>{dir}</WorkingDirectory>\n\
    </Exec>\n\
  </Actions>\n\
</Task>\n"
    )
}

/// The systemd unit for `selfhost daemon`.
///
/// `WantedBy` differs by scope: a system unit is pulled in by
/// `multi-user.target` so it runs at boot with nobody logged in, a `--user` unit
/// by `default.target` so it runs when the operator's session starts.
fn systemd_unit(exe: &Path, working_dir: &Path, system: bool) -> String {
    let wanted_by = if system { "multi-user.target" } else { "default.target" };
    format!(
        "[Unit]\n\
Description=selfhost daemon — supervised services and the control API\n\
After=network-online.target\n\
Wants=network-online.target\n\
\n\
[Service]\n\
Type=simple\n\
ExecStart={exe} daemon\n\
WorkingDirectory={dir}\n\
Restart=on-failure\n\
RestartSec=5\n\
\n\
[Install]\n\
WantedBy={wanted_by}\n",
        exe = exe.display(),
        dir = working_dir.display()
    )
}

/// Escapes the three characters that would otherwise break XML text.
///
/// `&` first, so the entities this introduces are not themselves re-escaped.
fn xml_escape(raw: &str) -> String {
    raw.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;")
}

/// The LaunchAgents/LaunchDaemons path for this scope.
fn plist_path(system: bool) -> Result<PathBuf, String> {
    if system {
        Ok(PathBuf::from("/Library/LaunchDaemons").join(format!("{LABEL}.plist")))
    } else {
        Ok(home()?.join("Library/LaunchAgents").join(format!("{LABEL}.plist")))
    }
}

/// The systemd unit path for this scope.
fn systemd_path(system: bool) -> Result<PathBuf, String> {
    if system {
        Ok(PathBuf::from("/etc/systemd/system").join(SYSTEMD_UNIT))
    } else {
        Ok(home()?.join(".config/systemd/user").join(SYSTEMD_UNIT))
    }
}

/// The launchctl domain target for this scope.
///
/// `system` for a LaunchDaemon; `gui/<uid>` for a per-user LaunchAgent — the
/// exact target `scripts/launchd.sh` uses. The uid is read with `id -u` rather
/// than a libc call so this file needs no `unsafe`.
fn launchd_domain(system: bool) -> Result<String, String> {
    if system {
        return Ok("system".to_string());
    }
    let output = Command::new("id")
        .arg("-u")
        .output()
        .map_err(|error| format!("could not run id -u to find the login session: {error}"))?;
    if !output.status.success() {
        return Err("id -u did not report a user id".to_string());
    }
    Ok(format!("gui/{}", String::from_utf8_lossy(&output.stdout).trim()))
}

/// The current user's home directory, or a reason it could not be found.
fn home() -> Result<PathBuf, String> {
    std::env::var_os("HOME")
        .map(PathBuf::from)
        .ok_or_else(|| "HOME is not set, so the per-user unit directory cannot be located".to_string())
}

/// Writes `contents` to `path`, as UTF-16LE with a BOM when `wide`.
///
/// The Windows task loader reads its XML as Unicode; writing the declared
/// UTF-16 as UTF-16 keeps the bytes and the declaration honest.
fn write_unit(path: &Path, contents: &str, wide: bool) -> Result<(), String> {
    let bytes = if wide {
        let mut bytes = vec![0xFF, 0xFE];
        for unit in contents.encode_utf16() {
            bytes.extend_from_slice(&unit.to_le_bytes());
        }
        bytes
    } else {
        contents.as_bytes().to_vec()
    };
    std::fs::write(path, bytes).map_err(|error| format!("cannot write {}: {error}", path.display()))
}

/// Runs one step, reporting a fatal failure and letting a tolerated one pass.
fn run(step: &Step) -> Result<(), String> {
    let (program, args) = step.argv.split_first().ok_or("an empty command cannot be run")?;
    println!("  run      {}", step.argv.join(" "));
    let output = Command::new(program)
        .args(args)
        .output()
        .map_err(|error| format!("could not run {program}: {error}"))?;
    if !output.status.success() && !step.ignore_failure {
        let detail = String::from_utf8_lossy(&output.stderr);
        let detail = detail.trim();
        return Err(if detail.is_empty() {
            format!("{} exited unsuccessfully ({})", step.argv.join(" "), output.status)
        } else {
            format!("{} failed: {detail}", step.argv.join(" "))
        });
    }
    Ok(())
}

/// The message for an operating system with no supported service manager.
fn unsupported() -> String {
    "no service manager is supported on this operating system — selfhost can register with \
     launchd (macOS), systemd (Linux), or the Windows scheduled-task service, and this is none \
     of them"
        .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_launchd_plist_runs_the_daemon_and_keeps_it_alive() {
        let plist = launchd_plist(Path::new("/opt/selfhost/selfhost"), Path::new("/srv/site"));
        assert!(plist.contains("<string>com.selfhost.daemon</string>"));
        assert!(plist.contains("<string>/opt/selfhost/selfhost</string>"));
        assert!(plist.contains("<string>daemon</string>"));
        assert!(plist.contains("<key>RunAtLoad</key><true/>"));
        assert!(plist.contains("<key>KeepAlive</key><true/>"));
        assert!(plist.contains("<string>/srv/site</string>"), "the working directory is set");
    }

    #[test]
    fn the_task_xml_starts_at_boot_as_system_with_a_restart_policy() {
        let xml = scheduled_task_xml(Path::new("C:\\selfhost\\selfhost.exe"), Path::new("C:\\site"));
        assert!(xml.contains("<BootTrigger>"), "it starts at boot");
        assert!(xml.contains("<UserId>S-1-5-18</UserId>"), "it runs as SYSTEM");
        assert!(xml.contains("<RunLevel>HighestAvailable</RunLevel>"));
        assert!(xml.contains("<Count>3</Count>") && xml.contains("<Interval>PT1M</Interval>"));
        assert!(xml.contains("<Arguments>daemon</Arguments>"));
        assert!(xml.contains("C:\\selfhost\\selfhost.exe"));
    }

    #[test]
    fn a_system_and_a_user_systemd_unit_are_wanted_by_different_targets() {
        let system = systemd_unit(Path::new("/usr/bin/selfhost"), Path::new("/srv"), true);
        assert!(system.contains("WantedBy=multi-user.target"));
        assert!(system.contains("ExecStart=/usr/bin/selfhost daemon"));

        let user = systemd_unit(Path::new("/usr/bin/selfhost"), Path::new("/srv"), false);
        assert!(user.contains("WantedBy=default.target"));
    }

    #[test]
    fn xml_special_characters_in_a_path_are_escaped() {
        assert_eq!(xml_escape("a & b <c>"), "a &amp; b &lt;c&gt;");
    }

    #[test]
    fn the_plan_targets_this_host_and_runs_the_daemon() {
        let plan = plan(Path::new("/x/selfhost"), Path::new("/srv/site"), false)
            .expect("this host has a supported service manager");
        assert_eq!(plan.argv, vec!["/x/selfhost".to_string(), "daemon".to_string()]);
        assert_eq!(plan.working_dir, PathBuf::from("/srv/site"));
        assert!(!plan.contents.is_empty(), "there is a unit to write");
        assert!(!plan.activate.is_empty(), "and a command to register it");
    }

    #[test]
    fn install_and_uninstall_name_the_same_unit() {
        let install = plan(Path::new("/x/selfhost"), Path::new("/srv"), false).expect("supported");
        let uninstall = uninstall_plan(false).expect("supported");
        assert_eq!(install.label, uninstall.label, "uninstall must target what install created");
    }

    #[test]
    fn the_first_activation_step_tolerates_there_being_nothing_to_replace() {
        // A repeatable install unloads any previous copy first; on the very first
        // run there is nothing loaded, and that is not a failure.
        let plan = plan(Path::new("/x/selfhost"), Path::new("/srv"), false).expect("supported");
        if plan.mechanism == "launchd" {
            assert!(plan.activate[0].ignore_failure, "the unload-first step is tolerant");
        }
    }
}

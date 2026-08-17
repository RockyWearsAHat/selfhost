//! Registering the daemon with the operating system's service manager.
//!
//! # Why this is generated, not a shipped script
//!
//! `scripts/macos/launchd.sh` and `scripts/windows/install-service.ps1` each hard-code one
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
//! - **macOS** — a launchd job, mirroring `scripts/macos/launchd.sh`: `RunAtLoad`,
//!   `KeepAlive`, and `selfhost daemon` as its program. A per-user LaunchAgent by
//!   default; `--system` promotes it to a LaunchDaemon under
//!   `/Library/LaunchDaemons` so it runs with nobody logged in.
//! - **Windows** — a Task Scheduler task triggered at boot, running as the
//!   `SYSTEM` account (`S-1-5-18`) at the highest run level, restarted three
//!   times a minute apart if it dies and with no execution-time limit — the same
//!   policy `scripts/windows/install-service.ps1` sets, expressed as task XML.
//!
//!   One caveat, learned live: Task Scheduler's `RestartOnFailure` covers a
//!   task that *fails to run* — it does **not** re-run a program that started
//!   and then exited, whatever its exit code. A daemon that exits on purpose
//!   (a self-update's restart, exit 75) would therefore stay down. So the task
//!   does not point at the daemon at all: it points at a generated keep-alive
//!   wrapper ([`keep_alive_script`]), a batch loop that reruns the program
//!   after a pause. That is what launchd's `KeepAlive` and systemd's
//!   `Restart=` provide natively, written out on the one platform that has
//!   no equivalent.
//!
//! - **Linux** — a systemd unit, a `--user` unit by default and a system unit
//!   under `/etc/systemd/system` with `--system`.
//!
//! # One service, not several
//!
//! There is exactly one registration per machine, because there is exactly one
//! process. Earlier installations registered the proxy and the daemon
//! separately; that duplication is what [`plan`] and [`uninstall_plan`] remove
//! by name — on *install* too, not only on removal, because an upgraded box
//! that kept both would run a second proxy racing this one for `:443`.
//!
//! Two Windows tasks are deliberately **not** in that list, because neither is
//! actually superseded by the daemon:
//!
//! - `selfhost-vpn` runs the Secure-VPN server, not this binary — the VPN is a
//!   documented trust-anchor exception (`docs/VPN.md`) that stays its own
//!   process rather than being reimplemented here. The *installed* path is
//!   `C:\ProgramData\selfhost\securevpn\server.py`, which is what
//!   `scripts/securevpn/install-vpn-service.ps1` registers; the *source* it is
//!   copied from is the operator's own repository,
//!   `https://github.com/RockyWearsAHat/Secure-VPN.git`, where `server.py` has
//!   been committed all along beside the rest of the implementation.
//!
//!   Earlier revisions of this comment named `scripts/securevpn/server.py` — a
//!   path inside *this* repository that has never held anything — and four
//!   documents then recorded the whole VPN implementation as missing and
//!   therefore unauditable on the strength of it. **That was the origin of the
//!   error and it was wrong.** The code was always in a repository, just not
//!   this one: exactly the `rui` situation `docs/principles.dx` describes, which
//!   is a two-repositories problem and not a missing-code one. A path written
//!   down carelessly in a comment about scheduled tasks is what made a
//!   reviewable component look like an unreviewable one for as long as nobody
//!   checked it.
//! - `selfhost-lan-dns` runs `selfhost lan-dns --lan-ip <ip>`, which serves DNS
//!   with **zero `[dns]` configuration** by synthesising a zone per registrable
//!   domain already claimed elsewhere in the config
//!   (`crate::lan_dns::with_synthesised_zones`). The daemon's own DNS path does
//!   not do this — it only serves a zone that `[dns].zone` names explicitly —
//!   so a box with no `[dns]` section that loses this task loses DNS
//!   entirely, for the LAN and for the public zone alike. Folding LAN DNS into
//!   the daemon is real future work, not something this list may pretend has
//!   already happened.
//!
//! Neither is touched by install or uninstall, so tearing either down as a
//! side effect of registering the daemon is a regression, not a cleanup.

use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::Command;

/// The launchd label / systemd unit stem the daemon is registered under.
const LABEL: &str = "com.selfhost.daemon";

/// The Windows scheduled-task name.
const TASK_NAME: &str = "selfhost-daemon";

/// The scheduled task that serves DNS for the LAN and the public zone.
///
/// Named here, in the module that owns what a selfhost registration must look
/// like, even though its *action* is registered by
/// `scripts/windows/install-lan-dns.ps1`. That split is what let the live task be
/// created with Windows' defaults while this file emitted correct XML for a
/// different task, and nobody compared them — see [`audit_installed`].
pub const LAN_DNS_TASK_NAME: &str = "selfhost-lan-dns";

/// The scheduled task that runs the Secure-VPN server.
///
/// Not this binary and never folded into it (`docs/VPN.md`), but its *settings*
/// are still selfhost's business: a VPN killed every seventy-two hours takes the
/// admin console's only reachable route with it, which is the same outage as the
/// DNS one wearing a different hat.
pub const VPN_TASK_NAME: &str = "selfhost-vpn";

/// Every Windows scheduled task this deployment owns the settings of.
///
/// One list, so "which registrations must hold to the policy" is a fact stated
/// in one place rather than implied by three PowerShell scripts that were
/// written months apart and had already stopped agreeing.
pub const MANAGED_TASK_NAMES: &[&str] = &[TASK_NAME, LAN_DNS_TASK_NAME, VPN_TASK_NAME];

/// Scheduled tasks earlier versions installed, now folded into [`TASK_NAME`].
///
/// Removed on both install and uninstall. An upgraded box that kept `selfhost`
/// registered would start a second proxy racing the unified process for
/// `:443` — the exact half-running state the merge into one process exists to
/// make impossible. Removal tolerates absence, so this is a no-op on a machine
/// that never had it.
///
/// Deliberately excludes `selfhost-vpn` and `selfhost-lan-dns` — see the
/// module docs above for why neither is actually superseded.
const SUPERSEDED_TASK_NAMES: &[&str] = &["selfhost"];

/// The launchd label an earlier version registered the proxy under, separately
/// from the daemon. Removed for the reason [`SUPERSEDED_TASK_NAMES`] gives.
const SUPERSEDED_LAUNCHD_LABEL: &str = "com.selfhost.proxy";

/// The systemd unit file name.
const SYSTEMD_UNIT: &str = "selfhost-daemon.service";

/// One external command a plan runs, and whether its failure is fatal.
///
/// The unload-first step of a repeatable install fails cleanly the first time,
/// when there is nothing loaded to remove — the same reason `scripts/macos/launchd.sh`
/// writes `launchctl bootout … || true`. That tolerance is carried as data here
/// rather than as a special case in the runner.
#[derive(Debug)]
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
    /// A second file the unit depends on, written alongside it.
    ///
    /// Only Windows has one — the keep-alive wrapper the task invokes. Carried
    /// in the plan rather than written by [`carry_out`] directly so it is shown
    /// to the operator before anything is created, which is the whole point of
    /// this type: nothing appears on disk that the plan did not name.
    pub companion: Option<(PathBuf, String)>,
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
                companion: None,
                argv,
                working_dir,
                activate: vec![
                    Step::ignoring(vec![
                        "launchctl".into(),
                        "bootout".into(),
                        format!("{domain}/{LABEL}"),
                    ]),
                    // The separately-registered proxy an earlier version
                    // installed. Tolerated absent, so this is a no-op on a
                    // machine that never had one.
                    Step::ignoring(vec![
                        "launchctl".into(),
                        "bootout".into(),
                        format!("{domain}/{SUPERSEDED_LAUNCHD_LABEL}"),
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
            let wrapper = project_dir.join("data").join("selfhost-keepalive.cmd");

            // Delete first, register second. A superseded task left running
            // would race this one for :443 and :53.
            let mut activate: Vec<Step> = SUPERSEDED_TASK_NAMES
                .iter()
                .map(|name| {
                    Step::ignoring(vec![
                        "schtasks".into(),
                        "/Delete".into(),
                        "/TN".into(),
                        (*name).into(),
                        "/F".into(),
                    ])
                })
                .collect();
            activate.push(Step::required(vec![
                "schtasks".into(),
                "/Create".into(),
                "/TN".into(),
                TASK_NAME.into(),
                "/XML".into(),
                path.display().to_string(),
                "/F".into(),
            ]));

            Ok(Plan {
                mechanism: "Windows scheduled task",
                label: TASK_NAME.to_string(),
                contents: scheduled_task_xml(project_dir),
                wide: true,
                companion: Some((wrapper, keep_alive_script(exe, project_dir))),
                argv,
                working_dir,
                activate,
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
                companion: None,
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
                steps: vec![
                    Step::ignoring(vec![
                        "launchctl".into(),
                        "bootout".into(),
                        format!("{domain}/{LABEL}"),
                    ]),
                    // "Uninstall" has to mean *nothing selfhost starts is left
                    // registered*, so an earlier version's separate proxy job
                    // goes too. Tolerated absent.
                    Step::ignoring(vec![
                        "launchctl".into(),
                        "bootout".into(),
                        format!("{domain}/{SUPERSEDED_LAUNCHD_LABEL}"),
                    ]),
                ],
            })
        }
        Target::ScheduledTask => {
            let mut steps = vec![Step::required(vec![
                "schtasks".into(),
                "/Delete".into(),
                "/TN".into(),
                TASK_NAME.into(),
                "/F".into(),
            ])];
            steps.extend(SUPERSEDED_TASK_NAMES.iter().map(|name| {
                Step::ignoring(vec![
                    "schtasks".into(),
                    "/Delete".into(),
                    "/TN".into(),
                    (*name).into(),
                    "/F".into(),
                ])
            }));
            Ok(UninstallPlan {
                mechanism: "Windows scheduled task",
                label: TASK_NAME.to_string(),
                path: None,
                steps,
            })
        }
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

    // Before the unit, because the unit refers to it: a task registered while
    // its wrapper is missing is one that fails at the next boot rather than at
    // install time, when somebody is watching.
    if let Some((path, contents)) = &plan.companion {
        write_unit(path, contents, false)?;
        println!("  wrote    {}", path.display());
    }

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

/// The launchd plist for `selfhost daemon`, mirroring `scripts/macos/launchd.sh`.
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

/// The keep-alive wrapper the Windows task actually runs.
///
/// Task Scheduler will not restart a program that exited, so this loop does it:
/// run the daemon, and whatever it exits with, pause and run it again. That
/// covers the deliberate exit (a self-update's `75`) and a crash with the same
/// two lines, which is why it does not test the exit code — every way the
/// daemon can stop is a way it should come back.
///
/// The pause matters. Without it a daemon that fails immediately — a port held,
/// a config that stopped validating — becomes a spin that fills the log and
/// pins a core. Five seconds is long enough to keep that harmless and short
/// enough that a real restart is not noticed.
///
/// `>>` on the log rather than `>`: the reason a restart happened is in the
/// output of the run *before* it, so truncating on each start would delete the
/// evidence every time it mattered.
fn keep_alive_script(exe: &Path, working_dir: &Path) -> String {
    format!(
        "@echo off\r\n\
rem Generated by `selfhost service install`. Task Scheduler cannot restart a\r\n\
rem program that exited, so this loop is what makes the daemon keep running.\r\n\
rem Edit the config, not this file: reinstalling the service overwrites it.\r\n\
cd /d \"{dir}\"\r\n\
:loop\r\n\
\"{exe}\" daemon >> \"{dir}\\data\\selfhost-daemon.log\" 2>&1\r\n\
timeout /t 5 /nobreak > nul\r\n\
goto loop\r\n",
        exe = exe.display(),
        dir = working_dir.display(),
    )
}

/// The Windows Task Scheduler XML for the keep-alive wrapper.
///
/// A boot trigger, the `SYSTEM` account at the highest run level, and the
/// restart policy `scripts/windows/install-service.ps1` sets: three retries a minute
/// apart, no execution-time limit. Declared UTF-16 because that is how Task
/// Scheduler stores and re-exports its XML, and [`write_unit`] writes it as
/// UTF-16 to match.
///
/// The command is [`keep_alive_script`], not the daemon: see the module docs
/// for why `RestartOnFailure` is not enough on its own. `RestartOnFailure` is
/// still set, because it covers the case the wrapper cannot — the wrapper
/// itself failing to start.
fn scheduled_task_xml(working_dir: &Path) -> String {
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
{settings}\
  <Actions Context=\"Author\">\n\
    <Exec>\n\
      <Command>{dir}\\data\\selfhost-keepalive.cmd</Command>\n\
      <WorkingDirectory>{dir}</WorkingDirectory>\n\
    </Exec>\n\
  </Actions>\n\
</Task>\n",
        settings = intended_settings_xml()
    )
}

/// The `<Settings>` block **every** selfhost scheduled task must carry.
///
/// # This function is the fix for the outage
///
/// Two of these settings are not preferences. `ExecutionTimeLimit` of `PT0S`
/// means *no limit*; leave it out and Task Scheduler applies its own default of
/// `PT72H`, which kills a server three days after it starts. `RestartOnFailure`
/// is what brings it back if it dies for any other reason, and its default is
/// no restarts at all. A task carrying both defaults is a server that runs for
/// exactly seventy-two hours, once, and then is gone with its task still sitting
/// in the `Ready` state looking perfectly healthy. That is precisely what
/// happened to `selfhost-lan-dns`.
///
/// The other four are the difference between a server and a program that ran at
/// boot: `StartWhenAvailable` recovers a start that was missed because the
/// machine was off, the two battery settings stop a laptop-shaped policy from
/// stopping a server, and `IgnoreNew` means a second trigger does not start a
/// second copy to fight over `:53` or `:443`.
///
/// Pure, and shared between the XML this module *writes* and the XML it
/// *checks*, so the intent cannot be right in one place and wrong in the other.
pub fn intended_settings_xml() -> String {
    "  <Settings>\n\
    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>\n\
    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>\n\
    <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>\n\
    <StartWhenAvailable>true</StartWhenAvailable>\n\
    <ExecutionTimeLimit>PT0S</ExecutionTimeLimit>\n\
    <RestartOnFailure>\n\
      <Interval>PT1M</Interval>\n\
      <Count>3</Count>\n\
    </RestartOnFailure>\n\
  </Settings>\n"
        .to_string()
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
/// exact target `scripts/macos/launchd.sh` uses. The uid is read with `id -u` rather
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

/// Runs a sequence of steps, stopping at the first fatal failure.
///
/// Exposed so [`crate::converge`] drives the service manager through the same
/// code path an install does. A supervisor with its own idea of how to invoke
/// `schtasks` would be a second opinion about the platform, which is the class
/// of bug this whole file is now defending against.
pub fn run_steps(steps: &[Step]) -> Result<(), String> {
    for step in steps {
        run(step)?;
    }
    Ok(())
}

/// The commands that stop and start an installed registration.
///
/// End-then-run rather than a single restart verb: `schtasks` has no restart,
/// and a `/Run` against a task the scheduler still believes is executing is
/// silently ignored — which would make a repair that reported success and
/// changed nothing, the worst possible outcome for a self-healing loop. The
/// `/End` tolerates failure because a task that is already stopped is the
/// ordinary case for something being repaired.
///
/// The launchd and systemd forms are **modelled, not exercised**: no deployment
/// registers a separate DNS unit on either platform today, so nothing here has
/// ever run against a live `launchctl` or `systemctl`. They are written out
/// rather than left as a `todo!` so the shape is reviewable, and they are named
/// as unverified here rather than discovered to be wrong during an incident.
pub fn restart_steps(label: &str) -> Vec<Step> {
    match target() {
        Target::ScheduledTask => vec![
            Step::ignoring(vec!["schtasks".into(), "/End".into(), "/TN".into(), label.into()]),
            Step::required(vec!["schtasks".into(), "/Run".into(), "/TN".into(), label.into()]),
        ],
        // `kickstart -k` is one call that stops and restarts, and it is the only
        // launchd verb that does not race a `bootout`/`bootstrap` pair.
        Target::Launchd => vec![Step::required(vec![
            "launchctl".into(),
            "kickstart".into(),
            "-k".into(),
            format!("system/{label}"),
        ])],
        Target::Systemd => {
            vec![Step::required(vec!["systemctl".into(), "restart".into(), label.into()])]
        }
        Target::Unsupported => Vec::new(),
    }
}

/// The name of the registration that serves DNS separately from the daemon, if
/// this machine has one.
///
/// Asked of the machine rather than assumed from `cfg!`, because the answer is
/// not a platform constant: the production box serves DNS from
/// `selfhost-lan-dns` only because it has no `[dns]` section, and a Windows box
/// that wrote one serves `:53` from the daemon itself. Restarting a task on the
/// second kind of box would start a second nameserver to fight over the port.
///
/// `None` on macOS and Linux, where no separate DNS registration is modelled at
/// all — the daemon's own `:53` arm is the whole story there.
pub fn separate_dns_registration() -> Option<String> {
    match target() {
        Target::ScheduledTask => {
            task_exists(LAN_DNS_TASK_NAME).then(|| LAN_DNS_TASK_NAME.to_owned())
        }
        Target::Launchd | Target::Systemd | Target::Unsupported => None,
    }
}

/// Whether the service manager knows about a task by this name.
fn task_exists(name: &str) -> bool {
    Command::new("schtasks")
        .args(["/Query", "/TN", name])
        .output()
        .map(|output| output.status.success())
        .unwrap_or(false)
}

/// What one installed registration looks like, measured against what it was
/// meant to be.
#[derive(Debug, Clone)]
pub struct UnitAudit {
    /// The task name, launchd label, or systemd unit.
    pub label: String,
    /// Whether the service manager has it at all.
    pub present: bool,
    /// Each way the installed settings differ from the intended ones, in a
    /// sentence naming both the setting and what it costs.
    pub faults: Vec<String>,
    /// Why the audit could not be carried out, when it could not.
    ///
    /// Distinct from an empty `faults`, for the reason `doctor` distinguishes
    /// `Unknown` from `Pass`: a registration nobody could read is not a
    /// registration that is correct.
    pub untestable: Option<String>,
}

/// Reads every registration this deployment owns and reports how each differs
/// from what it was installed as.
///
/// # Why this check exists at all
///
/// `selfhost service install` emits correct task XML. The task that took the box
/// down was created by a *different* path — a PowerShell script, or a
/// hand-typed `schtasks /Create`, which applies Windows' defaults — and nothing
/// ever compared the two. An installer being correct is not the same as an
/// installation being correct, and only the second one keeps a server up. This
/// function asks the machine what it actually has.
///
/// Read-only. [`repair_settings`] is the writing half, and it is a separate call
/// so a check can be run without changing anything.
pub fn audit_installed(system: bool) -> Vec<UnitAudit> {
    match target() {
        Target::ScheduledTask => MANAGED_TASK_NAMES
            .iter()
            .map(|name| match read_task_xml(name) {
                Ok(None) => UnitAudit {
                    label: (*name).to_owned(),
                    present: false,
                    faults: Vec::new(),
                    untestable: None,
                },
                Ok(Some(xml)) => UnitAudit {
                    label: (*name).to_owned(),
                    present: true,
                    faults: settings_faults(&xml),
                    untestable: None,
                },
                Err(error) => UnitAudit {
                    label: (*name).to_owned(),
                    present: true,
                    faults: Vec::new(),
                    untestable: Some(error),
                },
            })
            .collect(),
        Target::Launchd => vec![audit_file(
            LABEL,
            plist_path(system).ok(),
            launchd_faults as fn(&str) -> Vec<String>,
        )],
        Target::Systemd => vec![audit_file(
            SYSTEMD_UNIT,
            systemd_path(system).ok(),
            systemd_faults as fn(&str) -> Vec<String>,
        )],
        Target::Unsupported => Vec::new(),
    }
}

/// Audits a unit that lives in a file, which is both non-Windows cases.
fn audit_file(label: &str, path: Option<PathBuf>, faults: fn(&str) -> Vec<String>) -> UnitAudit {
    let Some(path) = path else {
        return UnitAudit {
            label: label.to_owned(),
            present: false,
            faults: Vec::new(),
            untestable: Some("the per-user unit directory could not be located".to_owned()),
        };
    };
    match std::fs::read_to_string(&path) {
        Ok(text) => UnitAudit {
            label: label.to_owned(),
            present: true,
            faults: faults(&text),
            untestable: None,
        },
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => UnitAudit {
            label: label.to_owned(),
            present: false,
            faults: Vec::new(),
            untestable: None,
        },
        Err(error) => UnitAudit {
            label: label.to_owned(),
            present: true,
            faults: Vec::new(),
            untestable: Some(format!("{} could not be read: {error}", path.display())),
        },
    }
}

/// Asks the scheduler for a task's XML, or `Ok(None)` if it has no such task.
fn read_task_xml(name: &str) -> Result<Option<String>, String> {
    let output = Command::new("schtasks")
        .args(["/Query", "/TN", name, "/XML", "ONE"])
        .output()
        .map_err(|error| format!("could not run schtasks: {error}"))?;
    if !output.status.success() {
        // The scheduler says the same thing for "no such task" and for "you may
        // not look at it", and the second is worth distinguishing: a check run
        // without privilege that reported "not installed" would send somebody to
        // install a second copy of a task that is already there.
        let complaint = String::from_utf8_lossy(&output.stderr).to_lowercase();
        if complaint.contains("access is denied") {
            return Err(format!(
                "the scheduler refused to show {name} — run this from an elevated prompt"
            ));
        }
        return Ok(None);
    }
    Ok(Some(decode_task_xml(&output.stdout)))
}

/// Decodes what `schtasks /Query /XML` wrote, whichever encoding it chose.
///
/// The scheduler stores task XML as UTF-16 and hands it back with a byte-order
/// mark when the output is a pipe, and as the console's own encoding when it is
/// not. Reading the wrong one turns every element name into mojibake, and the
/// settings check would then report a perfectly correct task as having no
/// `ExecutionTimeLimit` at all — a self-repairing loop rewriting healthy tasks
/// forever. Pure, so both encodings are tested on a machine with no scheduler.
fn decode_task_xml(raw: &[u8]) -> String {
    if raw.len() >= 2 && raw[0] == 0xFF && raw[1] == 0xFE {
        let units: Vec<u16> = raw[2..]
            .chunks_exact(2)
            .map(|pair| u16::from_le_bytes([pair[0], pair[1]]))
            .collect();
        return String::from_utf16_lossy(&units);
    }
    String::from_utf8_lossy(raw).into_owned()
}

/// Every way an installed task's settings differ from [`intended_settings_xml`].
///
/// Pure, and the whole comparison lives here rather than being spread through
/// the caller, so the exact outage — `ExecutionTimeLimit` of `PT72H` and
/// `RestartCount` of zero — is a test rather than a memory.
///
/// Only the `<Settings>` element is examined. The `<Actions>`, `<Principals>`
/// and `<Triggers>` of `selfhost-lan-dns` and `selfhost-vpn` are owned by
/// whoever registered them — the VPN task runs a Python program this repository
/// does not build — and a settings audit that started rewriting what a task
/// *runs* would be a far more dangerous thing than the bug it fixes.
pub fn settings_faults(xml: &str) -> Vec<String> {
    let Some(settings) = element(xml, "Settings") else {
        return vec![
            "it has no <Settings> element at all, so every one of Task Scheduler's defaults \
             applies — including a 72-hour execution limit that kills a server three days after \
             it starts"
                .to_owned(),
        ];
    };

    let mut faults = Vec::new();

    match element(&settings, "ExecutionTimeLimit").as_deref() {
        Some("PT0S") => {}
        Some(limit) => faults.push(format!(
            "ExecutionTimeLimit is {limit}, so Task Scheduler kills this program after that long \
             and — with no restart policy — never starts it again. It must be PT0S, which means \
             no limit"
        )),
        None => faults.push(
            "ExecutionTimeLimit is not set, so Task Scheduler applies its default of PT72H and \
             kills this program every three days. It must be PT0S, which means no limit"
                .to_owned(),
        ),
    }

    match element(&settings, "RestartOnFailure") {
        None => faults.push(
            "there is no RestartOnFailure policy, so nothing starts this program again when it \
             dies. It must retry 3 times at PT1M"
                .to_owned(),
        ),
        Some(restart) => {
            let count = element(&restart, "Count").and_then(|raw| raw.parse::<u32>().ok());
            match count {
                Some(count) if count >= 3 => {}
                Some(count) => faults.push(format!(
                    "RestartOnFailure retries only {count} time(s); it must be at least 3"
                )),
                None => faults
                    .push("RestartOnFailure has no readable Count; it must be at least 3".to_owned()),
            }
            if element(&restart, "Interval").as_deref() != Some("PT1M") {
                faults.push(
                    "RestartOnFailure's Interval is not PT1M, so a restart is either hammering or \
                     minutes away from happening"
                        .to_owned(),
                );
            }
        }
    }

    for (name, wanted, cost) in [
        (
            "StartWhenAvailable",
            "true",
            "a start missed because the machine was off is never made up",
        ),
        (
            "MultipleInstancesPolicy",
            "IgnoreNew",
            "a second trigger starts a second copy to fight over the same port",
        ),
        (
            "DisallowStartIfOnBatteries",
            "false",
            "the server refuses to start whenever the machine is on battery",
        ),
        (
            "StopIfGoingOnBatteries",
            "false",
            "the server is stopped the moment the machine loses mains power",
        ),
    ] {
        let found = element(&settings, name);
        if found.as_deref() != Some(wanted) {
            let observed = found.unwrap_or_else(|| "not set".to_owned());
            faults.push(format!("{name} is {observed} and must be {wanted}, or {cost}"));
        }
    }

    faults
}

/// The same task XML with its `<Settings>` replaced by the intended block.
///
/// Everything else — the action, the principal, the triggers, the description —
/// comes back byte for byte, because those belong to whoever registered the
/// task and this repair has no business inventing them. `None` when there is
/// nowhere to put the block, which is a malformed task the caller must report
/// rather than a task to guess at.
pub fn with_intended_settings(xml: &str) -> Option<String> {
    let settings = intended_settings_xml();
    if let (Some(open), Some(close)) = (xml.find("<Settings>"), xml.find("</Settings>")) {
        let end = close + "</Settings>".len();
        // The newline the intended block ends with replaces whatever whitespace
        // followed the old element, so re-running the repair is a no-op rather
        // than a source of drifting blank lines.
        let tail = xml.get(end..)?.trim_start_matches(['\r', '\n']);
        let head = xml.get(..open)?;
        return Some(format!("{head}{}{tail}", settings.trim_start_matches(' ')));
    }
    // A task with no settings element at all: the block goes where Task
    // Scheduler's schema puts it, immediately before the actions.
    let actions = xml.find("<Actions")?;
    let head = xml.get(..actions)?;
    let tail = xml.get(actions..)?;
    // `head` already ends with the indentation of the line `<Actions` sits on,
    // so it indents the block being inserted; the same run of spaces is written
    // again to put `<Actions` back where it was.
    let indent = head.rsplit('\n').next().unwrap_or_default();
    Some(format!("{head}{}{indent}{tail}", settings.trim_start_matches(' ')))
}

/// Rewrites one registration's settings to what they were meant to be.
///
/// Returns whether anything was changed, so a caller can stay quiet about a
/// registration that was already correct. Only the settings move — see
/// [`with_intended_settings`].
///
/// Windows only in effect. On launchd and systemd this reports what is wrong and
/// refuses to act, and that refusal is deliberate rather than unfinished: the
/// launchd and systemd faults below have **never been observed on a live
/// machine**, no deployment registers a separate DNS unit on either platform,
/// and a repair that rewrote a unit file on the strength of an untested
/// comparison could take down a box this project has no way to test on.
pub fn repair_settings(label: &str) -> Result<bool, String> {
    match target() {
        Target::ScheduledTask => {
            let Some(xml) = read_task_xml(label)? else {
                return Err(format!("{label} is not registered, so there is nothing to repair"));
            };
            let Some(repaired) = with_intended_settings(&xml) else {
                return Err(format!(
                    "{label}'s XML has neither a <Settings> element nor an <Actions> element, so \
                     this repair has nowhere to put the settings and will not guess"
                ));
            };
            if repaired == xml {
                return Ok(false);
            }
            let path = std::env::temp_dir().join(format!("{label}.repair.task.xml"));
            write_unit(&path, &repaired, true)?;
            let result = run(&Step::required(vec![
                "schtasks".into(),
                "/Create".into(),
                "/TN".into(),
                label.into(),
                "/XML".into(),
                path.display().to_string(),
                "/F".into(),
            ]));
            // The repaired XML is a copy of a registration, not a secret, but it
            // is also not something to leave lying in the temporary directory.
            let _ = std::fs::remove_file(&path);
            result?;
            Ok(true)
        }
        Target::Launchd | Target::Systemd => Err(format!(
            "the settings of {label} are checked but not repaired on this platform: the \
             comparison has never been run against a live launchd or systemd, and rewriting a \
             unit file on the strength of an untested check is a worse failure than the drift"
        )),
        Target::Unsupported => Err(unsupported()),
    }
}

/// Every way an installed launchd plist differs from what [`launchd_plist`]
/// writes.
///
/// **Unverified.** This has never been run against a live launchd job. It is
/// modelled because macOS is a supported target and a check that exists is one
/// somebody can correct; it is not modelled as *working*.
///
/// launchd has no equivalent of `ExecutionTimeLimit` — nothing kills a job for
/// running too long — so the drift class that took the box down cannot occur
/// here. Its analogue is a job that is loaded but will not come back:
/// `KeepAlive` missing means a job that exits stays exited, and `RunAtLoad`
/// missing means one that never starts until somebody asks.
fn launchd_faults(plist: &str) -> Vec<String> {
    let mut faults = Vec::new();
    if !plist.contains("<key>KeepAlive</key><true/>") {
        faults.push(
            "KeepAlive is not set to true, so launchd leaves this job stopped once it exits — \
             including after a self-update, which exits on purpose"
                .to_owned(),
        );
    }
    if !plist.contains("<key>RunAtLoad</key><true/>") {
        faults.push(
            "RunAtLoad is not set to true, so this job does not start when it is loaded"
                .to_owned(),
        );
    }
    faults
}

/// Every way an installed systemd unit differs from what [`systemd_unit`]
/// writes.
///
/// **Unverified**, in the same sense as [`launchd_faults`]: never run against a
/// live `systemctl`.
///
/// `RuntimeMaxSec` is systemd's exact counterpart of the setting that caused the
/// outage — a unit carrying one is killed when it expires — so it is checked for
/// by absence. It has no unsafe default, which is why this is a check against
/// somebody having added one rather than against a default having applied.
fn systemd_faults(unit: &str) -> Vec<String> {
    let mut faults = Vec::new();
    if !unit.lines().any(|line| line.trim_start().starts_with("Restart=")) {
        faults.push(
            "there is no Restart= directive, so systemd leaves this unit stopped once it exits"
                .to_owned(),
        );
    }
    if let Some(line) =
        unit.lines().find(|line| line.trim_start().starts_with("RuntimeMaxSec="))
    {
        faults.push(format!(
            "{} is set, which is systemd's version of the setting that killed this project's DNS \
             every 72 hours; a server must have no run-time limit",
            line.trim()
        ));
    }
    faults
}

/// The text inside the first `<name>…</name>` element, trimmed.
///
/// A deliberately small reader rather than an XML parser: task XML is written by
/// Task Scheduler from a fixed schema, the elements checked here are flat and
/// unattributed, and pulling a parser into the workspace to read six values
/// would be a dependency added for a diagnostic. It returns `None` rather than
/// guessing when the element is absent, which is the case that matters — an
/// absent setting is a default applied.
fn element(xml: &str, name: &str) -> Option<String> {
    let open = format!("<{name}>");
    let close = format!("</{name}>");
    let start = xml.find(&open)? + open.len();
    let end = xml.get(start..)?.find(&close)? + start;
    Some(xml.get(start..end)?.trim().to_owned())
}

/// The message for an operating system with no supported service manager, for
/// callers outside this module.
pub fn unsupported_message() -> String {
    unsupported()
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
        let xml = scheduled_task_xml(Path::new("C:\\site"));
        assert!(xml.contains("<BootTrigger>"), "it starts at boot");
        assert!(xml.contains("<UserId>S-1-5-18</UserId>"), "it runs as SYSTEM");
        assert!(xml.contains("<RunLevel>HighestAvailable</RunLevel>"));
        assert!(xml.contains("<Count>3</Count>") && xml.contains("<Interval>PT1M</Interval>"));
    }

    #[test]
    fn the_task_runs_the_keep_alive_wrapper_rather_than_the_daemon_directly() {
        // The bug this encodes: Task Scheduler does not re-run a program that
        // exited, so pointing the task straight at the daemon leaves the box
        // down after every self-update (which exits 75 on purpose).
        let xml = scheduled_task_xml(Path::new("C:\\site"));
        assert!(
            xml.contains("C:\\site\\data\\selfhost-keepalive.cmd"),
            "the task must invoke the wrapper: {xml}"
        );
        assert!(
            !xml.contains("<Arguments>daemon</Arguments>"),
            "invoking the daemon directly is the bug: {xml}"
        );
    }

    #[test]
    fn the_keep_alive_wrapper_restarts_on_any_exit_and_pauses_between_tries() {
        let script = keep_alive_script(
            Path::new("C:\\selfhost\\selfhost.exe"),
            Path::new("C:\\site"),
        );
        assert!(script.contains(":loop") && script.contains("goto loop"), "{script}");
        assert!(script.contains("\"C:\\selfhost\\selfhost.exe\" daemon"), "{script}");
        // No exit-code test anywhere: a deliberate exit and a crash are both
        // reasons to come back, so branching on the code would be a way to
        // stay down.
        assert!(!script.contains("errorlevel"), "{script}");
        // The pause is what keeps an immediate, repeating failure from becoming
        // a spin that pins a core and floods the log.
        assert!(script.contains("timeout /t 5"), "{script}");
        // Appended, not truncated: the reason for a restart is in the previous
        // run's output.
        assert!(script.contains(">> "), "{script}");
    }

    #[test]
    fn installing_removes_the_registrations_this_one_supersedes() {
        // An upgraded box that kept the old proxy task would run a second
        // process racing this one for :443.
        for name in SUPERSEDED_TASK_NAMES {
            assert_ne!(*name, TASK_NAME, "a superseded name must not be the live one");
        }
        assert!(SUPERSEDED_TASK_NAMES.contains(&"selfhost"), "the old proxy task");
    }

    /// `selfhost-vpn` runs the box's own `server.py`, and `selfhost-lan-dns`
    /// runs `selfhost lan-dns --lan-ip <ip>` — the only thing that serves DNS
    /// with no `[dns]` section written (`crate::lan_dns::with_synthesised_zones`).
    /// Neither is folded into the daemon. If either of these ever starts
    /// asserting `true`, installing or uninstalling the daemon would tear one
    /// of them down: the VPN bridge the admin console's only reachable route
    /// depends on, or the only thing serving DNS at all on a box with no
    /// `[dns]` section.
    #[test]
    fn installing_never_touches_the_separate_vpn_or_lan_dns_tasks() {
        for name in ["selfhost-vpn", "selfhost-lan-dns"] {
            assert!(
                !SUPERSEDED_TASK_NAMES.contains(&name),
                "{name} is not this process and must survive install/uninstall"
            );
        }
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

    /// A task as Windows creates one from a bare `schtasks /Create` — which is
    /// what the live `selfhost-lan-dns` was, and why the box went dark every
    /// three days.
    const DEFAULTED_TASK: &str = "<?xml version=\"1.0\" encoding=\"UTF-16\"?>\n\
<Task version=\"1.2\" xmlns=\"http://schemas.microsoft.com/windows/2004/02/mit/task\">\n\
  <Triggers><BootTrigger><Enabled>true</Enabled></BootTrigger></Triggers>\n\
  <Settings>\n\
    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>\n\
    <DisallowStartIfOnBatteries>true</DisallowStartIfOnBatteries>\n\
    <StopIfGoingOnBatteries>true</StopIfGoingOnBatteries>\n\
    <StartWhenAvailable>false</StartWhenAvailable>\n\
    <ExecutionTimeLimit>PT72H</ExecutionTimeLimit>\n\
  </Settings>\n\
  <Actions Context=\"Author\">\n\
    <Exec><Command>C:\\Users\\Alex\\Self-Host\\target\\release\\selfhost.exe</Command>\n\
      <Arguments>lan-dns --lan-ip 192.168.1.8</Arguments></Exec>\n\
  </Actions>\n\
</Task>\n";

    #[test]
    fn the_exact_settings_that_took_dns_down_are_reported_as_faults() {
        // The incident, as a test. `ExecutionTimeLimit` of PT72H with no
        // `RestartOnFailure` is a nameserver that dies every three days and
        // never comes back, while its task sits in `Ready` looking perfect.
        let faults = settings_faults(DEFAULTED_TASK);
        let all = faults.join("\n");
        assert!(all.contains("ExecutionTimeLimit is PT72H"), "{all}");
        assert!(all.contains("no RestartOnFailure"), "{all}");
        assert!(all.contains("StartWhenAvailable"), "{all}");
        // And each fault says what it costs, not just what it is — a drift
        // report nobody can act on is a drift report nobody reads.
        assert!(all.contains("kills this program"), "{all}");
    }

    #[test]
    fn the_xml_this_module_writes_has_no_faults_against_its_own_intent() {
        // The check and the installer must not be able to disagree: an intent
        // that the installer cannot satisfy would make every healthy box report
        // drift and then be rewritten once every six hours, forever.
        assert!(
            settings_faults(&scheduled_task_xml(Path::new("C:\\site"))).is_empty(),
            "{:?}",
            settings_faults(&scheduled_task_xml(Path::new("C:\\site")))
        );
    }

    #[test]
    fn a_task_with_no_settings_element_is_a_fault_rather_than_a_pass() {
        // Every default applies, including the 72-hour one. Reading "no
        // settings" as "nothing wrong" is how the outage stayed invisible.
        let faults = settings_faults("<Task><Actions/></Task>");
        assert_eq!(faults.len(), 1);
        assert!(faults[0].contains("no <Settings> element"), "{}", faults[0]);
    }

    #[test]
    fn a_repair_rewrites_the_settings_and_leaves_the_action_untouched() {
        // The action of `selfhost-lan-dns` — and, more importantly, of
        // `selfhost-vpn`, which runs a Python program this repository does not
        // build — belongs to whoever registered it. A settings repair that
        // rewrote what a task runs would be far more dangerous than the drift.
        let repaired = with_intended_settings(DEFAULTED_TASK).expect("there is somewhere to put it");
        assert!(settings_faults(&repaired).is_empty(), "{repaired}");
        assert!(
            repaired.contains("<Arguments>lan-dns --lan-ip 192.168.1.8</Arguments>"),
            "{repaired}"
        );
        assert!(repaired.contains("<BootTrigger>"), "the trigger survives: {repaired}");
        assert!(!repaired.contains("PT72H"), "{repaired}");
    }

    #[test]
    fn repairing_a_correct_task_changes_nothing() {
        // Idempotence is what makes this safe to run every six hours: a repair
        // that reformatted the XML each pass would rewrite healthy registrations
        // forever and fill the ledger with work that was never needed.
        let good = scheduled_task_xml(Path::new("C:\\site"));
        assert_eq!(with_intended_settings(&good).as_deref(), Some(good.as_str()));
        let once = with_intended_settings(DEFAULTED_TASK).expect("repairable");
        assert_eq!(with_intended_settings(&once).as_deref(), Some(once.as_str()));
    }

    #[test]
    fn a_task_with_no_settings_element_gets_one_before_its_actions() {
        let bare = "<Task>\n  <Actions Context=\"Author\"><Exec/></Actions>\n</Task>\n";
        let repaired = with_intended_settings(bare).expect("the actions are an anchor");
        assert!(settings_faults(&repaired).is_empty(), "{repaired}");
        assert!(
            repaired.find("<Settings>") < repaired.find("<Actions"),
            "the schema wants settings before actions: {repaired}"
        );
        assert!(repaired.contains("<Exec/>"), "{repaired}");
    }

    #[test]
    fn xml_with_nowhere_to_put_settings_is_refused_rather_than_guessed_at() {
        assert_eq!(with_intended_settings("<Task></Task>"), None);
    }

    #[test]
    fn utf16_task_xml_is_decoded_rather_than_read_as_mojibake() {
        // Task Scheduler hands its XML back as UTF-16 with a byte-order mark.
        // Reading it as UTF-8 turns every element name into rubbish, the
        // settings check then finds no ExecutionTimeLimit anywhere, and the
        // repair loop rewrites healthy tasks once every six hours forever.
        let text = "<Settings><ExecutionTimeLimit>PT0S</ExecutionTimeLimit></Settings>";
        let mut utf16 = vec![0xFF, 0xFE];
        for unit in text.encode_utf16() {
            utf16.extend_from_slice(&unit.to_le_bytes());
        }
        assert_eq!(decode_task_xml(&utf16), text);
        assert_eq!(decode_task_xml(text.as_bytes()), text);
    }

    #[test]
    fn every_managed_task_is_audited_including_the_two_this_binary_does_not_install() {
        // `selfhost-lan-dns` is registered by a PowerShell script and
        // `selfhost-vpn` runs a program from another repository. Neither is
        // installed here — and both being outside this file's install path is
        // exactly why nothing ever checked their settings.
        assert!(MANAGED_TASK_NAMES.contains(&TASK_NAME));
        assert!(MANAGED_TASK_NAMES.contains(&LAN_DNS_TASK_NAME));
        assert!(MANAGED_TASK_NAMES.contains(&VPN_TASK_NAME));
        // And auditing them must never be confused with superseding them.
        for name in [LAN_DNS_TASK_NAME, VPN_TASK_NAME] {
            assert!(!SUPERSEDED_TASK_NAMES.contains(&name), "{name} must survive an install");
        }
    }

    #[test]
    fn a_restart_stops_before_it_starts() {
        // `schtasks` has no restart verb, and a `/Run` against a task the
        // scheduler still believes is executing is silently ignored — a repair
        // that reports success and changes nothing.
        let steps = restart_steps(LAN_DNS_TASK_NAME);
        assert!(!steps.is_empty(), "every supported platform has a restart");
        if steps.len() == 2 {
            assert!(steps[0].argv.contains(&"/End".to_string()), "{:?}", steps[0].argv);
            assert!(steps[0].ignore_failure, "an already-stopped task is the ordinary case");
            assert!(steps[1].argv.contains(&"/Run".to_string()), "{:?}", steps[1].argv);
            assert!(!steps[1].ignore_failure, "a start that failed is not a repair");
        }
    }

    #[test]
    fn a_launchd_job_that_would_stay_down_is_reported() {
        // Unverified against a live launchd — see the function's own note. The
        // property is still worth asserting: a plist without KeepAlive is a
        // daemon that never comes back from a self-update's deliberate exit.
        assert!(launchd_faults(&launchd_plist(Path::new("/x"), Path::new("/srv"))).is_empty());
        let faults = launchd_faults("<plist><dict></dict></plist>");
        assert_eq!(faults.len(), 2);
        assert!(faults.iter().any(|fault| fault.contains("KeepAlive")));
    }

    #[test]
    fn a_systemd_unit_with_a_run_time_limit_is_reported() {
        // RuntimeMaxSec is systemd's exact counterpart of the setting that
        // killed DNS every 72 hours.
        let good = systemd_unit(Path::new("/usr/bin/selfhost"), Path::new("/srv"), true);
        assert!(systemd_faults(&good).is_empty(), "{:?}", systemd_faults(&good));
        let limited = format!("{good}RuntimeMaxSec=259200\n");
        let faults = systemd_faults(&limited);
        assert_eq!(faults.len(), 1);
        assert!(faults[0].contains("RuntimeMaxSec"), "{}", faults[0]);
    }

    #[test]
    fn a_nested_element_is_read_from_its_own_parent() {
        // `Count` and `Interval` are only meaningful inside RestartOnFailure; a
        // reader that found them anywhere in the document would happily accept a
        // task whose restart policy is missing entirely.
        let settings = element(DEFAULTED_TASK, "Settings").expect("there is one");
        assert_eq!(element(&settings, "ExecutionTimeLimit").as_deref(), Some("PT72H"));
        assert_eq!(element(&settings, "RestartOnFailure"), None);
        assert_eq!(element("<a>  spaced  </a>", "a").as_deref(), Some("spaced"));
        assert_eq!(element("<a>unclosed", "a"), None);
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

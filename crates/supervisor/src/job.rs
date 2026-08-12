//! Tying a process tree to the daemon's own lifetime, so nothing outlives it.
//!
//! A supervised service is rarely one process. `npm start` forks node, a shell
//! script forks the program that actually binds the port, and a language
//! launcher forks its runtime. Killing the process the supervisor spawned
//! therefore kills a wrapper and reparents the real program — still running,
//! still holding the port — which is how the *next* start fails to bind and
//! blames the wrong thing.
//!
//! Unix already had the answer: [`isolate_process_group`](crate::child) puts
//! the child in its own process group and `kill(-pid, …)` reaches the whole
//! tree. This module is the Windows half, which needs a **job object** — the
//! only mechanism on that platform that owns a process *tree* rather than a
//! process.
//!
//! # The one property that matters
//!
//! `JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE` says: when the last handle to this job
//! closes, terminate everything in it. The daemon holds that handle, so the
//! handle closes exactly when the daemon stops existing — including the ways a
//! daemon stops existing that run no shutdown code at all: `TerminateProcess`,
//! a power event, a panic under `panic = "abort"`. It is the kernel, not our
//! teardown path, that does the killing, which is why this is a guarantee
//! rather than a best effort.
//!
//! That is the whole reason the job is preferred to the tidy shutdown the
//! supervisor already performs. A graceful stop is better *when it runs*; this
//! is what covers the case where nothing runs.
//!
//! # Failing safe
//!
//! Every call here degrades rather than refuses. A job that cannot be created
//! or assigned leaves the child running under the process-group flag alone —
//! exactly the behaviour this project had before job objects — and says so
//! once. A service that starts with weaker cleanup beats a service that does
//! not start, and the operator is told which one they have.

/// A handle to an operating-system job object, or nothing on platforms that
/// have no such concept.
///
/// Dropping it is what kills the tree on Windows, so it is held for as long as
/// the processes inside it should live. On Unix this is an empty value: the
/// process group set at spawn already does the job, and pretending otherwise
/// would mean two mechanisms to keep in step.
#[derive(Debug)]
pub struct Job {
    #[cfg(windows)]
    handle: Option<windows::Handle>,
    /// Keeps the type inhabited and the field list non-empty off Windows.
    #[cfg(not(windows))]
    _unsupported: (),
}

impl Job {
    /// Creates a job that kills its members when this value is dropped.
    ///
    /// Never fails: a platform without job objects, or a kernel that refuses to
    /// make one, yields a `Job` that owns nothing. [`Job::adopt`] then does
    /// nothing too, and the caller's process-group handling is what cleans up.
    pub fn kill_on_drop() -> Self {
        #[cfg(windows)]
        {
            Self { handle: windows::create_killing_job() }
        }
        #[cfg(not(windows))]
        {
            Self { _unsupported: () }
        }
    }

    /// Puts an already-spawned child, and everything it goes on to start, into
    /// this job.
    ///
    /// Returns whether the child is actually covered, so a caller can say which
    /// guarantee is in force rather than assume the stronger one. A `false` here
    /// is not fatal: it means cleanup falls back to the process group.
    ///
    /// Assigning *after* spawn rather than creating the process suspended is
    /// deliberate. The race it admits is real but tiny — a process that forks
    /// within the microseconds before assignment escapes — and closing it needs
    /// `CreateProcess` with `CREATE_SUSPENDED`, which `tokio::process` does not
    /// expose. The alternative is hand-rolling process creation, which would put
    /// a far larger and less-tested surface underneath every service on the box
    /// to cover a window no real service startup lands in.
    #[cfg_attr(not(windows), allow(unused_variables))]
    pub fn adopt(&self, child: &tokio::process::Child) -> bool {
        #[cfg(windows)]
        {
            let Some(handle) = self.handle.as_ref() else { return false };
            let Some(process) = child.raw_handle() else { return false };
            windows::assign(handle, process)
        }
        #[cfg(not(windows))]
        {
            false
        }
    }

    /// Kills every process in the job now, without waiting for the drop.
    ///
    /// This is the Windows answer to `kill(-pid, SIGKILL)`: it reaches the whole
    /// tree, including the grandchildren a wrapper started. Returns whether the
    /// job was there to be terminated, so the caller can fall back to killing
    /// the direct child alone.
    pub fn terminate(&self) -> bool {
        #[cfg(windows)]
        {
            self.handle.as_ref().is_some_and(windows::terminate)
        }
        #[cfg(not(windows))]
        {
            false
        }
    }

    /// Whether this job actually owns anything.
    ///
    /// Reported rather than inferred: "no lingering processes" is a promise, and
    /// a caller that cannot keep it should be able to say so instead of
    /// printing it anyway.
    pub fn is_active(&self) -> bool {
        #[cfg(windows)]
        {
            self.handle.is_some()
        }
        #[cfg(not(windows))]
        {
            false
        }
    }
}

#[cfg(windows)]
mod windows {
    //! The five Win32 calls a job object needs, declared rather than depended
    //! on.
    //!
    //! The same reasoning the rest of this project applies to libc: these are
    //! the operating system, and five symbols are a smaller surface than a
    //! binding crate with its own release cadence and its own view of which
    //! Windows versions exist.

    use std::os::windows::io::RawHandle;

    /// An owned kernel handle, closed on drop.
    ///
    /// The close is what triggers `KILL_ON_JOB_CLOSE`, so this type existing —
    /// rather than a bare handle nobody owns — is what makes the guarantee
    /// hold.
    #[derive(Debug)]
    pub struct Handle(isize);

    impl Drop for Handle {
        fn drop(&mut self) {
            #[allow(unsafe_code)]
            unsafe {
                CloseHandle(self.0);
            }
        }
    }

    // Handles are kernel objects, not thread-local state: the supervisor holds
    // one across tasks that tokio may move between threads.
    #[allow(unsafe_code)]
    unsafe impl Send for Handle {}
    #[allow(unsafe_code)]
    unsafe impl Sync for Handle {}

    /// `JOBOBJECT_BASIC_LIMIT_INFORMATION`, laid out as the kernel expects.
    ///
    /// Every field is present even though only `limit_flags` is set: the struct
    /// is passed by size, and a short one is a buffer overread in the kernel's
    /// direction. `repr(C)` supplies the padding the C declaration implies.
    #[repr(C)]
    #[derive(Default)]
    struct BasicLimitInformation {
        per_process_user_time_limit: i64,
        per_job_user_time_limit: i64,
        limit_flags: u32,
        minimum_working_set_size: usize,
        maximum_working_set_size: usize,
        active_process_limit: u32,
        affinity: usize,
        priority_class: u32,
        scheduling_class: u32,
    }

    /// `IO_COUNTERS`. Never read here; present so the extended struct below is
    /// the size the kernel validates against.
    #[repr(C)]
    #[derive(Default)]
    struct IoCounters {
        read_operation_count: u64,
        write_operation_count: u64,
        other_operation_count: u64,
        read_transfer_count: u64,
        write_transfer_count: u64,
        other_transfer_count: u64,
    }

    /// `JOBOBJECT_EXTENDED_LIMIT_INFORMATION` — the class that carries
    /// `KILL_ON_JOB_CLOSE`.
    #[repr(C)]
    #[derive(Default)]
    struct ExtendedLimitInformation {
        basic_limit_information: BasicLimitInformation,
        io_info: IoCounters,
        process_memory_limit: usize,
        job_memory_limit: usize,
        peak_process_memory_used: usize,
        peak_job_memory_used: usize,
    }

    /// Terminate every process in the job when its last handle closes. The one
    /// flag this module exists to set.
    const JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE: u32 = 0x0000_2000;

    /// `JobObjectExtendedLimitInformation`, the information class of the struct
    /// above.
    const JOB_OBJECT_EXTENDED_LIMIT_INFORMATION: u32 = 9;

    /// What `CreateJobObjectW` answers on failure.
    const NULL_HANDLE: isize = 0;

    #[allow(unsafe_code)]
    unsafe extern "system" {
        fn CreateJobObjectW(attributes: *mut core::ffi::c_void, name: *const u16) -> isize;
        fn SetInformationJobObject(
            job: isize,
            class: u32,
            information: *const core::ffi::c_void,
            length: u32,
        ) -> i32;
        fn AssignProcessToJobObject(job: isize, process: isize) -> i32;
        fn TerminateJobObject(job: isize, exit_code: u32) -> i32;
        fn CloseHandle(object: isize) -> i32;
    }

    /// Creates an unnamed job whose members die with it, or `None` with the
    /// reason reported once.
    ///
    /// Unnamed deliberately: a named job is a shared object another process on
    /// the machine could open a handle to, and a handle it holds open is one
    /// this daemon's death would not close — which is precisely the guarantee
    /// being bought here.
    pub fn create_killing_job() -> Option<Handle> {
        #[allow(unsafe_code)]
        let raw = unsafe { CreateJobObjectW(std::ptr::null_mut(), std::ptr::null()) };
        if raw == NULL_HANDLE {
            eprintln!(
                "supervisor: could not create a job object ({}); services will be cleaned up \
                 by process group alone, so a wrapper's grandchildren may survive a crash",
                std::io::Error::last_os_error()
            );
            return None;
        }
        let handle = Handle(raw);

        let mut limits = ExtendedLimitInformation::default();
        limits.basic_limit_information.limit_flags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;

        #[allow(unsafe_code)]
        let set = unsafe {
            SetInformationJobObject(
                handle.0,
                JOB_OBJECT_EXTENDED_LIMIT_INFORMATION,
                (&raw const limits).cast(),
                size_of::<ExtendedLimitInformation>() as u32,
            )
        };
        if set == 0 {
            // The job exists but would *not* kill its members, which is worse
            // than no job: it would look like cover that is not there. Dropping
            // the handle closes it and leaves the honest fallback in place.
            eprintln!(
                "supervisor: a job object was created but would not take the kill-on-close \
                 limit ({}); falling back to process-group cleanup",
                std::io::Error::last_os_error()
            );
            return None;
        }
        Some(handle)
    }

    /// Adds one process, and its future descendants, to the job.
    pub fn assign(job: &Handle, process: RawHandle) -> bool {
        #[allow(unsafe_code)]
        unsafe {
            AssignProcessToJobObject(job.0, process as isize) != 0
        }
    }

    /// Kills every process currently in the job.
    ///
    /// The exit code is the one the kernel reports for each victim; `1` marks
    /// them as having been ended rather than having finished.
    pub fn terminate(job: &Handle) -> bool {
        #[allow(unsafe_code)]
        unsafe {
            TerminateJobObject(job.0, 1) != 0
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_job_is_always_constructible_even_where_the_concept_does_not_exist() {
        // The contract every caller relies on: this never fails, so no start
        // path has to branch on whether the platform has job objects.
        let job = Job::kill_on_drop();
        // On Unix there is nothing to own; on Windows there should be.
        assert_eq!(job.is_active(), cfg!(windows));
    }

    #[test]
    fn an_inactive_job_reports_that_it_cleaned_nothing_up() {
        // Off Windows the process group is the mechanism, and `terminate` must
        // say it did nothing so the caller falls back rather than believing the
        // tree is gone.
        #[cfg(not(windows))]
        {
            let job = Job::kill_on_drop();
            assert!(!job.terminate());
            assert!(!job.is_active());
        }
    }

    #[tokio::test]
    #[cfg(windows)]
    async fn a_job_kills_the_tree_when_the_last_handle_closes() {
        use std::process::Stdio;
        // A child that would outlive its parent for two minutes if nothing
        // killed it, so "still running" and "already exited" cannot be
        // confused by timing.
        let mut command = tokio::process::Command::new("cmd.exe");
        command.args(["/C", "timeout /T 120 /NOBREAK"]).stdout(Stdio::null()).stderr(Stdio::null());

        let job = Job::kill_on_drop();
        let mut child = command.spawn().expect("spawn a sleeper");
        assert!(job.adopt(&child), "the child should be covered by the job");

        drop(job);

        let ended = tokio::time::timeout(std::time::Duration::from_secs(20), child.wait()).await;
        assert!(ended.is_ok(), "closing the job's last handle must kill its members");
    }
}

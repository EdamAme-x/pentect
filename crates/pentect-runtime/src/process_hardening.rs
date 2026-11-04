//! Keeps crash dumps from carrying the process-local keys and recovery
//! ciphertext out of memory. Best effort: a failure leaves the OS default.

/// Disables core dumps for this process. Call once, first thing in `main`.
pub fn disable_crash_dumps() {
    // Linux: also blocks same-user ptrace and /proc/<pid>/mem reads. The flag
    // resets on execve, so spawned agents are unaffected.
    #[cfg(target_os = "linux")]
    unsafe {
        libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0);
    }
    // Other Unix: only lower the soft limit so children keep their hard limit.
    #[cfg(all(unix, not(target_os = "linux")))]
    unsafe {
        let mut limit = libc::rlimit {
            rlim_cur: 0,
            rlim_max: 0,
        };
        if libc::getrlimit(libc::RLIMIT_CORE, &mut limit) == 0 {
            limit.rlim_cur = 0;
            libc::setrlimit(libc::RLIMIT_CORE, &limit);
        }
    }
    // Windows: keep the heap, which holds the keys and recovery map, out of
    // Windows Error Reporting dumps. Stacks are still captured; excluding the
    // process entirely needs a persistent per-user registry entry, which a
    // CLI should not write on its own.
    #[cfg(windows)]
    unsafe {
        use windows_sys::Win32::System::ErrorReporting::{
            WerSetFlags, WER_FAULT_REPORTING_FLAG_NOHEAP,
        };
        WerSetFlags(WER_FAULT_REPORTING_FLAG_NOHEAP);
    }
}

#[cfg(test)]
mod tests {
    #[cfg(target_os = "linux")]
    #[test]
    fn linux_process_is_not_dumpable() {
        super::disable_crash_dumps();
        assert_eq!(unsafe { libc::prctl(libc::PR_GET_DUMPABLE) }, 0);
    }

    #[cfg(all(unix, not(target_os = "linux")))]
    #[test]
    fn unix_core_limit_is_zero() {
        super::disable_crash_dumps();
        let mut limit = libc::rlimit {
            rlim_cur: 1,
            rlim_max: 1,
        };
        assert_eq!(unsafe { libc::getrlimit(libc::RLIMIT_CORE, &mut limit) }, 0);
        assert_eq!(limit.rlim_cur, 0);
    }

    #[cfg(windows)]
    #[test]
    fn windows_error_reports_exclude_heap() {
        use windows_sys::Win32::System::ErrorReporting::{
            WerGetFlags, WER_FAULT_REPORTING_FLAG_NOHEAP,
        };
        use windows_sys::Win32::System::Threading::GetCurrentProcess;
        super::disable_crash_dumps();
        let mut flags = 0;
        assert_eq!(unsafe { WerGetFlags(GetCurrentProcess(), &mut flags) }, 0);
        assert_ne!(flags & WER_FAULT_REPORTING_FLAG_NOHEAP, 0);
    }
}

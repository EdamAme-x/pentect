use crossterm::{
    cursor::Show,
    event::{DisableBracketedPaste, DisableMouseCapture},
    execute,
    style::ResetColor,
    terminal::{EnableLineWrap, LeaveAlternateScreen},
};
use std::io::{IsTerminal, Write};

pub(crate) struct IgnoreCtrlCGuard {
    active: bool,
}

impl IgnoreCtrlCGuard {
    pub(crate) fn new() -> Self {
        let active = ignore_ctrl_c_for_parent_process();
        Self { active }
    }
}

impl Drop for IgnoreCtrlCGuard {
    fn drop(&mut self) {
        if self.active {
            restore_ctrl_c_for_parent_process();
            restore_after_tui();
        }
    }
}

pub(crate) fn restore_after_tui() {
    restore_platform_console_mode();
    restore_ansi_state();
}

const ANSI_TUI_RESET: &str = concat!(
    "\x1b[0m",     // reset SGR attributes
    "\x1b(B",      // restore ASCII character set
    "\x1b[?25h",   // show cursor
    "\x1b[?7h",    // enable line wrap
    "\x1b[?12l",   // disable blinking cursor mode
    "\x1b[?1l",    // leave application cursor-key mode
    "\x1b[?1000l", // disable X10 mouse
    "\x1b[?1002l", // disable button-event mouse
    "\x1b[?1003l", // disable any-event mouse
    "\x1b[?1004l", // disable focus events
    "\x1b[?1005l", // disable UTF-8 mouse mode
    "\x1b[?1006l", // disable SGR mouse mode
    "\x1b[?1015l", // disable urxvt mouse mode
    "\x1b[?2004l", // disable bracketed paste
    "\x1b[?2026l", // disable synchronized output
    "\x1b[?1048l", // restore cursor from older alt-screen flows
    "\x1b[?1047l", // leave older alternate screen
    "\x1b[?1049l", // leave alternate screen
    "\r\x1b[0K",   // clear a partially drawn prompt line
);

fn restore_ansi_state() {
    let mut out = std::io::stdout();
    if !out.is_terminal() {
        return;
    }
    let _ = execute!(
        out,
        LeaveAlternateScreen,
        DisableMouseCapture,
        DisableBracketedPaste,
        EnableLineWrap,
        Show,
        ResetColor
    );
    let _ = out.write_all(ANSI_TUI_RESET.as_bytes());
    let _ = out.flush();
}

#[cfg(windows)]
fn restore_platform_console_mode() {
    use windows_sys::Win32::System::Console::{
        GetConsoleMode, GetStdHandle, SetConsoleMode, ENABLE_ECHO_INPUT, ENABLE_EXTENDED_FLAGS,
        ENABLE_INSERT_MODE, ENABLE_LINE_INPUT, ENABLE_PROCESSED_INPUT, ENABLE_PROCESSED_OUTPUT,
        ENABLE_QUICK_EDIT_MODE, ENABLE_VIRTUAL_TERMINAL_PROCESSING, ENABLE_WRAP_AT_EOL_OUTPUT,
        STD_ERROR_HANDLE, STD_INPUT_HANDLE, STD_OUTPUT_HANDLE,
    };

    unsafe {
        let stdin = GetStdHandle(STD_INPUT_HANDLE);
        let stdout = GetStdHandle(STD_OUTPUT_HANDLE);
        let stderr = GetStdHandle(STD_ERROR_HANDLE);

        set_console_mode_if_console(
            stdin,
            ENABLE_PROCESSED_INPUT
                | ENABLE_LINE_INPUT
                | ENABLE_ECHO_INPUT
                | ENABLE_INSERT_MODE
                | ENABLE_QUICK_EDIT_MODE
                | ENABLE_EXTENDED_FLAGS,
        );
        set_console_mode_if_console(
            stdout,
            ENABLE_PROCESSED_OUTPUT
                | ENABLE_WRAP_AT_EOL_OUTPUT
                | ENABLE_VIRTUAL_TERMINAL_PROCESSING,
        );
        set_console_mode_if_console(
            stderr,
            ENABLE_PROCESSED_OUTPUT
                | ENABLE_WRAP_AT_EOL_OUTPUT
                | ENABLE_VIRTUAL_TERMINAL_PROCESSING,
        );
    }

    unsafe fn set_console_mode_if_console(handle: *mut std::ffi::c_void, mode: u32) {
        let mut current = 0;
        if GetConsoleMode(handle, &mut current) != 0 {
            let _ = SetConsoleMode(handle, mode);
        }
    }
}

#[cfg(windows)]
fn ignore_ctrl_c_for_parent_process() -> bool {
    use windows_sys::Win32::System::Console::SetConsoleCtrlHandler;

    unsafe { SetConsoleCtrlHandler(None, 1) != 0 }
}

#[cfg(windows)]
fn restore_ctrl_c_for_parent_process() {
    use windows_sys::Win32::System::Console::SetConsoleCtrlHandler;

    unsafe {
        let _ = SetConsoleCtrlHandler(None, 0);
    }
}

#[cfg(unix)]
fn restore_platform_console_mode() {
    if !std::io::stdin().is_terminal() {
        return;
    }
    let _ = std::process::Command::new("stty")
        .arg("sane")
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status();
}

#[cfg(not(any(unix, windows)))]
fn restore_platform_console_mode() {}

#[cfg(not(windows))]
fn ignore_ctrl_c_for_parent_process() -> bool {
    false
}

#[cfg(not(windows))]
fn restore_ctrl_c_for_parent_process() {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ansi_tui_reset_covers_common_leftover_private_modes() {
        for mode in [
            "\x1b[?25h",
            "\x1b[?1000l",
            "\x1b[?1002l",
            "\x1b[?1003l",
            "\x1b[?1004l",
            "\x1b[?1005l",
            "\x1b[?1006l",
            "\x1b[?1015l",
            "\x1b[?2004l",
            "\x1b[?2026l",
            "\x1b[?1047l",
            "\x1b[?1048l",
            "\x1b[?1049l",
            "\r\x1b[0K",
        ] {
            assert!(ANSI_TUI_RESET.contains(mode), "{mode:?}");
        }
    }
}

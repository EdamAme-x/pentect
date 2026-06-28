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
            restore_platform_console_mode();
            restore_ansi_state(ResetLine::Keep);
        }
    }
}

pub(crate) fn prepare_for_tui() {
    restore_platform_console_mode();
    restore_ansi_state(ResetLine::Keep);
}

pub(crate) fn restore_after_tui() {
    restore_platform_console_mode();
    restore_ansi_state(ResetLine::FreshPrompt);
}

const ANSI_TUI_RESET: &str = concat!(
    "\x1b[0m",     // reset SGR attributes
    "\x1b(B",      // restore ASCII character set
    "\x1b>",       // leave application keypad mode
    "\x1b[?25h",   // show cursor
    "\x1b[?7h",    // enable line wrap
    "\x1b[?12l",   // disable blinking cursor mode
    "\x1b[?1l",    // leave application cursor-key mode
    "\x1b[?5l",    // disable reverse video
    "\x1b[?6l",    // disable origin mode
    "\x1b[?47l",   // leave legacy alternate screen
    "\x1b[?69l",   // disable left/right margin mode
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
    "\x1b[r",      // reset top/bottom scroll margins
);

const ANSI_FRESH_PROMPT_LINE: &str = "\r\x1b[2K\r\n";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ResetLine {
    Keep,
    FreshPrompt,
}

fn restore_ansi_state(reset_line: ResetLine) {
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
    if reset_line == ResetLine::FreshPrompt {
        let _ = out.write_all(ANSI_FRESH_PROMPT_LINE.as_bytes());
    }
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
            "\x1b[?5l",
            "\x1b[?6l",
            "\x1b[?47l",
            "\x1b[?69l",
            "\x1b[?1047l",
            "\x1b[?1048l",
            "\x1b[?1049l",
            "\x1b[r",
            "\x1b>",
        ] {
            assert!(ANSI_TUI_RESET.contains(mode), "{mode:?}");
        }
    }

    #[test]
    fn after_tui_reset_moves_prompt_to_fresh_line() {
        assert_eq!(ANSI_FRESH_PROMPT_LINE, "\r\x1b[2K\r\n");
    }
}

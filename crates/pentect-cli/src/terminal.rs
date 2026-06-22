use crossterm::{
    cursor::Show,
    event::{DisableBracketedPaste, DisableMouseCapture},
    execute,
    style::ResetColor,
    terminal::{EnableLineWrap, LeaveAlternateScreen},
};
use std::io::{IsTerminal, Write};

pub(crate) fn restore_after_tui() {
    restore_platform_console_mode();
    restore_ansi_state();
}

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

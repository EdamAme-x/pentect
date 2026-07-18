use crossterm::{
    cursor::Show,
    event::{DisableBracketedPaste, DisableMouseCapture},
    execute,
    style::ResetColor,
    terminal::EnableLineWrap,
};
use std::io::{IsTerminal, Write};
use std::sync::{Arc, Mutex};

pub(crate) struct IgnoreCtrlCGuard {
    active: bool,
}

pub(crate) struct TuiSessionGuard {
    state: PlatformConsoleState,
    keyboard_modes: TerminalModeTracker,
    restored: bool,
}

impl TuiSessionGuard {
    pub(crate) fn enter() -> Self {
        let state = capture_platform_console_state();
        sanitize_platform_console_mode();
        let keyboard_modes = TerminalModeTracker::default();
        begin_main_keyboard_isolation(&keyboard_modes);
        Self {
            state,
            keyboard_modes,
            restored: false,
        }
    }

    pub(crate) fn mode_tracker(&self) -> TerminalModeTracker {
        self.keyboard_modes.clone()
    }

    pub(crate) fn restore_after_tui(&mut self) {
        self.restore(ResetLine::FreshPrompt);
    }

    pub(crate) fn restore_without_prompt(&mut self) {
        self.restore(ResetLine::Keep);
    }

    pub(crate) fn quiesce_input_reporting(&self) {
        sanitize_platform_console_mode();
        reset_ansi_input_reporting();
    }

    fn restore(&mut self, reset_line: ResetLine) {
        if self.restored {
            return;
        }
        sanitize_platform_console_mode();
        let keyboard_restore = self.keyboard_modes.take_restore();
        restore_ansi_state(reset_line, &keyboard_restore);
        restore_platform_console_state(&self.state);
        self.restored = true;
    }
}

impl Drop for TuiSessionGuard {
    fn drop(&mut self) {
        self.restore_without_prompt();
    }
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
        }
    }
}

const ANSI_INPUT_REPORTING_RESET: &str = concat!(
    "\x1b[?9l",    // disable xterm mouse reporting
    "\x1b[?1000l", // disable X10 mouse
    "\x1b[?1001l", // disable highlight mouse
    "\x1b[?1002l", // disable button-event mouse
    "\x1b[?1003l", // disable any-event mouse
    "\x1b[?1004l", // disable focus events
    "\x1b[?1005l", // disable UTF-8 mouse mode
    "\x1b[?1006l", // disable SGR mouse mode
    "\x1b[?1007l", // disable alternate scroll mode
    "\x1b[?1015l", // disable urxvt mouse mode
    "\x1b[?1016l", // disable SGR pixel mouse mode
    "\x1b[?2004l", // disable bracketed paste
    "\x1b[?2005l", // disable bracketed paste quote mode
    "\x1b[?2006l", // disable bracketed paste literal newline mode
);

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
    "\x1b[?69l",   // disable left/right margin mode
    "\x1b[?2026l", // disable synchronized output
    "\x1b[r",      // reset top/bottom scroll margins
);

const ANSI_FRESH_PROMPT_LINE: &str = "\r\x1b[2K\r\n";

#[derive(Clone, Default)]
pub(crate) struct TerminalModeTracker {
    state: Arc<Mutex<TerminalModeState>>,
}

#[derive(Default)]
struct TerminalModeState {
    parser: CsiParser,
    screen: TerminalScreen,
    alternate_kind: Option<AlternateScreen>,
    main: KeyboardModeState,
    alternate: KeyboardModeState,
}

#[derive(Default)]
struct CsiParser {
    escape: bool,
    body: Option<Vec<u8>>,
    string: Option<StringControl>,
    string_escape: bool,
    string_utf8_remaining: u8,
    utf8_remaining: u8,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum StringControl {
    Osc,
    Other,
}

#[derive(Clone, Copy, Default, PartialEq, Eq)]
enum TerminalScreen {
    #[default]
    Main,
    Alternate(AlternateScreen),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum AlternateScreen {
    Legacy,
    Extended,
    SavedCursor,
}

#[derive(Default)]
struct KeyboardModeState {
    stack_depth: usize,
}

#[derive(Default)]
struct KeyboardModeRestore {
    before_screen_leave: Vec<u8>,
    after_screen_leave: Vec<u8>,
    leave_alternate_screen: Option<AlternateScreen>,
}

impl TerminalModeTracker {
    pub(crate) fn observe(&self, bytes: &[u8]) {
        let mut state = match self.state.lock() {
            Ok(state) => state,
            Err(poisoned) => poisoned.into_inner(),
        };
        for byte in bytes {
            state.observe(*byte);
        }
    }

    fn take_restore(&self) -> KeyboardModeRestore {
        let mut state = match self.state.lock() {
            Ok(state) => state,
            Err(poisoned) => poisoned.into_inner(),
        };
        state.take_restore()
    }

    fn register_main_isolation(&self) {
        let mut state = match self.state.lock() {
            Ok(state) => state,
            Err(poisoned) => poisoned.into_inner(),
        };
        state.main.stack_depth = state.main.stack_depth.saturating_add(1);
    }
}

fn begin_main_keyboard_isolation(tracker: &TerminalModeTracker) {
    let mut out = std::io::stdout();
    if !out.is_terminal() {
        return;
    }
    enable_ansi_for_reset();
    if out.write_all(b"\x1b[>0u").and_then(|_| out.flush()).is_ok() {
        tracker.register_main_isolation();
    }
}

impl TerminalModeState {
    fn observe(&mut self, byte: u8) {
        if let Some(kind) = self.parser.string {
            if self.parser.string_utf8_remaining > 0 {
                if (0x80..=0xbf).contains(&byte) {
                    self.parser.string_utf8_remaining -= 1;
                    return;
                }
                self.parser.string_utf8_remaining = 0;
            }
            if let Some(remaining) = utf8_continuation_count(byte) {
                self.parser.string_utf8_remaining = remaining;
                return;
            }
            if byte == 0x9c || (kind == StringControl::Osc && byte == 0x07) {
                self.parser.string = None;
                self.parser.string_escape = false;
                self.parser.string_utf8_remaining = 0;
            } else if self.parser.string_escape {
                if byte == b'\\' {
                    self.parser.string = None;
                    self.parser.string_escape = false;
                } else {
                    self.parser.string_escape = byte == 0x1b;
                }
            } else if byte == 0x1b {
                self.parser.string_escape = true;
            }
            return;
        }
        if let Some(mut body) = self.parser.body.take() {
            if (b'@'..=b'~').contains(&byte) {
                self.apply_csi(&body, byte);
            } else if (0x20..=0x3f).contains(&byte) && body.len() < 64 {
                body.push(byte);
                self.parser.body = Some(body);
            } else {
                self.parser.escape = byte == 0x1b;
            }
            return;
        }
        if self.parser.escape {
            self.parser.escape = false;
            match byte {
                b'[' => self.parser.body = Some(Vec::new()),
                b']' => self.parser.string = Some(StringControl::Osc),
                b'P' | b'X' | b'^' | b'_' => self.parser.string = Some(StringControl::Other),
                0x1b => self.parser.escape = true,
                _ => {}
            }
            return;
        }
        if self.parser.utf8_remaining > 0 {
            if (0x80..=0xbf).contains(&byte) {
                self.parser.utf8_remaining -= 1;
                return;
            }
            self.parser.utf8_remaining = 0;
        }
        if let Some(remaining) = utf8_continuation_count(byte) {
            self.parser.utf8_remaining = remaining;
            return;
        }
        match byte {
            0x1b => self.parser.escape = true,
            0x90 | 0x98 | 0x9e | 0x9f => self.parser.string = Some(StringControl::Other),
            0x9b => self.parser.body = Some(Vec::new()),
            0x9d => self.parser.string = Some(StringControl::Osc),
            _ => {}
        }
    }

    fn apply_csi(&mut self, body: &[u8], final_byte: u8) {
        if matches!(final_byte, b'h' | b'l') {
            self.update_screen(body, final_byte == b'h');
            return;
        }
        if final_byte != b'u' {
            return;
        }
        let Some(prefix) = body.first().copied() else {
            return;
        };
        match prefix {
            b'>' => {
                let mode = self.current_mode_mut();
                mode.stack_depth = mode.stack_depth.saturating_add(1);
            }
            b'<' => {
                let count = parse_decimal(&body[1..]).unwrap_or(1).max(1);
                let mode = self.current_mode_mut();
                mode.stack_depth = mode.stack_depth.saturating_sub(count);
            }
            _ => {}
        }
    }

    fn update_screen(&mut self, body: &[u8], enabled: bool) {
        let Some(parameters) = body.strip_prefix(b"?") else {
            return;
        };
        let kind = parameters
            .split(|byte| *byte == b';')
            .filter_map(alternate_screen_kind)
            .next_back();
        let Some(kind) = kind else { return };
        self.alternate_kind = Some(kind);
        self.screen = if enabled {
            TerminalScreen::Alternate(kind)
        } else {
            TerminalScreen::Main
        };
    }

    fn current_mode_mut(&mut self) -> &mut KeyboardModeState {
        match self.screen {
            TerminalScreen::Main => &mut self.main,
            TerminalScreen::Alternate(_) => &mut self.alternate,
        }
    }

    fn take_restore(&mut self) -> KeyboardModeRestore {
        let mut restore = KeyboardModeRestore::default();
        match self.screen {
            TerminalScreen::Main => {
                restore.before_screen_leave = take_keyboard_restore(&mut self.main);
                let alternate = take_keyboard_restore(&mut self.alternate);
                if !alternate.is_empty() {
                    let kind = self.alternate_kind.unwrap_or(AlternateScreen::SavedCursor);
                    restore
                        .before_screen_leave
                        .extend_from_slice(alternate_screen_control(kind, true));
                    restore.before_screen_leave.extend(alternate);
                    restore
                        .before_screen_leave
                        .extend_from_slice(alternate_screen_control(kind, false));
                }
            }
            TerminalScreen::Alternate(kind) => {
                restore.before_screen_leave = take_keyboard_restore(&mut self.alternate);
                restore.after_screen_leave = take_keyboard_restore(&mut self.main);
                restore.leave_alternate_screen = Some(kind);
            }
        }
        restore
    }
}

fn utf8_continuation_count(byte: u8) -> Option<u8> {
    match byte {
        0xc2..=0xdf => Some(1),
        0xe0..=0xef => Some(2),
        0xf0..=0xf4 => Some(3),
        _ => None,
    }
}

fn alternate_screen_kind(parameter: &[u8]) -> Option<AlternateScreen> {
    match parameter {
        b"47" => Some(AlternateScreen::Legacy),
        b"1047" => Some(AlternateScreen::Extended),
        b"1049" => Some(AlternateScreen::SavedCursor),
        _ => None,
    }
}

fn alternate_screen_control(kind: AlternateScreen, enabled: bool) -> &'static [u8] {
    match (kind, enabled) {
        (AlternateScreen::Legacy, true) => b"\x1b[?47h",
        (AlternateScreen::Legacy, false) => b"\x1b[?47l",
        (AlternateScreen::Extended, true) => b"\x1b[?1047h",
        (AlternateScreen::Extended, false) => b"\x1b[?1047l",
        (AlternateScreen::SavedCursor, true) => b"\x1b[?1049h",
        (AlternateScreen::SavedCursor, false) => b"\x1b[?1049l",
    }
}

fn parse_decimal(bytes: &[u8]) -> Option<usize> {
    if bytes.is_empty() {
        return None;
    }
    bytes.iter().try_fold(0usize, |value, byte| {
        byte.is_ascii_digit().then(|| {
            value
                .saturating_mul(10)
                .saturating_add(usize::from(byte - b'0'))
        })
    })
}

fn take_keyboard_restore(mode: &mut KeyboardModeState) -> Vec<u8> {
    let mut restore = Vec::new();
    if mode.stack_depth == 1 {
        restore.extend_from_slice(b"\x1b[<u");
    } else if mode.stack_depth > 1 {
        restore.extend_from_slice(format!("\x1b[<{}u", mode.stack_depth).as_bytes());
    }
    *mode = KeyboardModeState::default();
    restore
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ResetLine {
    Keep,
    FreshPrompt,
}

fn restore_ansi_state(reset_line: ResetLine, keyboard_restore: &KeyboardModeRestore) {
    let mut out = std::io::stdout();
    if !out.is_terminal() {
        return;
    }
    enable_ansi_for_reset();
    let _ = out.write_all(&keyboard_restore.before_screen_leave);
    if let Some(kind) = keyboard_restore.leave_alternate_screen {
        let _ = out.write_all(alternate_screen_control(kind, false));
    }
    let _ = execute!(
        out,
        DisableMouseCapture,
        DisableBracketedPaste,
        EnableLineWrap,
        Show,
        ResetColor
    );
    let _ = out.write_all(&keyboard_restore.after_screen_leave);
    let _ = out.write_all(ANSI_INPUT_REPORTING_RESET.as_bytes());
    let _ = out.write_all(ANSI_TUI_RESET.as_bytes());
    if reset_line == ResetLine::FreshPrompt {
        let _ = out.write_all(ANSI_FRESH_PROMPT_LINE.as_bytes());
    }
    let _ = out.flush();
}

fn reset_ansi_input_reporting() {
    let mut out = std::io::stdout();
    if !out.is_terminal() {
        return;
    }
    enable_ansi_for_reset();
    let _ = out.write_all(ANSI_INPUT_REPORTING_RESET.as_bytes());
    let _ = out.flush();
}

#[cfg(windows)]
#[derive(Clone, Copy, Debug, Default)]
struct PlatformConsoleState {
    stdin: Option<ConsoleMode>,
    stdout: Option<ConsoleMode>,
    stderr: Option<ConsoleMode>,
}

#[cfg(windows)]
#[derive(Clone, Copy, Debug)]
struct ConsoleMode {
    handle: *mut std::ffi::c_void,
    mode: u32,
}

#[cfg(windows)]
fn capture_platform_console_state() -> PlatformConsoleState {
    use windows_sys::Win32::System::Console::{
        GetConsoleMode, GetStdHandle, STD_ERROR_HANDLE, STD_INPUT_HANDLE, STD_OUTPUT_HANDLE,
    };

    unsafe fn console_mode(handle: *mut std::ffi::c_void) -> Option<ConsoleMode> {
        let mut mode = 0;
        unsafe { (GetConsoleMode(handle, &mut mode) != 0).then_some(ConsoleMode { handle, mode }) }
    }

    unsafe {
        PlatformConsoleState {
            stdin: console_mode(GetStdHandle(STD_INPUT_HANDLE)),
            stdout: console_mode(GetStdHandle(STD_OUTPUT_HANDLE)),
            stderr: console_mode(GetStdHandle(STD_ERROR_HANDLE)),
        }
    }
}

#[cfg(windows)]
fn sanitize_platform_console_mode() {
    use windows_sys::Win32::System::Console::{
        GetStdHandle, ENABLE_ECHO_INPUT, ENABLE_EXTENDED_FLAGS, ENABLE_INSERT_MODE,
        ENABLE_LINE_INPUT, ENABLE_PROCESSED_INPUT, ENABLE_PROCESSED_OUTPUT, ENABLE_QUICK_EDIT_MODE,
        ENABLE_VIRTUAL_TERMINAL_PROCESSING, ENABLE_WRAP_AT_EOL_OUTPUT, STD_ERROR_HANDLE,
        STD_INPUT_HANDLE, STD_OUTPUT_HANDLE,
    };

    unsafe {
        set_console_mode_if_console(
            GetStdHandle(STD_INPUT_HANDLE),
            ENABLE_PROCESSED_INPUT
                | ENABLE_LINE_INPUT
                | ENABLE_ECHO_INPUT
                | ENABLE_INSERT_MODE
                | ENABLE_QUICK_EDIT_MODE
                | ENABLE_EXTENDED_FLAGS,
        );
        set_console_mode_if_console(
            GetStdHandle(STD_OUTPUT_HANDLE),
            ENABLE_PROCESSED_OUTPUT
                | ENABLE_WRAP_AT_EOL_OUTPUT
                | ENABLE_VIRTUAL_TERMINAL_PROCESSING,
        );
        set_console_mode_if_console(
            GetStdHandle(STD_ERROR_HANDLE),
            ENABLE_PROCESSED_OUTPUT
                | ENABLE_WRAP_AT_EOL_OUTPUT
                | ENABLE_VIRTUAL_TERMINAL_PROCESSING,
        );
    }

    unsafe fn set_console_mode_if_console(handle: *mut std::ffi::c_void, mode: u32) {
        use windows_sys::Win32::System::Console::{GetConsoleMode, SetConsoleMode};

        let mut current = 0;
        if GetConsoleMode(handle, &mut current) != 0 {
            let _ = SetConsoleMode(handle, mode);
        }
    }
}

#[cfg(windows)]
fn enable_ansi_for_reset() {
    use windows_sys::Win32::System::Console::{
        GetConsoleMode, GetStdHandle, SetConsoleMode, ENABLE_PROCESSED_OUTPUT,
        ENABLE_VIRTUAL_TERMINAL_PROCESSING, ENABLE_WRAP_AT_EOL_OUTPUT, STD_ERROR_HANDLE,
        STD_OUTPUT_HANDLE,
    };

    unsafe {
        for handle_id in [STD_OUTPUT_HANDLE, STD_ERROR_HANDLE] {
            let handle = GetStdHandle(handle_id);
            let mut current = 0;
            if GetConsoleMode(handle, &mut current) != 0 {
                let _ = SetConsoleMode(
                    handle,
                    current
                        | ENABLE_PROCESSED_OUTPUT
                        | ENABLE_WRAP_AT_EOL_OUTPUT
                        | ENABLE_VIRTUAL_TERMINAL_PROCESSING,
                );
            }
        }
    }
}

#[cfg(windows)]
fn restore_platform_console_state(state: &PlatformConsoleState) {
    use windows_sys::Win32::System::Console::SetConsoleMode;

    unsafe fn set_console_mode_if_console(handle: *mut std::ffi::c_void, mode: u32) {
        if !handle.is_null() {
            unsafe {
                let _ = SetConsoleMode(handle, mode);
            }
        }
    }

    if let Some(mode) = state.stdin {
        unsafe { set_console_mode_if_console(mode.handle, mode.mode) };
    }
    if let Some(mode) = state.stdout {
        unsafe { set_console_mode_if_console(mode.handle, mode.mode) };
    }
    if let Some(mode) = state.stderr {
        unsafe { set_console_mode_if_console(mode.handle, mode.mode) };
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
#[derive(Clone, Debug, Default)]
struct PlatformConsoleState {
    stty: Option<String>,
}

#[cfg(unix)]
fn capture_platform_console_state() -> PlatformConsoleState {
    if !std::io::stdin().is_terminal() {
        return PlatformConsoleState::default();
    }
    let stty = std::process::Command::new("stty")
        .arg("-g")
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::null())
        .output()
        .ok()
        .filter(|output| output.status.success())
        .map(|output| String::from_utf8_lossy(&output.stdout).trim().to_string())
        .filter(|value| !value.is_empty());
    PlatformConsoleState { stty }
}

#[cfg(unix)]
fn sanitize_platform_console_mode() {
    if !std::io::stdin().is_terminal() {
        return;
    }
    let _ = std::process::Command::new("stty")
        .arg("sane")
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status();
}

#[cfg(unix)]
fn enable_ansi_for_reset() {}

#[cfg(unix)]
fn restore_platform_console_state(state: &PlatformConsoleState) {
    let Some(stty) = &state.stty else {
        return;
    };
    if !std::io::stdin().is_terminal() {
        return;
    }
    let _ = std::process::Command::new("stty")
        .arg(stty)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status();
}

#[cfg(not(any(unix, windows)))]
#[derive(Clone, Debug, Default)]
struct PlatformConsoleState;

#[cfg(not(any(unix, windows)))]
fn capture_platform_console_state() -> PlatformConsoleState {
    PlatformConsoleState
}

#[cfg(not(any(unix, windows)))]
fn sanitize_platform_console_mode() {}

#[cfg(not(any(unix, windows)))]
fn enable_ansi_for_reset() {}

#[cfg(not(any(unix, windows)))]
fn restore_platform_console_state(_state: &PlatformConsoleState) {}

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
            "\x1b[?1000l",
            "\x1b[?1001l",
            "\x1b[?1002l",
            "\x1b[?1003l",
            "\x1b[?1004l",
            "\x1b[?1005l",
            "\x1b[?1006l",
            "\x1b[?1007l",
            "\x1b[?1015l",
            "\x1b[?1016l",
            "\x1b[?2004l",
            "\x1b[?2005l",
            "\x1b[?2006l",
            "\x1b[?9l",
        ] {
            assert!(ANSI_INPUT_REPORTING_RESET.contains(mode), "{mode:?}");
        }
        for mode in [
            "\x1b[?25h",
            "\x1b[?2026l",
            "\x1b[?5l",
            "\x1b[?6l",
            "\x1b[?69l",
            "\x1b[r",
            "\x1b>",
        ] {
            assert!(ANSI_TUI_RESET.contains(mode), "{mode:?}");
        }
    }

    #[test]
    fn ansi_tui_reset_does_not_leave_an_unowned_alternate_screen() {
        for mode in ["\x1b[?47l", "\x1b[?1047l", "\x1b[?1048l", "\x1b[?1049l"] {
            assert!(!ANSI_TUI_RESET.contains(mode), "{mode:?}");
        }
    }

    #[test]
    fn after_tui_reset_moves_prompt_to_fresh_line() {
        assert_eq!(ANSI_FRESH_PROMPT_LINE, "\r\x1b[2K\r\n");
    }

    #[test]
    fn keyboard_mode_tracker_restores_each_screen_in_order() {
        let tracker = TerminalModeTracker::default();
        tracker.observe(b"\x1b[>1u\x1b[?1049h\x1b[>3");
        tracker.observe(b"u\x1b[>7u");

        let restore = tracker.take_restore();
        assert_eq!(restore.before_screen_leave, b"\x1b[<2u");
        assert_eq!(restore.after_screen_leave, b"\x1b[<u");
        assert_eq!(
            restore.leave_alternate_screen,
            Some(AlternateScreen::SavedCursor)
        );
    }

    #[test]
    fn keyboard_mode_tracker_ignores_balanced_push_and_pop() {
        let tracker = TerminalModeTracker::default();
        tracker.observe(b"\x1b[>1u\x1b[<u");

        let restore = tracker.take_restore();
        assert!(restore.before_screen_leave.is_empty());
        assert!(restore.after_screen_leave.is_empty());
        assert!(restore.leave_alternate_screen.is_none());
    }

    #[test]
    fn keyboard_mode_tracker_restores_direct_changes_through_owned_frame() {
        let tracker = TerminalModeTracker::default();
        tracker.register_main_isolation();
        tracker.observe(b"\x9b=15;1u");

        let restore = tracker.take_restore();
        assert_eq!(restore.before_screen_leave, b"\x1b[<u");
        assert!(restore.leave_alternate_screen.is_none());
    }

    #[test]
    fn keyboard_mode_tracker_cleans_inactive_alternate_screen() {
        let tracker = TerminalModeTracker::default();
        tracker.observe(b"\x1b[?1049h\x1b[>1u\x1b[?1049l");

        let restore = tracker.take_restore();
        assert_eq!(
            restore.before_screen_leave,
            b"\x1b[?1049h\x1b[<u\x1b[?1049l"
        );
        assert!(restore.after_screen_leave.is_empty());
        assert!(restore.leave_alternate_screen.is_none());
    }

    #[test]
    fn keyboard_mode_tracker_ignores_controls_inside_terminal_strings() {
        let tracker = TerminalModeTracker::default();
        tracker.register_main_isolation();
        tracker.observe("\u{1b}]0;title Ü\u{1b}[>7u\u{7}".as_bytes());
        tracker.observe("\u{1b}Ppayload Ü\u{1b}[>3u\u{1b}\\".as_bytes());

        let restore = tracker.take_restore();
        assert_eq!(restore.before_screen_leave, b"\x1b[<u");
    }

    #[test]
    fn keyboard_mode_tracker_does_not_parse_utf8_continuations_as_c1() {
        let tracker = TerminalModeTracker::default();
        tracker.register_main_isolation();
        let text = "日本語の漛端末";
        assert!(text.as_bytes().contains(&0x9b));
        tracker.observe(text.as_bytes());

        let restore = tracker.take_restore();
        assert_eq!(restore.before_screen_leave, b"\x1b[<u");
        assert!(restore.after_screen_leave.is_empty());
        assert!(restore.leave_alternate_screen.is_none());
    }

    #[test]
    fn keyboard_mode_tracker_restores_the_matching_alternate_screen_kind() {
        for (enter, kind) in [
            (b"\x1b[?47h".as_slice(), AlternateScreen::Legacy),
            (b"\x1b[?1047h".as_slice(), AlternateScreen::Extended),
            (b"\x1b[?1049h".as_slice(), AlternateScreen::SavedCursor),
        ] {
            let tracker = TerminalModeTracker::default();
            tracker.observe(enter);
            let restore = tracker.take_restore();
            assert_eq!(restore.leave_alternate_screen, Some(kind));
            assert_eq!(alternate_screen_control(kind, false).last(), Some(&b'l'));
        }
    }
}

use std::io::{self, BufRead, Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::{
    atomic::{AtomicBool, Ordering},
    mpsc, Arc,
};
use std::thread::{self, JoinHandle};
use std::time::Duration;

use zeroize::Zeroize;

const MAX_HEADLESS_INPUT_BYTES: usize = 32 * 1024 * 1024;
const MAX_HEADLESS_IMAGE_BYTES: u64 = 64 * 1024 * 1024;
const MAX_HEADLESS_OUTPUT_BYTES: usize = 32 * 1024 * 1024;
const MAX_HEADLESS_OUTPUT_RECORD_BYTES: usize = 8 * 1024 * 1024;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum AgentKind {
    Codex,
    Claude,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) enum InputMode {
    #[default]
    Buffered,
    JsonLines,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) enum OutputMode {
    #[default]
    Text,
    JsonRecords,
}

#[derive(Default)]
pub(crate) struct ProtectedImageFiles {
    root: Option<PathBuf>,
    next_file: usize,
}

impl ProtectedImageFiles {
    fn protect_path(&mut self, value: &str) -> Result<String, String> {
        let path = Path::new(value);
        let file = std::fs::File::open(path)
            .map_err(|error| format!("could not read image '{}': {error}", path.display()))?;
        let mut bytes = Vec::new();
        if let Err(error) = file
            .take(MAX_HEADLESS_IMAGE_BYTES + 1)
            .read_to_end(&mut bytes)
        {
            bytes.zeroize();
            return Err(format!(
                "could not read image '{}': {error}",
                path.display()
            ));
        }
        if bytes.len() as u64 > MAX_HEADLESS_IMAGE_BYTES {
            bytes.zeroize();
            return Err(format!(
                "image '{}' exceeds {MAX_HEADLESS_IMAGE_BYTES} bytes",
                path.display()
            ));
        }
        let redaction = pentect_agent::redact_image_bytes_into_active_memory_store(&bytes);
        bytes.zeroize();
        let Some(mut redacted) = redaction? else {
            return Ok(value.to_string());
        };
        let output = self.output_path(path, &redacted)?;
        let write_result = write_private_file(&output, &redacted);
        redacted.zeroize();
        write_result?;
        Ok(output.to_string_lossy().into_owned())
    }

    fn output_path(&mut self, source: &Path, bytes: &[u8]) -> Result<PathBuf, String> {
        let root = match &self.root {
            Some(root) => root.clone(),
            None => {
                let mut nonce = [0u8; 16];
                getrandom::getrandom(&mut nonce)
                    .map_err(|error| format!("could not create protected image path: {error}"))?;
                let root = std::env::temp_dir().join(format!(
                    "pentect-images-{}-{}",
                    std::process::id(),
                    data_encoding::HEXLOWER.encode(&nonce)
                ));
                nonce.zeroize();
                std::fs::create_dir(&root).map_err(|error| {
                    format!("could not create protected image directory: {error}")
                })?;
                set_private_directory_permissions(&root)?;
                self.root = Some(root.clone());
                root
            }
        };
        self.next_file += 1;
        let extension = image_extension(bytes).unwrap_or_else(|| {
            source
                .extension()
                .and_then(|extension| extension.to_str())
                .filter(|extension| {
                    !extension.is_empty()
                        && extension.len() <= 10
                        && extension
                            .chars()
                            .all(|character| character.is_ascii_alphanumeric())
                })
                .unwrap_or("png")
        });
        Ok(root.join(format!("image-{}.{extension}", self.next_file)))
    }
}

fn image_extension(bytes: &[u8]) -> Option<&'static str> {
    if bytes.starts_with(b"\x89PNG\r\n\x1a\n") {
        Some("png")
    } else if bytes.starts_with(&[0xff, 0xd8, 0xff]) {
        Some("jpg")
    } else if bytes.starts_with(b"GIF87a") || bytes.starts_with(b"GIF89a") {
        Some("gif")
    } else if bytes.starts_with(b"BM") {
        Some("bmp")
    } else if bytes.starts_with(b"RIFF") && bytes.get(8..12) == Some(b"WEBP") {
        Some("webp")
    } else {
        None
    }
}

impl Drop for ProtectedImageFiles {
    fn drop(&mut self) {
        if let Some(root) = self.root.take() {
            remove_private_directory(&root);
        }
    }
}

fn remove_private_directory(root: &Path) {
    for delay in [0, 10, 25, 50] {
        if delay > 0 {
            thread::sleep(Duration::from_millis(delay));
        }
        match std::fs::remove_dir_all(root) {
            Ok(()) => return,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return,
            Err(_) => {}
        }
    }
}

pub(crate) fn protect_codex_image_args(
    args: &[String],
) -> Result<(Vec<String>, ProtectedImageFiles), String> {
    let mut protected = args.to_vec();
    let mut files = ProtectedImageFiles::default();
    rewrite_codex_image_values(&mut protected, &mut |value| {
        let mut rewritten = Vec::new();
        for path in value.split(',') {
            rewritten.push(files.protect_path(path)?);
        }
        Ok(rewritten.join(","))
    })?;
    Ok((protected, files))
}

fn rewrite_codex_image_values<F>(args: &mut [String], rewrite: &mut F) -> Result<(), String>
where
    F: FnMut(&str) -> Result<String, String>,
{
    let mut index = 0usize;
    while index < args.len() {
        if args[index] == "--" {
            break;
        }
        if let Some(value) = args[index]
            .strip_prefix("--image=")
            .or_else(|| args[index].strip_prefix("-i="))
        {
            let prefix = args[index]
                .split_once('=')
                .map(|(prefix, _)| prefix)
                .unwrap_or("-i");
            args[index] = format!("{prefix}={}", rewrite(value)?);
            index += 1;
            continue;
        }
        if matches!(args[index].as_str(), "-i" | "--image") {
            index += 1;
            while index < args.len()
                && args[index] != "--"
                && !args[index].starts_with('-')
                && !is_codex_command(&args[index])
            {
                args[index] = rewrite(&args[index])?;
                index += 1;
            }
            continue;
        }
        index += 1;
    }
    Ok(())
}

fn write_private_file(path: &Path, bytes: &[u8]) -> Result<(), String> {
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options
        .open(path)
        .map_err(|error| format!("could not create protected image: {error}"))?;
    file.write_all(bytes)
        .map_err(|error| format!("could not write protected image: {error}"))
}

#[cfg(unix)]
fn set_private_directory_permissions(path: &Path) -> Result<(), String> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))
        .map_err(|error| format!("could not protect image directory: {error}"))
}

#[cfg(not(unix))]
fn set_private_directory_permissions(_path: &Path) -> Result<(), String> {
    Ok(())
}

#[cfg(windows)]
struct HeadlessProcessSupervisor {
    job: windows_sys::Win32::Foundation::HANDLE,
}

#[cfg(windows)]
impl HeadlessProcessSupervisor {
    fn new(child: &Child) -> Self {
        use std::os::windows::io::AsRawHandle;
        use windows_sys::Win32::System::JobObjects::{
            AssignProcessToJobObject, CreateJobObjectW, JobObjectExtendedLimitInformation,
            SetInformationJobObject, JOBOBJECT_EXTENDED_LIMIT_INFORMATION,
            JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
        };

        let job = unsafe { CreateJobObjectW(std::ptr::null(), std::ptr::null()) };
        if job.is_null() {
            return Self { job };
        }
        let mut limits = JOBOBJECT_EXTENDED_LIMIT_INFORMATION::default();
        limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
        let configured = unsafe {
            SetInformationJobObject(
                job,
                JobObjectExtendedLimitInformation,
                std::ptr::from_ref(&limits).cast(),
                std::mem::size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32,
            )
        } != 0;
        let assigned = configured
            && unsafe { AssignProcessToJobObject(job, child.as_raw_handle().cast()) } != 0;
        if assigned {
            Self { job }
        } else {
            unsafe {
                let _ = windows_sys::Win32::Foundation::CloseHandle(job);
            }
            Self {
                job: std::ptr::null_mut(),
            }
        }
    }

    fn terminate(&mut self) -> bool {
        use windows_sys::Win32::{Foundation::CloseHandle, System::JobObjects::TerminateJobObject};

        if self.job.is_null() {
            return false;
        }
        let terminated = unsafe { TerminateJobObject(self.job, 1) != 0 };
        unsafe {
            let _ = CloseHandle(self.job);
        }
        self.job = std::ptr::null_mut();
        terminated
    }
}

#[cfg(windows)]
impl Drop for HeadlessProcessSupervisor {
    fn drop(&mut self) {
        let _ = self.terminate();
    }
}

#[cfg(not(windows))]
struct HeadlessProcessSupervisor;

#[cfg(not(windows))]
impl HeadlessProcessSupervisor {
    fn new(_child: &Child) -> Self {
        Self
    }

    fn terminate(&mut self) -> bool {
        false
    }
}

pub(crate) fn protect_prompt_args(
    agent: AgentKind,
    args: &[String],
) -> Result<Vec<String>, String> {
    rewrite_prompt_args_with(agent, args, &mut |text| {
        pentect_agent::mask_prompt_text_into_active_memory_store(text)
    })
}

pub(crate) fn claude_input_mode(args: &[String]) -> InputMode {
    for (index, arg) in args.iter().enumerate() {
        if arg == "--" {
            break;
        }
        if arg == "--input-format"
            && args
                .get(index + 1)
                .is_some_and(|value| value == "stream-json")
        {
            return InputMode::JsonLines;
        }
        if arg == "--input-format=stream-json" {
            return InputMode::JsonLines;
        }
    }
    InputMode::Buffered
}

pub(crate) fn codex_output_mode(args: &[String]) -> OutputMode {
    if args
        .iter()
        .take_while(|arg| arg.as_str() != "--")
        .any(|arg| arg == "--json")
    {
        OutputMode::JsonRecords
    } else {
        OutputMode::Text
    }
}

pub(crate) fn claude_output_mode(args: &[String]) -> OutputMode {
    for (index, arg) in args.iter().enumerate() {
        if arg == "--" {
            break;
        }
        let value = if arg == "--output-format" {
            args.get(index + 1).map(String::as_str)
        } else {
            arg.strip_prefix("--output-format=")
        };
        if value.is_some_and(|value| matches!(value, "json" | "stream-json")) {
            return OutputMode::JsonRecords;
        }
    }
    OutputMode::Text
}

pub(crate) fn claude_uses_partial_output(args: &[String]) -> bool {
    args.iter()
        .take_while(|arg| arg.as_str() != "--")
        .any(|arg| arg == "--include-partial-messages")
}

pub(crate) fn protect_stdin(
    agent: AgentKind,
    args: &[String],
    stdin_is_terminal: bool,
    stdout_is_terminal: bool,
) -> bool {
    match agent {
        AgentKind::Codex => {
            codex_reads_prompt_from_stdin(args)
                || (!stdin_is_terminal && codex_accepts_prompt_input(args))
        }
        AgentKind::Claude => {
            claude_reads_prompt_from_stdin(args, stdin_is_terminal, stdout_is_terminal)
        }
    }
}

pub(crate) fn run_noninteractive_command(
    cmd: &mut Command,
    display: &Path,
    input_mode: InputMode,
    output_mode: OutputMode,
    protect_stdin: bool,
) -> Result<ExitStatus, String> {
    let protected_stdin = protect_stdin;
    let streaming_masker = if protected_stdin && input_mode == InputMode::JsonLines {
        Some(pentect_agent::ActiveToolOutputMasker::new()?)
    } else {
        None
    };
    if protected_stdin {
        cmd.stdin(Stdio::piped());
    } else {
        cmd.stdin(Stdio::inherit());
    }
    cmd.stdout(Stdio::piped()).stderr(Stdio::piped());
    let cancelled = Arc::new(AtomicBool::new(false));
    let interrupt_cancelled = Arc::clone(&cancelled);
    ctrlc::set_handler(move || interrupt_cancelled.store(true, Ordering::Release))
        .map_err(|error| format!("could not install interrupt handler: {error}"))?;
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        cmd.process_group(0);
    }
    let mut child = cmd
        .spawn()
        .map_err(|error| format!("could not start '{}': {error}", display.display()))?;
    let mut process_supervisor = HeadlessProcessSupervisor::new(&child);
    let supervised_root = crate::capture_supervised_root_pid(Some(child.id()));
    let mut streaming_stdin = None;
    let mut stdin_thread = None;
    if protected_stdin {
        let stdin = child
            .stdin
            .take()
            .ok_or_else(|| format!("could not open '{}' stdin", display.display()))?;
        if input_mode == InputMode::Buffered {
            let cancelled = Arc::clone(&cancelled);
            stdin_thread = Some(thread::spawn(move || {
                // Start the agent before waiting for inherited stdin. A positional
                // prompt can finish while an unrelated automation pipe stays open.
                let result = read_masked_buffered_stdin()
                    .and_then(|buffered| write_buffered_stdin(stdin, buffered));
                if result.is_err() {
                    cancelled.store(true, Ordering::Release);
                }
                result
            }));
        } else {
            let (sender, receiver) = mpsc::sync_channel(1);
            let input_cancelled = Arc::clone(&cancelled);
            stdin_thread = Some(thread::spawn(move || {
                read_json_lines(sender, input_cancelled)
            }));
            streaming_stdin = Some((
                stdin,
                streaming_masker.ok_or_else(|| "prompt masker is unavailable".to_string())?,
                receiver,
            ));
        }
    }
    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| format!("could not open '{}' stdout", display.display()))?;
    let stderr = child
        .stderr
        .take()
        .ok_or_else(|| format!("could not open '{}' stderr", display.display()))?;
    let stdout_cancelled = Arc::clone(&cancelled);
    let stdout_thread = thread::spawn(move || {
        let output = io::stdout();
        let framing = if output_mode == OutputMode::Text {
            OutputFraming::Whole
        } else {
            OutputFraming::Records
        };
        proxy_output(
            stdout,
            output.lock(),
            stdout_cancelled,
            true,
            output_mode,
            framing,
        )
    });
    let stderr_cancelled = Arc::clone(&cancelled);
    let stderr_thread = thread::spawn(move || {
        let output = io::stderr();
        proxy_output(
            stderr,
            output.lock(),
            stderr_cancelled,
            true,
            OutputMode::Text,
            OutputFraming::Whole,
        )
    });

    let mut early_status = None;
    let streaming_input_error = if let Some((mut stdin, mut masker, receiver)) = streaming_stdin {
        loop {
            if cancelled.load(Ordering::Acquire) {
                break None;
            }
            match child.try_wait() {
                Ok(Some(status)) => {
                    early_status = Some(status);
                    break None;
                }
                Ok(None) => {}
                Err(error) => {
                    cancelled.store(true, Ordering::Release);
                    break Some(format!(
                        "could not wait for '{}': {error}",
                        display.display()
                    ));
                }
            }
            match receiver.recv_timeout(Duration::from_millis(10)) {
                Ok(Ok(mut line)) => {
                    let result = mask_and_write_json_prompt(&line, &mut stdin, &mut masker)
                        .and_then(|()| {
                            stdin
                                .flush()
                                .map_err(|error| format!("could not flush agent stdin: {error}"))
                        });
                    line.zeroize();
                    if let Err(error) = result {
                        cancelled.store(true, Ordering::Release);
                        break Some(error);
                    }
                }
                Ok(Err(error)) => {
                    cancelled.store(true, Ordering::Release);
                    break Some(error);
                }
                Err(mpsc::RecvTimeoutError::Timeout) => {}
                Err(mpsc::RecvTimeoutError::Disconnected) => break None,
            }
        }
    } else {
        None
    };

    let status = if let Some(status) = early_status {
        terminate_headless_processes(&mut process_supervisor, supervised_root);
        status
    } else {
        loop {
            if cancelled.load(Ordering::Acquire) {
                terminate_headless_processes(&mut process_supervisor, supervised_root);
                let _ = child.kill();
                let status = child
                    .wait()
                    .map_err(|error| format!("could not stop '{}': {error}", display.display()))?;
                break status;
            }
            if let Some(status) = child
                .try_wait()
                .map_err(|error| format!("could not wait for '{}': {error}", display.display()))?
            {
                terminate_headless_processes(&mut process_supervisor, supervised_root);
                break status;
            }
            thread::sleep(Duration::from_millis(10));
        }
    };
    join_output(stdout_thread, "stdout")?;
    join_output(stderr_thread, "stderr")?;
    if let Some(stdin_thread) = stdin_thread {
        // An agent with a complete positional prompt need not consume inherited
        // stdin. Do not keep Pentect alive solely for an unrelated open pipe.
        if stdin_thread.is_finished() {
            join_input(stdin_thread)?;
        }
    }
    if let Some(error) = streaming_input_error {
        return Err(error);
    }
    Ok(status)
}

fn terminate_headless_processes(
    supervisor: &mut HeadlessProcessSupervisor,
    root: Option<crate::SupervisedRoot>,
) {
    if !supervisor.terminate() {
        terminate_cancelled_processes(root);
    }
}

#[cfg(windows)]
fn terminate_cancelled_processes(root: Option<crate::SupervisedRoot>) {
    if let Some(root) = root {
        crate::terminate_supervised_processes(root);
    }
}

#[cfg(unix)]
fn terminate_cancelled_processes(root: Option<crate::SupervisedRoot>) {
    if let Some(root) = root {
        unsafe {
            let _ = libc::kill(-(root.pid.as_u32() as i32), libc::SIGKILL);
        }
    }
}

#[cfg(not(any(unix, windows)))]
fn terminate_cancelled_processes(_root: Option<crate::SupervisedRoot>) {}

fn proxy_output(
    mut reader: impl Read,
    mut writer: impl Write,
    cancelled: Arc<AtomicBool>,
    detect_new_secrets: bool,
    output_mode: OutputMode,
    framing: OutputFraming,
) -> Result<(), String> {
    let mut masker = match HeadlessOutputMasker::new(detect_new_secrets, output_mode, framing) {
        Ok(masker) => masker,
        Err(error) => {
            cancelled.store(true, Ordering::Release);
            drain_sensitive(&mut reader);
            return Err(error);
        }
    };
    let mut buffer = [0u8; 8192];
    let mut output_open = true;
    let mut first_error = None;
    loop {
        let read = match reader.read(&mut buffer) {
            Ok(0) => break,
            Ok(read) => read,
            Err(error) => {
                buffer.zeroize();
                cancelled.store(true, Ordering::Release);
                return Err(format!("could not read agent output: {error}"));
            }
        };
        if first_error.is_some() {
            buffer[..read].zeroize();
            continue;
        }
        let mut masked = match masker.push(&buffer[..read]) {
            Ok(masked) => masked,
            Err(error) => {
                buffer[..read].zeroize();
                cancelled.store(true, Ordering::Release);
                first_error = Some(error);
                continue;
            }
        };
        buffer[..read].zeroize();
        if output_open {
            match writer.write_all(&masked).and_then(|()| writer.flush()) {
                Ok(()) => {}
                Err(error) if error.kind() == io::ErrorKind::BrokenPipe => {
                    output_open = false;
                    cancelled.store(true, Ordering::Release);
                }
                Err(error) => {
                    output_open = false;
                    cancelled.store(true, Ordering::Release);
                    first_error = Some(format!("could not write agent output: {error}"));
                }
            }
        }
        masked.zeroize();
    }
    buffer.zeroize();
    if let Some(error) = first_error {
        return Err(error);
    }
    let mut tail = masker.finish()?;
    let tail_result = if output_open {
        match writer.write_all(&tail).and_then(|()| writer.flush()) {
            Ok(()) => Ok(()),
            Err(error) if error.kind() == io::ErrorKind::BrokenPipe => Ok(()),
            Err(error) => Err(format!("could not write agent output: {error}")),
        }
    } else {
        Ok(())
    };
    tail.zeroize();
    tail_result
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum OutputFraming {
    Whole,
    Records,
}

struct HeadlessOutputMasker {
    detector: Option<pentect_agent::ActiveToolOutputMasker>,
    remasker: pentect_agent::ActiveTerminalOutputRemasker,
    pending: Vec<u8>,
    output_mode: OutputMode,
    framing: OutputFraming,
}

impl HeadlessOutputMasker {
    fn new(
        detect_new_secrets: bool,
        output_mode: OutputMode,
        framing: OutputFraming,
    ) -> Result<Self, String> {
        Ok(Self {
            detector: detect_new_secrets
                .then(pentect_agent::ActiveToolOutputMasker::new)
                .transpose()?,
            remasker: pentect_agent::ActiveTerminalOutputRemasker::new()?,
            pending: Vec::new(),
            output_mode,
            framing,
        })
    }

    fn push(&mut self, bytes: &[u8]) -> Result<Vec<u8>, String> {
        self.pending.extend_from_slice(bytes);
        if self.framing == OutputFraming::Whole {
            if self.pending.len() > MAX_HEADLESS_OUTPUT_BYTES {
                self.pending.zeroize();
                self.pending.clear();
                return Err(format!(
                    "agent output exceeds {MAX_HEADLESS_OUTPUT_BYTES} bytes"
                ));
            }
            return Ok(Vec::new());
        }
        let mut out = Vec::with_capacity(bytes.len());
        let mut start = 0usize;
        while let Some(relative) = memchr::memchr2(b'\n', b'\r', &self.pending[start..]) {
            let end = start + relative + 1;
            let mut record = self.pending[start..end].to_vec();
            let masked = self.mask_record(&record);
            record.zeroize();
            let masked = match masked {
                Ok(masked) => masked,
                Err(error) => {
                    self.pending.zeroize();
                    self.pending.clear();
                    out.zeroize();
                    return Err(error);
                }
            };
            out.extend(masked);
            start = end;
        }
        if start > 0 {
            let remaining = self.pending.len() - start;
            self.pending.copy_within(start.., 0);
            self.pending[remaining..].zeroize();
            self.pending.truncate(remaining);
        }
        if self.pending.len() > MAX_HEADLESS_OUTPUT_RECORD_BYTES {
            self.pending.zeroize();
            self.pending.clear();
            out.zeroize();
            return Err(format!(
                "agent output record exceeds {MAX_HEADLESS_OUTPUT_RECORD_BYTES} bytes"
            ));
        }
        Ok(out)
    }

    fn finish(&mut self) -> Result<Vec<u8>, String> {
        let mut out = Vec::new();
        if !self.pending.is_empty() {
            let mut record = std::mem::take(&mut self.pending);
            let masked = self.mask_record(&record);
            record.zeroize();
            match masked {
                Ok(masked) => out.extend(masked),
                Err(error) => {
                    out.zeroize();
                    return Err(error);
                }
            }
        }
        out.extend(self.remasker.finish()?);
        Ok(out)
    }

    fn mask_record(&mut self, record: &[u8]) -> Result<Vec<u8>, String> {
        let text = std::str::from_utf8(record)
            .map_err(|_| "agent output must be UTF-8 text so Pentect can protect it".to_string())?;
        let Some(detector) = &mut self.detector else {
            return self.remasker.push(record);
        };
        if self.output_mode == OutputMode::Text && benign_identifier_metadata_record(record) {
            return self.remasker.push(record);
        }
        if self.output_mode == OutputMode::JsonRecords {
            return mask_json_record(record, detector, &mut self.remasker);
        }
        let Some(mut masked) = detector.mask_tool_output(text)? else {
            return self.remasker.push(record);
        };
        let result = self.remasker.push(masked.as_bytes());
        masked.zeroize();
        result
    }
}

fn benign_identifier_metadata_record(record: &[u8]) -> bool {
    use pentect_core::OverMaskGuard;

    let Ok(text) = std::str::from_utf8(record) else {
        return false;
    };
    let Some((key, value)) = text.trim().split_once(':') else {
        return false;
    };
    let tokens = key
        .split(|character: char| !character.is_ascii_alphanumeric())
        .filter(|token| !token.is_empty())
        .map(str::to_ascii_lowercase)
        .collect::<Vec<_>>();
    if !tokens
        .iter()
        .any(|token| matches!(token.as_str(), "id" | "uuid" | "hash" | "sha"))
        || tokens.iter().any(|token| {
            matches!(
                token.as_str(),
                "secret" | "token" | "key" | "password" | "credential" | "auth" | "cookie"
            )
        })
    {
        return false;
    }
    pentect_core::ShapeGuard::builtin().benign(value.trim())
}

impl Drop for HeadlessOutputMasker {
    fn drop(&mut self) {
        self.pending.zeroize();
    }
}

fn mask_json_record(
    record: &[u8],
    detector: &mut pentect_agent::ActiveToolOutputMasker,
    remasker: &mut pentect_agent::ActiveTerminalOutputRemasker,
) -> Result<Vec<u8>, String> {
    let body_len = record
        .iter()
        .rposition(|byte| !matches!(byte, b'\r' | b'\n'))
        .map_or(0, |index| index + 1);
    let (body, ending) = record.split_at(body_len);
    if body.iter().all(u8::is_ascii_whitespace) {
        return remasker.push(record);
    }
    let mut value: serde_json::Value = serde_json::from_slice(body)
        .map_err(|error| format!("agent JSON output is invalid: {error}"))?;
    let images_changed = match redact_json_images(&mut value) {
        Ok(changed) => changed,
        Err(error) => {
            zeroize_json_strings(&mut value);
            return Err(error);
        }
    };
    let suppressed = suppress_partial_json_deltas(&mut value);
    let changed = mask_json_value(&mut value, true, &mut |text| {
        detector.mask_tool_output(text)
    });
    let changed = match changed {
        Ok(changed) => images_changed || suppressed || changed,
        Err(error) => {
            zeroize_json_strings(&mut value);
            return Err(error);
        }
    };
    if !changed {
        zeroize_json_strings(&mut value);
        return remasker.push(record);
    }
    let encoded = serde_json::to_vec(&value);
    zeroize_json_strings(&mut value);
    let mut masked = encoded
        .map_err(|error| format!("could not encode protected agent JSON output: {error}"))?;
    masked.extend_from_slice(ending);
    let result = remasker.push(&masked);
    masked.zeroize();
    result
}

fn redact_json_images(value: &mut serde_json::Value) -> Result<bool, String> {
    let Some(updated) = pentect_agent::redact_tool_images_into_active_memory_store(value)? else {
        return Ok(false);
    };
    zeroize_json_strings(value);
    *value = updated;
    Ok(true)
}

fn mask_json_value<F>(
    value: &mut serde_json::Value,
    scan_string: bool,
    mask: &mut F,
) -> Result<bool, String>
where
    F: FnMut(&str) -> Result<Option<String>, String>,
{
    mask_json_value_scoped(value, scan_string, JsonProtocolScope::Root, mask)
}

#[derive(Clone, Copy)]
enum JsonProtocolScope {
    Root,
    Message,
    MessageContent,
    Other,
}

fn mask_json_value_scoped<F>(
    value: &mut serde_json::Value,
    scan_string: bool,
    scope: JsonProtocolScope,
    mask: &mut F,
) -> Result<bool, String>
where
    F: FnMut(&str) -> Result<Option<String>, String>,
{
    match value {
        serde_json::Value::Object(object) => {
            let object_type = object
                .get("type")
                .and_then(serde_json::Value::as_str)
                .map(str::to_string);
            let mut changed = false;
            for (key, value) in object {
                let scan_child = scan_string
                    && !value.as_str().is_some_and(looks_like_image_payload_string)
                    && !value
                        .as_str()
                        .is_some_and(|text| safe_protocol_path(key, text))
                    && !value.as_str().is_some_and(|text| {
                        safe_agent_protocol_metadata(scope, object_type.as_deref(), key, text)
                    });
                let child_scope = match (scope, key.as_str()) {
                    (JsonProtocolScope::Root, "message") => JsonProtocolScope::Message,
                    (JsonProtocolScope::Message, "content") => JsonProtocolScope::MessageContent,
                    _ => JsonProtocolScope::Other,
                };
                changed |= mask_json_value_scoped(value, scan_child, child_scope, mask)?;
            }
            Ok(changed)
        }
        serde_json::Value::Array(values) => {
            let mut changed = false;
            for value in values {
                changed |= mask_json_value_scoped(value, scan_string, scope, mask)?;
            }
            Ok(changed)
        }
        serde_json::Value::String(text) if scan_string => {
            let Some(masked) = mask(text)? else {
                return Ok(false);
            };
            if masked == *text {
                return Ok(false);
            }
            text.zeroize();
            *text = masked;
            Ok(true)
        }
        _ => Ok(false),
    }
}

fn safe_agent_protocol_metadata(
    scope: JsonProtocolScope,
    object_type: Option<&str>,
    key: &str,
    text: &str,
) -> bool {
    match scope {
        JsonProtocolScope::Root => {
            matches!(
                key,
                "uuid"
                    | "session_id"
                    | "sessionId"
                    | "request_id"
                    | "requestId"
                    | "response_id"
                    | "responseId"
                    | "parent_tool_use_id"
                    | "parentToolUseId"
                    | "hook_id"
                    | "hookId"
                    | "prompt_id"
                    | "promptId"
                    | "parent_uuid"
                    | "parentUuid"
                    | "leaf_uuid"
                    | "leafUuid"
            ) && known_agent_protocol_id(text)
        }
        JsonProtocolScope::Message => {
            key == "id" && text.starts_with("msg_") && protocol_tail(text)
        }
        JsonProtocolScope::MessageContent => {
            (key == "id" && text.starts_with("toolu_") && protocol_tail(text))
                || (matches!(key, "tool_use_id" | "toolUseId")
                    && text.starts_with("toolu_")
                    && protocol_tail(text))
                || (key == "signature" && object_type == Some("thinking"))
        }
        JsonProtocolScope::Other => false,
    }
}

fn known_agent_protocol_id(text: &str) -> bool {
    uuid_shape(text)
        || [
            "req_", "resp_", "msg_", "toolu_", "call_", "item_", "thread_", "turn_",
        ]
        .iter()
        .any(|prefix| text.starts_with(prefix) && protocol_tail(text))
}

fn protocol_tail(text: &str) -> bool {
    let Some((_, tail)) = text.split_once('_') else {
        return false;
    };
    tail.len() >= 8
        && tail
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
}

fn uuid_shape(text: &str) -> bool {
    text.len() == 36
        && text.bytes().enumerate().all(|(index, byte)| {
            if matches!(index, 8 | 13 | 18 | 23) {
                byte == b'-'
            } else {
                byte.is_ascii_hexdigit()
            }
        })
}

fn safe_protocol_path(key: &str, text: &str) -> bool {
    use pentect_core::OverMaskGuard;

    if !matches!(key, "path" | "cwd") {
        return false;
    }
    let candidate = text
        .strip_prefix("file:///")
        .or_else(|| text.strip_prefix("file://"))
        .unwrap_or(text);
    !text.contains(['?', '#', '\r', '\n']) && pentect_core::ShapeGuard::builtin().benign(candidate)
}

fn looks_like_image_payload_string(text: &str) -> bool {
    text.trim_start()
        .get(..11)
        .is_some_and(|prefix| prefix.eq_ignore_ascii_case("data:image/"))
}

fn suppress_partial_json_deltas(value: &mut serde_json::Value) -> bool {
    if !json_has_partial_event_marker(value) {
        return false;
    }
    clear_partial_json_payload(value, None)
}

fn json_has_partial_event_marker(value: &serde_json::Value) -> bool {
    match value {
        serde_json::Value::Object(object) => {
            object.iter().any(|(key, value)| {
                matches!(key.as_str(), "type" | "event" | "method")
                    && value.as_str().is_some_and(|text| {
                        let lower = text.to_ascii_lowercase();
                        lower == "stream_event"
                            || lower
                                .rsplit(['/', '_'])
                                .next()
                                .is_some_and(|part| part.ends_with("delta"))
                    })
            }) || object.values().any(json_has_partial_event_marker)
        }
        serde_json::Value::Array(values) => values.iter().any(json_has_partial_event_marker),
        _ => false,
    }
}

fn clear_partial_json_payload(value: &mut serde_json::Value, key: Option<&str>) -> bool {
    match value {
        serde_json::Value::Object(object) => {
            let mut changed = false;
            for (key, value) in object {
                changed |= clear_partial_json_payload(value, Some(key));
            }
            changed
        }
        serde_json::Value::Array(values) => {
            let mut changed = false;
            for value in values {
                changed |= clear_partial_json_payload(value, key);
            }
            changed
        }
        serde_json::Value::String(text) if !key.is_some_and(partial_json_metadata_key) => {
            text.zeroize();
            text.clear();
            true
        }
        _ => false,
    }
}

fn partial_json_metadata_key(key: &str) -> bool {
    matches!(
        key,
        "type"
            | "event"
            | "method"
            | "jsonrpc"
            | "id"
            | "request_id"
            | "response_id"
            | "session_id"
            | "thread_id"
            | "turn_id"
            | "item_id"
            | "message_id"
            | "tool_use_id"
            | "call_id"
            | "parent_id"
            | "uuid"
            | "status"
            | "phase"
            | "timestamp"
            | "created_at"
            | "updated_at"
            | "version"
    )
}

fn zeroize_json_strings(value: &mut serde_json::Value) {
    match value {
        serde_json::Value::Object(object) => {
            for value in object.values_mut() {
                zeroize_json_strings(value);
            }
        }
        serde_json::Value::Array(values) => {
            for value in values {
                zeroize_json_strings(value);
            }
        }
        serde_json::Value::String(text) => text.zeroize(),
        _ => {}
    }
}

fn drain_sensitive(reader: &mut impl Read) {
    let mut buffer = [0u8; 8192];
    loop {
        match reader.read(&mut buffer) {
            Ok(0) | Err(_) => break,
            Ok(read) => buffer[..read].zeroize(),
        }
    }
    buffer.zeroize();
}

fn read_masked_buffered_stdin() -> Result<Vec<u8>, String> {
    let mut input = Vec::new();
    if let Err(error) = io::stdin()
        .take((MAX_HEADLESS_INPUT_BYTES + 1) as u64)
        .read_to_end(&mut input)
    {
        input.zeroize();
        return Err(format!("could not read agent stdin: {error}"));
    }
    if input.len() > MAX_HEADLESS_INPUT_BYTES {
        input.zeroize();
        return Err(format!(
            "agent stdin exceeds {MAX_HEADLESS_INPUT_BYTES} bytes"
        ));
    }
    let mut masked = Vec::with_capacity(input.len());
    let result = pentect_agent::ActiveToolOutputMasker::new()
        .and_then(|mut masker| mask_and_write_prompt(&input, &mut masked, &mut masker));
    input.zeroize();
    match result {
        Ok(()) => Ok(masked),
        Err(error) => {
            masked.zeroize();
            Err(error)
        }
    }
}

fn write_buffered_stdin(mut child_stdin: impl Write, mut buffered: Vec<u8>) -> Result<(), String> {
    let result = child_stdin
        .write_all(&buffered)
        .and_then(|()| child_stdin.flush())
        .map_err(|error| format!("could not write agent stdin: {error}"));
    buffered.zeroize();
    result
}

fn read_json_lines(
    sender: mpsc::SyncSender<Result<Vec<u8>, String>>,
    cancelled: Arc<AtomicBool>,
) -> Result<(), String> {
    let stdin = io::stdin();
    let mut reader = io::BufReader::new(stdin.lock());
    let mut total = 0usize;
    let mut line = Vec::new();
    loop {
        if cancelled.load(Ordering::Acquire) {
            break;
        }
        line.clear();
        let mut read = match reader.read_until(b'\n', &mut line) {
            Ok(read) => read,
            Err(error) => {
                line.zeroize();
                let _ = sender.send(Err(format!("could not read agent stdin: {error}")));
                return Ok(());
            }
        };
        if read == 0 {
            break;
        }
        if utf16le_line_needs_trailing_byte(&line) {
            let mut trailing = [0u8; 1];
            if let Err(error) = reader.read_exact(&mut trailing) {
                line.zeroize();
                trailing.zeroize();
                let _ = sender.send(Err(format!(
                    "could not complete agent UTF-16 stdin line: {error}"
                )));
                return Ok(());
            }
            line.push(trailing[0]);
            trailing.zeroize();
            read += 1;
        }
        total = total.saturating_add(read);
        if total > MAX_HEADLESS_INPUT_BYTES {
            line.zeroize();
            let _ = sender.send(Err(format!(
                "agent stdin exceeds {MAX_HEADLESS_INPUT_BYTES} bytes"
            )));
            return Ok(());
        }
        let next = std::mem::take(&mut line);
        if let Err(error) = sender.send(Ok(next)) {
            if let Ok(mut unsent) = error.0 {
                unsent.zeroize();
            }
            break;
        }
    }
    line.zeroize();
    Ok(())
}

fn mask_and_write_json_prompt(
    input: &[u8],
    output: &mut impl Write,
    masker: &mut pentect_agent::ActiveToolOutputMasker,
) -> Result<(), String> {
    let mut decoded = decode_agent_input(input)?;
    let body_len = decoded
        .as_bytes()
        .iter()
        .rposition(|byte| !matches!(byte, b'\r' | b'\n'))
        .map_or(0, |index| index + 1);
    let parsed = serde_json::from_slice(&decoded.as_bytes()[..body_len]);
    let mut value: serde_json::Value = match parsed {
        Ok(value) => value,
        Err(error) => {
            decoded.zeroize();
            return Err(format!("agent JSON input is invalid: {error}"));
        }
    };
    let images_changed = match redact_json_images(&mut value) {
        Ok(changed) => changed,
        Err(error) => {
            zeroize_json_strings(&mut value);
            decoded.zeroize();
            return Err(error);
        }
    };
    let changed = mask_json_value(&mut value, true, &mut |text| masker.mask_prompt_text(text));
    let changed = match changed {
        Ok(changed) => images_changed || changed,
        Err(error) => {
            zeroize_json_strings(&mut value);
            decoded.zeroize();
            return Err(error);
        }
    };
    if !changed {
        zeroize_json_strings(&mut value);
        let result = output
            .write_all(decoded.as_bytes())
            .map_err(|error| format!("could not write agent stdin: {error}"));
        decoded.zeroize();
        return result;
    }
    let encoded = serde_json::to_vec(&value);
    zeroize_json_strings(&mut value);
    let mut masked =
        encoded.map_err(|error| format!("could not encode protected agent JSON input: {error}"))?;
    masked.extend_from_slice(&decoded.as_bytes()[body_len..]);
    decoded.zeroize();
    let result = output
        .write_all(&masked)
        .map_err(|error| format!("could not write agent stdin: {error}"));
    masked.zeroize();
    result
}

fn mask_and_write_prompt(
    input: &[u8],
    output: &mut impl Write,
    masker: &mut pentect_agent::ActiveToolOutputMasker,
) -> Result<(), String> {
    let mut text = decode_agent_input(input)?;
    let masked_result = masker.mask_prompt_text(&text);
    let mut masked = match masked_result {
        Ok(masked) => masked,
        Err(error) => {
            text.zeroize();
            return Err(error);
        }
    };
    let bytes = masked.as_deref().unwrap_or(&text).as_bytes();
    let result = output
        .write_all(bytes)
        .map_err(|error| format!("could not write agent stdin: {error}"));
    if let Some(masked) = masked.as_mut() {
        masked.zeroize();
    }
    text.zeroize();
    result
}

fn decode_agent_input(input: &[u8]) -> Result<String, String> {
    let (bytes, little_endian) = if let Some(bytes) = input.strip_prefix(&[0xff, 0xfe]) {
        (bytes, Some(true))
    } else if let Some(bytes) = input.strip_prefix(&[0xfe, 0xff]) {
        (bytes, Some(false))
    } else if looks_like_utf16(input, true) {
        (input, Some(true))
    } else if looks_like_utf16(input, false) {
        (input, Some(false))
    } else {
        let text = std::str::from_utf8(input)
            .map_err(|_| "agent stdin must be UTF-8 or UTF-16 text".to_string())?;
        return Ok(text.strip_prefix('\u{feff}').unwrap_or(text).to_string());
    };
    if !bytes.len().is_multiple_of(2) {
        return Err("agent UTF-16 stdin has an incomplete code unit".to_string());
    }
    let little_endian = little_endian.unwrap_or(true);
    let mut units = bytes
        .chunks_exact(2)
        .map(|pair| {
            if little_endian {
                u16::from_le_bytes([pair[0], pair[1]])
            } else {
                u16::from_be_bytes([pair[0], pair[1]])
            }
        })
        .collect::<Vec<_>>();
    let decoded = String::from_utf16(&units)
        .map_err(|_| "agent stdin contains invalid UTF-16 text".to_string());
    units.zeroize();
    decoded
}

fn looks_like_utf16(bytes: &[u8], little_endian: bool) -> bool {
    if bytes.len() < 4 || !bytes.len().is_multiple_of(2) {
        return false;
    }
    let (expected_zeroes, other_zeroes) =
        bytes
            .chunks_exact(2)
            .fold((0usize, 0usize), |(expected, other), pair| {
                let (expected_byte, other_byte) = if little_endian {
                    (pair[1], pair[0])
                } else {
                    (pair[0], pair[1])
                };
                (
                    expected + usize::from(expected_byte == 0),
                    other + usize::from(other_byte == 0),
                )
            });
    let units = bytes.len() / 2;
    expected_zeroes * 4 >= units * 3 && other_zeroes * 8 <= units
}

fn utf16le_line_needs_trailing_byte(bytes: &[u8]) -> bool {
    if bytes.len() < 3 || bytes.len().is_multiple_of(2) || bytes.last() != Some(&b'\n') {
        return false;
    }
    bytes.starts_with(&[0xff, 0xfe]) || looks_like_utf16(&bytes[..bytes.len() - 1], true)
}

fn join_input(thread: JoinHandle<Result<(), String>>) -> Result<(), String> {
    if !thread.is_finished() {
        return Ok(());
    }
    thread
        .join()
        .map_err(|_| "agent stdin thread panicked".to_string())?
}

fn join_output(thread: JoinHandle<Result<(), String>>, stream: &str) -> Result<(), String> {
    thread
        .join()
        .map_err(|_| format!("agent {stream} thread panicked"))?
}

fn rewrite_prompt_args_with<F>(
    agent: AgentKind,
    args: &[String],
    mask: &mut F,
) -> Result<Vec<String>, String>
where
    F: FnMut(&str) -> Result<Option<String>, String>,
{
    let positional_prompt = match agent {
        AgentKind::Codex => codex_prompt_index(args),
        AgentKind::Claude => claude_prompt_index(args),
    };
    let mut rewritten = args.to_vec();
    if let Some(index) = positional_prompt.filter(|index| rewritten[*index] != "-") {
        rewrite_prompt_value(&mut rewritten[index], mask)?;
    }
    if agent == AgentKind::Claude {
        let mut index = 0usize;
        while index < rewritten.len() {
            let arg = rewritten[index].as_str();
            if claude_prompt_option(arg) {
                if let Some(value) = rewritten.get_mut(index + 1) {
                    rewrite_prompt_value(value, mask)?;
                }
                index += 2;
                continue;
            }
            if let Some((prefix, value)) = claude_inline_prompt_option(arg) {
                let mut rewritten_value = value.to_string();
                rewrite_prompt_value(&mut rewritten_value, mask)?;
                rewritten[index] = format!("{prefix}={rewritten_value}");
            }
            index += 1;
        }
    }
    Ok(rewritten)
}

fn rewrite_prompt_value<F>(value: &mut String, mask: &mut F) -> Result<(), String>
where
    F: FnMut(&str) -> Result<Option<String>, String>,
{
    if let Some(masked) = mask(value)? {
        *value = masked;
    }
    Ok(())
}

fn claude_prompt_option(arg: &str) -> bool {
    matches!(
        arg,
        "--append-system-prompt" | "--system-prompt" | "--agents"
    )
}

fn claude_inline_prompt_option(arg: &str) -> Option<(&str, &str)> {
    let (name, value) = arg.split_once('=')?;
    claude_prompt_option(name).then_some((name, value))
}

fn codex_prompt_index(args: &[String]) -> Option<usize> {
    let root = codex_root_positional_indices(args);
    let first = *root.first()?;
    match args[first].as_str() {
        "exec" | "e" => codex_exec_prompt_index(args, first + 1),
        "review" => positional_indices(args, first + 1, codex_option_kind)
            .last()
            .copied(),
        "resume" | "fork" => codex_session_prompt_index(args, first + 1),
        command if is_codex_command(command) => None,
        _ => Some(first),
    }
}

fn codex_exec_prompt_index(args: &[String], start: usize) -> Option<usize> {
    let positionals = positional_indices(args, start, codex_option_kind);
    let first = *positionals.first()?;
    match args[first].as_str() {
        "review" => positionals.get(1..)?.last().copied(),
        "resume" => codex_session_prompt_index(args, first + 1),
        "help" => None,
        _ => positionals.last().copied(),
    }
}

fn codex_session_prompt_index(args: &[String], start: usize) -> Option<usize> {
    let positionals = positional_indices(args, start, codex_session_option_kind);
    if positionals.len() >= 2 || (positionals.len() == 1 && has_flag(args, start, "--last")) {
        positionals.last().copied()
    } else {
        None
    }
}

fn codex_reads_prompt_from_stdin(args: &[String]) -> bool {
    let root = codex_root_positional_indices(args);
    let Some(first) = root.first().copied() else {
        return false;
    };
    match args[first].as_str() {
        "exec" | "e" => {
            let positionals = positional_indices(args, first + 1, codex_option_kind);
            match positionals.first().map(|index| args[*index].as_str()) {
                None => true,
                Some("review") | Some("resume") => {
                    positionals.last().is_some_and(|index| args[*index] == "-")
                }
                Some("help") => false,
                Some(_) => positionals.last().is_some_and(|index| args[*index] == "-"),
            }
        }
        "review" => root.last().is_some_and(|index| args[*index] == "-"),
        _ => false,
    }
}

fn codex_accepts_prompt_input(args: &[String]) -> bool {
    let root = codex_root_positional_indices(args);
    root.first()
        .is_some_and(|index| matches!(args[*index].as_str(), "exec" | "e" | "review"))
}

fn claude_prompt_index(args: &[String]) -> Option<usize> {
    let positionals = positional_indices(args, 0, claude_option_kind);
    let first = *positionals.first()?;
    (!is_claude_command(&args[first])).then_some(first)
}

fn claude_reads_prompt_from_stdin(
    args: &[String],
    stdin_is_terminal: bool,
    stdout_is_terminal: bool,
) -> bool {
    let positionals = positional_indices(args, 0, claude_option_kind);
    if positionals
        .first()
        .is_some_and(|index| is_claude_command(&args[*index]))
    {
        return false;
    }
    if let Some(prompt) = claude_prompt_index(args) {
        return args[prompt] == "-" || !stdin_is_terminal;
    }
    !stdin_is_terminal
        || args
            .iter()
            .any(|arg| matches!(arg.as_str(), "-p" | "--print"))
        || !stdout_is_terminal
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum OptionKind {
    Flag,
    Value,
    Variadic,
}

fn codex_root_positional_indices(args: &[String]) -> Vec<usize> {
    let mut out = Vec::new();
    let mut index = 0usize;
    while index < args.len() {
        let arg = args[index].as_str();
        if arg == "--" {
            out.extend(index + 1..args.len());
            break;
        }
        if arg == "-" || !arg.starts_with('-') {
            out.push(index);
            index += 1;
            continue;
        }
        if arg.contains('=') {
            index += 1;
            continue;
        }
        if matches!(arg, "-i" | "--image") {
            index += 1;
            while index < args.len()
                && !args[index].starts_with('-')
                && !is_codex_command(&args[index])
            {
                index += 1;
            }
            continue;
        }
        index += match codex_option_kind(arg) {
            OptionKind::Flag => 1,
            OptionKind::Value | OptionKind::Variadic => 2,
        };
    }
    out
}

fn positional_indices(
    args: &[String],
    start: usize,
    option_kind: fn(&str) -> OptionKind,
) -> Vec<usize> {
    // These adapters preserve operational values such as model names, paths,
    // and session IDs while isolating the model-visible positional argument.
    let mut out = Vec::new();
    let mut index = start;
    while index < args.len() {
        let arg = args[index].as_str();
        if arg == "--" {
            out.extend(index + 1..args.len());
            break;
        }
        if arg == "-" || !arg.starts_with('-') {
            out.push(index);
            index += 1;
            continue;
        }
        if arg.contains('=') {
            index += 1;
            continue;
        }
        match option_kind(arg) {
            OptionKind::Flag => index += 1,
            OptionKind::Value => index += 2,
            OptionKind::Variadic => {
                index += 1;
                while index < args.len() && !args[index].starts_with('-') {
                    index += 1;
                }
            }
        }
    }
    out
}

fn codex_option_kind(arg: &str) -> OptionKind {
    if matches!(arg, "-i" | "--image") {
        return OptionKind::Variadic;
    }
    if matches!(
        arg,
        "-c" | "--config"
            | "--enable"
            | "--disable"
            | "-m"
            | "--model"
            | "--local-provider"
            | "-p"
            | "--profile"
            | "-s"
            | "--sandbox"
            | "-a"
            | "--ask-for-approval"
            | "-C"
            | "--cd"
            | "--add-dir"
            | "--output-schema"
            | "--color"
            | "-o"
            | "--output-last-message"
            | "--base"
            | "--commit"
            | "--title"
            | "--remote"
            | "--remote-auth-token-env"
    ) {
        OptionKind::Value
    } else {
        OptionKind::Flag
    }
}

fn codex_session_option_kind(arg: &str) -> OptionKind {
    if matches!(arg, "-i" | "--image") {
        OptionKind::Value
    } else {
        codex_option_kind(arg)
    }
}

fn claude_option_kind(arg: &str) -> OptionKind {
    if matches!(
        arg,
        "--add-dir"
            | "--allowedTools"
            | "--allowed-tools"
            | "--betas"
            | "--disallowedTools"
            | "--disallowed-tools"
            | "--file"
            | "--mcp-config"
            | "--tools"
    ) {
        return OptionKind::Variadic;
    }
    if matches!(
        arg,
        "--agent"
            | "--agents"
            | "--append-system-prompt"
            | "-d"
            | "--debug"
            | "--debug-file"
            | "--effort"
            | "--fallback-model"
            | "--from-pr"
            | "--input-format"
            | "--json-schema"
            | "--max-budget-usd"
            | "--model"
            | "-n"
            | "--name"
            | "--output-format"
            | "--permission-mode"
            | "--plugin-dir"
            | "--plugin-url"
            | "--prompt-suggestions"
            | "--remote-control"
            | "--remote-control-session-name-prefix"
            | "-r"
            | "--resume"
            | "--session-id"
            | "--setting-sources"
            | "--settings"
            | "--system-prompt"
            | "--worktree"
            | "-w"
    ) {
        OptionKind::Value
    } else {
        OptionKind::Flag
    }
}

fn has_flag(args: &[String], start: usize, flag: &str) -> bool {
    args.iter().skip(start).any(|arg| arg == flag)
}

pub(crate) fn is_codex_command(value: &str) -> bool {
    matches!(
        value,
        "exec"
            | "e"
            | "review"
            | "login"
            | "logout"
            | "mcp"
            | "plugin"
            | "mcp-server"
            | "app-server"
            | "remote-control"
            | "app"
            | "completion"
            | "update"
            | "debug"
            | "apply"
            | "resume"
            | "archive"
            | "delete"
            | "unarchive"
            | "fork"
            | "doctor"
            | "sandbox"
            | "features"
            | "cloud"
            | "help"
    )
}

fn is_claude_command(value: &str) -> bool {
    matches!(
        value,
        "agents"
            | "auth"
            | "auto-mode"
            | "doctor"
            | "gateway"
            | "install"
            | "mcp"
            | "plugin"
            | "plugins"
            | "project"
            | "setup-token"
            | "ultrareview"
            | "update"
            | "upgrade"
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rewrite(agent: AgentKind, args: &[&str]) -> Vec<String> {
        let args = args.iter().map(|arg| arg.to_string()).collect::<Vec<_>>();
        rewrite_prompt_args_with(agent, &args, &mut |text| {
            Ok(Some(text.replace("raw-secret", "<<SECRET_test>>")))
        })
        .unwrap()
    }

    #[test]
    fn codex_exec_masks_only_prompt() {
        let args = rewrite(
            AgentKind::Codex,
            &["--model", "raw-secret-model", "exec", "use raw-secret"],
        );
        assert_eq!(args[1], "raw-secret-model");
        assert_eq!(args[3], "use <<SECRET_test>>");
    }

    #[test]
    fn codex_short_approval_option_keeps_value_and_masks_prompt() {
        let args = rewrite(AgentKind::Codex, &["-a", "never", "exec", "use raw-secret"]);
        assert_eq!(args[1], "never");
        assert_eq!(args[3], "use <<SECRET_test>>");
    }

    #[test]
    fn codex_images_are_rewritten_without_touching_the_prompt() {
        let mut args = vec![
            "-i".to_string(),
            "first.png,second.png".to_string(),
            "exec".to_string(),
            "--image=third.png".to_string(),
            "-i".to_string(),
            "fourth.png".to_string(),
            "fifth.png".to_string(),
            "--".to_string(),
            "use raw-secret".to_string(),
        ];
        rewrite_codex_image_values(&mut args, &mut |value| Ok(format!("safe-{value}"))).unwrap();
        assert_eq!(args[1], "safe-first.png,second.png");
        assert_eq!(args[3], "--image=safe-third.png");
        assert_eq!(args[5], "safe-fourth.png");
        assert_eq!(args[6], "safe-fifth.png");
        assert_eq!(args[8], "use raw-secret");

        let masked = rewrite(
            AgentKind::Codex,
            &args.iter().map(String::as_str).collect::<Vec<_>>(),
        );
        assert_eq!(masked[8], "use <<SECRET_test>>");
        assert_eq!(image_extension(b"\x89PNG\r\n\x1a\nrest"), Some("png"));
        assert_eq!(image_extension(b"\xff\xd8\xffrest"), Some("jpg"));
    }

    #[test]
    fn codex_exec_stdin_marker_is_preserved() {
        let args = rewrite(AgentKind::Codex, &["exec", "-"]);
        assert_eq!(args, ["exec", "-"]);
    }

    #[test]
    fn codex_resume_keeps_session_and_masks_prompt() {
        let args = rewrite(
            AgentKind::Codex,
            &["exec", "resume", "raw-secret-session", "use raw-secret"],
        );
        assert_eq!(args[2], "raw-secret-session");
        assert_eq!(args[3], "use <<SECRET_test>>");
    }

    #[test]
    fn codex_root_resume_and_fork_mask_only_prompt() {
        for command in ["resume", "fork"] {
            let args = rewrite(
                AgentKind::Codex,
                &[command, "raw-secret-session", "use raw-secret"],
            );
            assert_eq!(args[1], "raw-secret-session");
            assert_eq!(args[2], "use <<SECRET_test>>");

            let args = rewrite(AgentKind::Codex, &[command, "--last", "use raw-secret"]);
            assert_eq!(args[2], "use <<SECRET_test>>");
        }
    }

    #[test]
    fn codex_review_masks_custom_instructions() {
        let args = rewrite(
            AgentKind::Codex,
            &["review", "--base", "main", "find raw-secret"],
        );
        assert_eq!(args[2], "main");
        assert_eq!(args[3], "find <<SECRET_test>>");
    }

    #[test]
    fn claude_print_masks_prompt_and_keeps_option_values() {
        let args = rewrite(
            AgentKind::Claude,
            &["-p", "--model", "raw-secret-model", "use raw-secret"],
        );
        assert_eq!(args[2], "raw-secret-model");
        assert_eq!(args[3], "use <<SECRET_test>>");
    }

    #[test]
    fn claude_commands_are_not_treated_as_prompts() {
        let args = rewrite(AgentKind::Claude, &["doctor", "raw-secret"]);
        assert_eq!(args, ["doctor", "raw-secret"]);
    }

    #[test]
    fn claude_single_value_options_do_not_consume_prompt() {
        for option in ["--plugin-dir", "--remote-control-session-name-prefix"] {
            let args = rewrite(
                AgentKind::Claude,
                &["-p", option, "raw-secret-option", "use raw-secret"],
            );
            assert_eq!(args[2], "raw-secret-option");
            assert_eq!(args[3], "use <<SECRET_test>>");
        }
    }

    #[test]
    fn claude_masks_model_visible_option_values() {
        let args = rewrite(
            AgentKind::Claude,
            &[
                "-p",
                "--system-prompt=keep raw-secret private",
                "--append-system-prompt",
                "also raw-secret",
                "answer raw-secret",
            ],
        );
        assert_eq!(args[1], "--system-prompt=keep <<SECRET_test>> private");
        assert_eq!(args[3], "also <<SECRET_test>>");
        assert_eq!(args[4], "answer <<SECRET_test>>");
    }

    #[test]
    fn claude_stream_json_selects_line_mode() {
        assert_eq!(
            claude_input_mode(&["-p".into(), "--input-format=stream-json".into()]),
            InputMode::JsonLines
        );
        assert_eq!(
            claude_input_mode(&["-p".into(), "--input-format".into(), "stream-json".into()]),
            InputMode::JsonLines
        );
    }

    #[test]
    fn machine_readable_output_modes_are_detected() {
        assert_eq!(
            codex_output_mode(&["exec".into(), "--json".into()]),
            OutputMode::JsonRecords
        );
        assert_eq!(
            claude_output_mode(&["-p".into(), "--output-format=json".into()]),
            OutputMode::JsonRecords
        );
        assert_eq!(
            claude_output_mode(&["-p".into(), "--output-format".into(), "stream-json".into()]),
            OutputMode::JsonRecords
        );
        assert!(claude_uses_partial_output(&[
            "-p".into(),
            "--include-partial-messages".into()
        ]));
        assert!(!claude_uses_partial_output(&["-p".into()]));
        assert_eq!(
            codex_output_mode(&["exec".into(), "--".into(), "--json".into()]),
            OutputMode::Text
        );
        assert_eq!(
            claude_output_mode(&["-p".into(), "--".into(), "--output-format=json".into()]),
            OutputMode::Text
        );
        assert!(!claude_uses_partial_output(&[
            "-p".into(),
            "--".into(),
            "--include-partial-messages".into()
        ]));
    }

    #[test]
    fn agent_input_decodes_powershell_utf16() {
        let text = "{\"type\":\"user\"}\r\n";
        let mut little = text
            .encode_utf16()
            .flat_map(u16::to_le_bytes)
            .collect::<Vec<_>>();
        assert_eq!(decode_agent_input(&little).unwrap(), text);
        little.splice(0..0, [0xff, 0xfe]);
        assert_eq!(decode_agent_input(&little).unwrap(), text);

        let mut partial = text
            .encode_utf16()
            .flat_map(u16::to_le_bytes)
            .collect::<Vec<_>>();
        assert_eq!(partial.pop(), Some(0));
        assert!(utf16le_line_needs_trailing_byte(&partial));
        little.zeroize();
        partial.zeroize();
    }

    #[test]
    fn structured_output_masks_every_secret_bearing_string() {
        let mut value = serde_json::json!({
            "type": "result",
            "session_id": "raw-secret-session",
            "result": "answer raw-secret",
            "message": {"content": [{"text": "tool raw-secret"}]},
            "item": {"command": "use raw-secret", "arguments": "raw-secret"}
        });
        let changed = mask_json_value(&mut value, true, &mut |text| {
            Ok(Some(text.replace("raw-secret", "<<SECRET_test>>")))
        })
        .unwrap();
        assert!(changed);
        assert_eq!(value["session_id"], "<<SECRET_test>>-session");
        assert_eq!(value["result"], "answer <<SECRET_test>>");
        assert_eq!(
            value["message"]["content"][0]["text"],
            "tool <<SECRET_test>>"
        );
        assert_eq!(value["item"]["command"], "use <<SECRET_test>>");
        assert_eq!(value["item"]["arguments"], "<<SECRET_test>>");
        zeroize_json_strings(&mut value);
    }

    #[test]
    fn structured_output_keeps_only_contextual_agent_protocol_metadata() {
        let signature = "Es0HCokBCA8YAipAWCkIbWnhWvXGSzbzfDUe9zlTS3NWm5lxvwRIrEHE9xdyn94F";
        let mut value = serde_json::json!({
            "type": "assistant",
            "uuid": "a18f48ad-fefb-47be-a6ac-4448de1b0485",
            "request_id": "req_011CdA1L1mNyKdPJUnGC2P8S",
            "message": {
                "id": "msg_011CdA1L4pvzK9sHJpEdvmd8",
                "content": [
                    {"type": "thinking", "signature": signature},
                    {
                        "type": "tool_use",
                        "id": "toolu_01JqZnVvjYnsgRq4noGzy8xG",
                        "input": {"id": "secret-value", "signature": "secret-value"}
                    },
                    {"type": "tool_result", "tool_use_id": "toolu_01JqZnVvjYnsgRq4noGzy8xG"}
                ]
            }
        });
        let changed =
            mask_json_value(&mut value, true, &mut |_| Ok(Some("SCANNED".to_string()))).unwrap();
        assert!(changed);
        assert_eq!(value["uuid"], "a18f48ad-fefb-47be-a6ac-4448de1b0485");
        assert_eq!(value["request_id"], "req_011CdA1L1mNyKdPJUnGC2P8S");
        assert_eq!(value["message"]["id"], "msg_011CdA1L4pvzK9sHJpEdvmd8");
        assert_eq!(value["message"]["content"][0]["signature"], signature);
        assert_eq!(
            value["message"]["content"][1]["id"],
            "toolu_01JqZnVvjYnsgRq4noGzy8xG"
        );
        assert_eq!(
            value["message"]["content"][2]["tool_use_id"],
            "toolu_01JqZnVvjYnsgRq4noGzy8xG"
        );
        assert_eq!(value["message"]["content"][1]["input"]["id"], "SCANNED");
        assert_eq!(
            value["message"]["content"][1]["input"]["signature"],
            "SCANNED"
        );
        zeroize_json_strings(&mut value);
    }

    #[test]
    fn structured_output_suppresses_partial_deltas() {
        let mut value = serde_json::json!({
            "method": "item/agentMessage/delta",
            "params": {
                "thread_id": "thread-1",
                "delta": {
                    "type": "text_delta",
                    "text": "sk-proj-part-one"
                }
            }
        });
        assert!(suppress_partial_json_deltas(&mut value));
        assert_eq!(value["method"], "item/agentMessage/delta");
        assert_eq!(value["params"]["thread_id"], "thread-1");
        assert_eq!(value["params"]["delta"]["type"], "text_delta");
        assert_eq!(value["params"]["delta"]["text"], "");
        zeroize_json_strings(&mut value);
    }

    #[test]
    fn protocol_path_bypass_requires_a_real_path_shape() {
        assert!(safe_protocol_path("cwd", r"C:\Users\yun40\Desktop\pentect"));
        assert!(safe_protocol_path(
            "path",
            "file:///C:/Users/yun40/Desktop/pentect"
        ));
        assert!(!safe_protocol_path(
            "path",
            "Authorization: Bearer sk-proj-secret"
        ));
        assert!(!safe_protocol_path("id", r"C:\Users\yun40\Desktop\pentect"));
    }

    #[test]
    fn diagnostic_identifier_metadata_is_not_treated_as_a_secret() {
        assert!(benign_identifier_metadata_record(
            b"session id: 019f6998-e305-7e81-85de-0a403ecf167e\n"
        ));
        assert!(!benign_identifier_metadata_record(
            b"private key id: 019f6998-e305-7e81-85de-0a403ecf167e\n"
        ));
        assert!(!benign_identifier_metadata_record(
            b"API_TOKEN=sk-proj-PENTECTSyntheticOnly1234567890\n"
        ));
    }

    #[test]
    fn text_output_waits_for_the_complete_response() {
        let mut masker = HeadlessOutputMasker::new(false, OutputMode::Text, OutputFraming::Whole)
            .expect("headless output masker");
        assert!(masker.push(b"first\n").unwrap().is_empty());
        assert!(masker.push(b"second").unwrap().is_empty());
        assert_eq!(masker.finish().unwrap(), b"first\nsecond");

        let mut records =
            HeadlessOutputMasker::new(false, OutputMode::Text, OutputFraming::Records)
                .expect("headless output masker");
        assert_eq!(records.push(b"first\nsecond").unwrap(), b"first\n");
        assert_eq!(records.finish().unwrap(), b"second");
    }

    #[test]
    fn stdin_is_protected_for_headless_agent_input() {
        assert!(protect_stdin(
            AgentKind::Codex,
            &["exec".into(), "--json".into()],
            true,
            true
        ));
        assert!(protect_stdin(
            AgentKind::Claude,
            &["-p".into(), "--output-format".into(), "json".into()],
            true,
            true
        ));
        assert!(protect_stdin(AgentKind::Claude, &[], false, true));
        assert!(protect_stdin(AgentKind::Claude, &[], true, false));
        assert!(protect_stdin(
            AgentKind::Claude,
            &["-p".into(), "hello".into()],
            false,
            true
        ));
        assert!(!protect_stdin(
            AgentKind::Claude,
            &["-p".into(), "hello".into()],
            true,
            true
        ));
        assert!(protect_stdin(
            AgentKind::Claude,
            &["-p".into(), "-".into()],
            false,
            true
        ));
        assert!(protect_stdin(
            AgentKind::Codex,
            &["exec".into(), "hello".into()],
            false,
            true
        ));
        assert!(!protect_stdin(
            AgentKind::Claude,
            &["doctor".into()],
            false,
            false
        ));
    }
}

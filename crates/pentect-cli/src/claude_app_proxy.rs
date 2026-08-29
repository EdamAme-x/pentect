//! Explicit HTTPS gateway for the unmodified Claude Desktop application.
//!
//! The root CA signing key exists only in memory. On Windows, Claude Desktop is
//! launched after explicit user consent with the public root certificate in the
//! current-user trust store; the certificate is removed when the session ends.
//! Other platforms use Chromium's SPKI allow-list. Chat completion bodies are
//! protected in memory and are never logged.

use futures_util::StreamExt;
use http_body_util::combinators::UnsyncBoxBody;
use http_body_util::{BodyExt, Empty, Full, Limited, StreamBody};
use hyper::body::{Bytes, Frame, Incoming};
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Method, Request, Response, StatusCode};
#[cfg(not(windows))]
use rcgen::PublicKeyData;
use rcgen::{
    BasicConstraints, CertificateParams, CertifiedIssuer, DistinguishedName, DnType, IsCa, KeyPair,
    KeyUsagePurpose,
};
#[cfg(windows)]
use sha1::{Digest as Sha1Digest, Sha1};
#[cfg(not(windows))]
use sha2::{Digest, Sha256};
use std::collections::{HashMap, VecDeque};
use std::convert::Infallible;
use std::error::Error;
use std::io;
#[cfg(windows)]
use std::io::{IsTerminal, Write};
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::process::{Command, Stdio};
use std::sync::{mpsc, Arc, Mutex};
use std::thread;
use std::time::Duration;
use tokio::net::TcpListener;
use tokio::sync::oneshot;
use tokio_rustls::rustls::pki_types::{CertificateDer, PrivatePkcs8KeyDer};
use tokio_rustls::rustls::ServerConfig;
use tokio_rustls::TlsAcceptor;
use zeroize::Zeroize;

use crate::handle_contract::HANDLE_CONTRACT;

type ProxyBodyError = Box<dyn Error + Send + Sync>;
type ProxyBody = UnsyncBoxBody<Bytes, ProxyBodyError>;

const MAX_CONNECTIONS: usize = 128;
const MAX_WEBSOCKET_CONNECTIONS: usize = 128;
const MAX_CERTIFICATE_CACHE_ENTRIES: usize = 64;
const MAX_CHAT_BODY_BYTES: usize = 32 * 1024 * 1024;
const MAX_PENDING_UPLOADS: usize = 256;
const MAX_IDS_PER_UPLOAD: usize = 16;
const APP_STARTUP_GRACE: Duration = Duration::from_secs(2);

pub(crate) fn cmd_claude_app(args: &[String]) -> i32 {
    match run_claude_app(args) {
        Ok(status) => status.code().unwrap_or(0),
        Err(error) => {
            eprintln!("[pentect] {error}");
            2
        }
    }
}

pub(crate) fn check_mode(args: &[String]) -> Result<bool, String> {
    ClaudeAppOptions::parse(args).map(|options| options.check)
}

fn run_claude_app(args: &[String]) -> Result<std::process::ExitStatus, String> {
    let options = ClaudeAppOptions::parse(args)?;
    #[cfg(not(windows))]
    let _ = options.assume_yes;
    let app = options.app.unwrap_or_else(default_claude_app_path);
    if options.check {
        let installed = app.is_file();
        println!("App: {}", app.display());
        println!("Installed: {}", if installed { "yes" } else { "no" });
        println!(
            "Running: {}",
            if claude_desktop_is_running(&app) {
                "yes"
            } else {
                "no"
            }
        );
        println!("Protection: supported Claude Desktop Chat and attachment routes");
        println!(
            "Compatibility: Windows uses an explicitly approved, session-only current-user certificate; other platforms require Chromium's certificate-pin switch"
        );
        let upstream = options
            .upstream
            .as_deref()
            .unwrap_or("https://api.anthropic.com");
        crate::upstream::parse_base(upstream, "Anthropic Messages")?;
        crate::upstream::header_overrides(&options.upstream_header_env)?;
        if !installed {
            return Err("Claude Desktop was not found; pass --app PATH".to_string());
        }
        return Ok(success_status());
    }
    if !app.is_file() {
        return Err(format!(
            "Claude Desktop was not found at '{}'; pass --app PATH",
            app.display()
        ));
    }
    if claude_desktop_is_running(&app) {
        return Err(
            "Claude Desktop is already running; quit it before `pentect claude app` so Chromium can apply the private proxy settings"
                .to_string(),
        );
    }

    #[cfg(windows)]
    {
        cleanup_stale_windows_user_ca()?;
        if !options.assume_yes && !confirm_windows_user_ca_install()? {
            return Err(
                "Claude Desktop protection was cancelled; no certificate was installed".to_string(),
            );
        }
    }

    let anthropic = crate::claude_http_proxy::ClaudeHttpProxyGuard::start_with_header_env(
        options
            .upstream
            .clone()
            .unwrap_or_else(|| "https://api.anthropic.com".to_string()),
        &options.upstream_header_env,
    )?;
    let proxy = ClaudeAppProxyGuard::start()?;
    #[cfg(windows)]
    let _trusted_ca =
        WindowsUserCaGuard::install(proxy.root_certificate_der(), proxy.ca_thumbprint())?;
    let user_data_dir = claude_user_data_dir()?;
    #[cfg(windows)]
    if let Some(package) = find_windows_claude_package()
        .filter(|package| paths_equal_case_insensitive(&package.executable, &app))
    {
        let arguments = claude_chromium_arguments(&proxy, &user_data_dir);
        let environment =
            ScopedPackageEnvironment::install(anthropic.base_url(), &options.upstream_header_env);
        let process = activate_windows_package(&package.aumid, &arguments)?;
        drop(environment);
        let process_id = process.id();
        let ca_thumbprint = proxy.ca_thumbprint().to_string();
        if let Err(error) = ctrlc::set_handler(move || {
            terminate_child_process(process_id);
            let _ = remove_windows_user_ca(&ca_thumbprint);
            let _ = remove_windows_ca_journal();
            std::process::exit(130);
        }) {
            terminate_child_process(process_id);
            return Err(format!(
                "could not install Claude Desktop shutdown handler: {error}"
            ));
        }
        thread::sleep(APP_STARTUP_GRACE);
        if let Some(status) = process.try_wait()? {
            return Err(claude_desktop_early_exit_error(status, true));
        }
        print_gateway_ready(&proxy);
        let status = process.wait()?;
        drop(proxy);
        drop(anthropic);
        return Ok(status);
    }

    let mut command = Command::new(&app);
    crate::upstream::hide_header_source_env(&mut command, &options.upstream_header_env);
    command
        .args(claude_chromium_arguments(&proxy, &user_data_dir))
        .env("ANTHROPIC_BASE_URL", anthropic.base_url())
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    configure_child_process(&mut command);
    let mut child = command
        .spawn()
        .map_err(|error| format!("could not start Claude Desktop: {error}"))?;
    let child_id = child.id();
    #[cfg(windows)]
    let ca_thumbprint = proxy.ca_thumbprint().to_string();
    if let Err(error) = ctrlc::set_handler(move || {
        terminate_child_process(child_id);
        #[cfg(windows)]
        {
            let _ = remove_windows_user_ca(&ca_thumbprint);
            let _ = remove_windows_ca_journal();
        }
        std::process::exit(130);
    }) {
        terminate_child_process(child_id);
        let _ = child.wait();
        return Err(format!(
            "could not install Claude Desktop shutdown handler: {error}"
        ));
    }
    thread::sleep(APP_STARTUP_GRACE);
    if let Some(status) = child
        .try_wait()
        .map_err(|error| format!("could not inspect Claude Desktop startup: {error}"))?
    {
        return Err(claude_desktop_early_exit_error(status, false));
    }
    print_gateway_ready(&proxy);
    let status = child
        .wait()
        .map_err(|error| format!("could not wait for Claude Desktop: {error}"))?;
    drop(proxy);
    drop(anthropic);
    Ok(status)
}

fn claude_desktop_early_exit_error(status: impl std::fmt::Display, packaged: bool) -> String {
    let installation = if packaged { " package" } else { "" };
    format!(
        "Claude Desktop{installation} exited before Pentect could attach protection ({status}); the temporary current-user certificate will be removed"
    )
}

fn claude_chromium_arguments(proxy: &ClaudeAppProxyGuard, user_data_dir: &Path) -> Vec<String> {
    let arguments = vec![
        format!("--proxy-server={}", proxy.proxy_url()),
        format!("--user-data-dir={}", user_data_dir.display()),
    ];
    #[cfg(not(windows))]
    {
        arguments
            .into_iter()
            .chain(std::iter::once(format!(
                "--ignore-certificate-errors-spki-list={}",
                proxy.spki_hash()
            )))
            .collect()
    }
    #[cfg(windows)]
    {
        arguments
    }
}

fn print_gateway_ready(proxy: &ClaudeAppProxyGuard) {
    eprintln!(
        "[pentect] Claude App gateway ready at {}",
        proxy.proxy_url()
    );
    eprintln!(
        "[pentect] Supported Claude Desktop Chat and attachment traffic is protected; bodies are not logged"
    );
}

#[cfg(windows)]
fn confirm_windows_user_ca_install() -> Result<bool, String> {
    if !std::io::stdin().is_terminal() {
        return Err(
            "input is not interactive; rerun `pentect claude app --yes` to approve the temporary current-user certificate"
                .to_string(),
        );
    }
    println!(
        "Pentect needs to temporarily trust a session-specific certificate for this Windows user so Claude Desktop traffic can be protected."
    );
    println!(
        "The private key stays in this Pentect process. The public certificate is removed when Claude Desktop exits."
    );
    print!("Continue? [y/N] ");
    std::io::stdout()
        .flush()
        .map_err(|error| format!("could not show Claude Desktop certificate prompt: {error}"))?;
    let mut answer = String::new();
    std::io::stdin()
        .read_line(&mut answer)
        .map_err(|error| format!("could not read Claude Desktop certificate prompt: {error}"))?;
    Ok(matches!(
        answer.trim().to_ascii_lowercase().as_str(),
        "y" | "yes"
    ))
}

#[cfg(windows)]
fn windows_ca_journal_path() -> Result<PathBuf, String> {
    let root = std::env::var_os("LOCALAPPDATA")
        .map(PathBuf::from)
        .ok_or_else(|| "LOCALAPPDATA is unavailable for Claude Desktop CA cleanup".to_string())?;
    // The journal lives in its own directory. `write_windows_ca_journal`
    // restricts the containing directory to the current user, so it must never
    // be the shared install root: that would strip the inheritable
    // SYSTEM/Administrators entries from `bin`, `plugins`, and `runtime`.
    Ok(root
        .join("Pentect")
        .join("claude-app-ca")
        .join("claude-app-temporary-ca.sha1"))
}

#[cfg(windows)]
fn write_windows_ca_journal(thumbprint: &str) -> Result<(), String> {
    let path = windows_ca_journal_path()?;
    let parent = path
        .parent()
        .ok_or_else(|| "Claude Desktop CA cleanup path has no parent".to_string())?;
    std::fs::create_dir_all(parent).map_err(|error| {
        format!("could not create Claude Desktop CA cleanup directory: {error}")
    })?;
    crate::secure_temp::restrict_to_current_user(parent)?;
    let journal = format!("{thumbprint}\n{}\n", std::process::id());
    std::fs::write(&path, journal)
        .map_err(|error| format!("could not write Claude Desktop CA cleanup journal: {error}"))?;
    crate::secure_temp::restrict_to_current_user(&path)
}

#[cfg(windows)]
fn remove_windows_ca_journal() -> Result<(), String> {
    remove_windows_ca_journal_at(&windows_ca_journal_path()?)
}

#[cfg(windows)]
fn remove_windows_ca_journal_at(path: &std::path::Path) -> Result<(), String> {
    match std::fs::remove_file(path) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => {
            return Err(format!(
                "could not remove Claude Desktop CA cleanup journal: {error}"
            ))
        }
    }
    Ok(())
}

#[cfg(windows)]
fn validate_ca_thumbprint(thumbprint: &str) -> Result<(), String> {
    if thumbprint.len() != 40 || !thumbprint.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err("Claude Desktop CA cleanup journal is invalid".to_string());
    }
    Ok(())
}

#[cfg(windows)]
struct WindowsCaJournal {
    thumbprint: String,
    owner: Option<u32>,
}

#[cfg(windows)]
fn parse_windows_ca_journal(content: &str) -> Result<WindowsCaJournal, String> {
    let mut lines = content.lines();
    let thumbprint = lines
        .next()
        .ok_or_else(|| "Claude Desktop CA cleanup journal is invalid".to_string())?;
    validate_ca_thumbprint(thumbprint)?;
    let owner = lines
        .next()
        .map(|value| {
            value
                .parse::<u32>()
                .ok()
                .filter(|owner| *owner != 0)
                .ok_or_else(|| "Claude Desktop CA cleanup journal is invalid".to_string())
        })
        .transpose()?;
    if lines.next().is_some() {
        return Err("Claude Desktop CA cleanup journal is invalid".to_string());
    }
    Ok(WindowsCaJournal {
        thumbprint: thumbprint.to_string(),
        owner,
    })
}

#[cfg(windows)]
fn windows_ca_owner_is_running(owner: Option<u32>) -> bool {
    let Some(owner) = owner else {
        return false;
    };
    let pid = sysinfo::Pid::from_u32(owner);
    let mut system = sysinfo::System::new();
    system.refresh_processes_specifics(
        sysinfo::ProcessesToUpdate::Some(&[pid]),
        true,
        sysinfo::ProcessRefreshKind::nothing(),
    );
    system.process(pid).is_some()
}

// Releases before the journal moved into its own directory wrote it directly
// into the install root. Read that location too so a certificate left behind by
// an older build is still cleaned up after an upgrade.
#[cfg(windows)]
fn legacy_windows_ca_journal_path() -> Result<PathBuf, String> {
    let root = std::env::var_os("LOCALAPPDATA")
        .map(PathBuf::from)
        .ok_or_else(|| "LOCALAPPDATA is unavailable for Claude Desktop CA cleanup".to_string())?;
    Ok(root.join("Pentect").join("claude-app-temporary-ca.sha1"))
}

#[cfg(windows)]
fn read_windows_ca_journals() -> Result<Vec<(PathBuf, WindowsCaJournal)>, String> {
    let mut journals = Vec::new();
    for path in [
        windows_ca_journal_path()?,
        legacy_windows_ca_journal_path()?,
    ] {
        match std::fs::read_to_string(&path) {
            Ok(content) => journals.push((path, parse_windows_ca_journal(&content)?)),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
            Err(error) => {
                return Err(format!(
                    "could not read Claude Desktop CA cleanup journal: {error}"
                ))
            }
        }
    }
    Ok(journals)
}

#[cfg(windows)]
fn open_windows_user_root_store(
) -> Result<windows::Win32::Security::Cryptography::HCERTSTORE, String> {
    use windows::Win32::Security::Cryptography::{
        CertOpenStore, CERT_OPEN_STORE_FLAGS, CERT_STORE_MAXIMUM_ALLOWED_FLAG,
        CERT_STORE_OPEN_EXISTING_FLAG, CERT_STORE_PROV_SYSTEM_REGISTRY_W,
        CERT_SYSTEM_STORE_CURRENT_USER, X509_ASN_ENCODING,
    };

    #[cfg(test)]
    let test_store = std::env::var_os("PENTECT_TEST_WINDOWS_CA_STORE")
        .map(|name| windows::core::HSTRING::from(name.to_string_lossy().as_ref()));
    #[cfg(not(test))]
    let test_store: Option<windows::core::HSTRING> = None;
    let store_name = test_store
        .as_ref()
        .cloned()
        .unwrap_or_else(|| windows::core::HSTRING::from("ROOT"));
    let mut raw_flags = CERT_SYSTEM_STORE_CURRENT_USER | CERT_STORE_MAXIMUM_ALLOWED_FLAG.0;
    if test_store.is_none() {
        raw_flags |= CERT_STORE_OPEN_EXISTING_FLAG.0;
    }
    let flags = CERT_OPEN_STORE_FLAGS(raw_flags);
    unsafe {
        CertOpenStore(
            CERT_STORE_PROV_SYSTEM_REGISTRY_W,
            X509_ASN_ENCODING,
            None,
            flags,
            Some(store_name.as_ptr() as *const std::ffi::c_void),
        )
    }
    .map_err(|error| format!("could not open the current-user Root store: {error}"))
}

#[cfg(windows)]
fn find_windows_user_ca(thumbprint: &str) -> Result<bool, String> {
    use windows::Win32::Security::Cryptography::{
        CertCloseStore, CertFindCertificateInStore, CERT_FIND_SHA1_HASH, CRYPT_INTEGER_BLOB,
        X509_ASN_ENCODING,
    };

    validate_ca_thumbprint(thumbprint)?;
    let mut hash = data_encoding::HEXUPPER
        .decode(thumbprint.as_bytes())
        .map_err(|_| "Claude Desktop CA cleanup journal is invalid".to_string())?;
    let blob = CRYPT_INTEGER_BLOB {
        cbData: hash.len() as u32,
        pbData: hash.as_mut_ptr(),
    };
    let store = open_windows_user_root_store()?;
    let context = unsafe {
        CertFindCertificateInStore(
            store,
            X509_ASN_ENCODING,
            0,
            CERT_FIND_SHA1_HASH,
            Some(&blob as *const _ as *const std::ffi::c_void),
            None,
        )
    };
    let found = !context.is_null();
    if found {
        let _ = unsafe {
            windows::Win32::Security::Cryptography::CertFreeCertificateContext(Some(context))
        };
    }
    let close = unsafe { CertCloseStore(Some(store), 0) };
    close.map_err(|error| format!("could not close the current-user Root store: {error}"))?;
    Ok(found)
}

#[cfg(windows)]
fn remove_windows_user_ca(thumbprint: &str) -> Result<(), String> {
    use windows::Win32::Security::Cryptography::{
        CertCloseStore, CertDeleteCertificateFromStore, CertFindCertificateInStore,
        CERT_FIND_SHA1_HASH, CRYPT_INTEGER_BLOB, X509_ASN_ENCODING,
    };

    validate_ca_thumbprint(thumbprint)?;
    let mut hash = data_encoding::HEXUPPER
        .decode(thumbprint.as_bytes())
        .map_err(|_| "Claude Desktop CA cleanup journal is invalid".to_string())?;
    let blob = CRYPT_INTEGER_BLOB {
        cbData: hash.len() as u32,
        pbData: hash.as_mut_ptr(),
    };
    let store = open_windows_user_root_store()?;
    let context = unsafe {
        CertFindCertificateInStore(
            store,
            X509_ASN_ENCODING,
            0,
            CERT_FIND_SHA1_HASH,
            Some(&blob as *const _ as *const std::ffi::c_void),
            None,
        )
    };
    if context.is_null() {
        unsafe { CertCloseStore(Some(store), 0) }
            .map_err(|error| format!("could not close the current-user Root store: {error}"))?;
        return Ok(());
    }
    let deleted = unsafe { CertDeleteCertificateFromStore(context) };
    let closed = unsafe { CertCloseStore(Some(store), 0) };
    deleted.map_err(|error| {
        format!("could not remove temporary Claude Desktop certificate: {error}")
    })?;
    closed.map_err(|error| format!("could not close the current-user Root store: {error}"))
}

#[cfg(windows)]
fn windows_user_ca_present(thumbprint: &str) -> Result<bool, String> {
    find_windows_user_ca(thumbprint)
}

#[cfg(windows)]
pub(crate) fn windows_ca_cleanup_pending() -> Result<bool, String> {
    Ok(read_windows_ca_journals()?
        .iter()
        .any(|(_, journal)| !windows_ca_owner_is_running(journal.owner)))
}

#[cfg(windows)]
pub(crate) fn cleanup_stale_windows_user_ca() -> Result<(), String> {
    let journals = read_windows_ca_journals()?;
    let mut removed = 0usize;
    for (path, journal) in journals {
        if windows_ca_owner_is_running(journal.owner) {
            continue;
        }
        remove_windows_user_ca(&journal.thumbprint)?;
        remove_windows_ca_journal_at(&path)?;
        removed += 1;
    }
    if removed > 0 {
        eprintln!("[pentect] Removed {removed} stale temporary Claude Desktop certificate(s)");
    }
    Ok(())
}

#[cfg(windows)]
struct WindowsUserCaGuard {
    thumbprint: String,
}

#[cfg(windows)]
impl WindowsUserCaGuard {
    fn install(certificate_der: &[u8], thumbprint: &str) -> Result<Self, String> {
        use windows::Win32::Security::Cryptography::{
            CertAddEncodedCertificateToStore, CertCloseStore, CERT_STORE_ADD_NEW, X509_ASN_ENCODING,
        };

        validate_ca_thumbprint(thumbprint)?;
        if windows_user_ca_present(thumbprint)? {
            return Err(
                "temporary Claude Desktop certificate already exists in CurrentUser Root"
                    .to_string(),
            );
        }
        #[cfg(test)]
        eprintln!("windows CA install: writing cleanup journal");
        write_windows_ca_journal(thumbprint)?;
        #[cfg(test)]
        eprintln!("windows CA install: opening current-user certificate store");
        let store = match open_windows_user_root_store() {
            Ok(store) => store,
            Err(error) => {
                let _ = remove_windows_ca_journal();
                return Err(error);
            }
        };
        #[cfg(test)]
        eprintln!("windows CA install: adding certificate through system store provider");
        let add = unsafe {
            CertAddEncodedCertificateToStore(
                Some(store),
                X509_ASN_ENCODING,
                certificate_der,
                CERT_STORE_ADD_NEW,
                None,
            )
        };
        let close_store = unsafe { CertCloseStore(Some(store), 0) };
        if let Err(error) = add {
            let _ = remove_windows_ca_journal();
            return Err(format!(
                "could not trust temporary Claude Desktop certificate: {error}"
            ));
        }
        close_store
            .map_err(|error| format!("could not close the Root certificate provider: {error}"))?;
        #[cfg(test)]
        eprintln!("windows CA install: certificate store update finished");
        Ok(Self {
            thumbprint: thumbprint.to_string(),
        })
    }
}

#[cfg(windows)]
impl Drop for WindowsUserCaGuard {
    fn drop(&mut self) {
        if let Err(error) = remove_windows_user_ca(&self.thumbprint) {
            eprintln!("[pentect] {error}");
            return;
        }
        if let Err(error) = remove_windows_ca_journal() {
            eprintln!("[pentect] {error}");
        }
        self.thumbprint.zeroize();
    }
}

#[cfg(windows)]
struct ScopedPackageEnvironment {
    previous: Vec<(String, Option<std::ffi::OsString>)>,
}

#[cfg(windows)]
impl ScopedPackageEnvironment {
    fn install(anthropic_base_url: &str, hidden: &[String]) -> Self {
        let mut changes = vec![(
            "ANTHROPIC_BASE_URL".to_string(),
            Some(std::ffi::OsString::from(anthropic_base_url)),
        )];
        changes.extend(hidden.iter().filter_map(|spec| {
            crate::upstream::header_source_env_name(spec).map(|name| (name.to_string(), None))
        }));
        let mut previous = Vec::with_capacity(changes.len());
        for (name, value) in changes {
            previous.push((name.clone(), std::env::var_os(&name)));
            match value {
                Some(value) => std::env::set_var(name, value),
                None => std::env::remove_var(name),
            }
        }
        Self { previous }
    }
}

#[cfg(windows)]
impl Drop for ScopedPackageEnvironment {
    fn drop(&mut self) {
        for (name, value) in self.previous.drain(..).rev() {
            match value {
                Some(value) => std::env::set_var(name, value),
                None => std::env::remove_var(name),
            }
        }
    }
}

#[cfg(windows)]
struct ActivatedWindowsProcess {
    id: u32,
    handle: windows_sys::Win32::Foundation::HANDLE,
}

#[cfg(windows)]
impl ActivatedWindowsProcess {
    fn id(&self) -> u32 {
        self.id
    }

    fn try_wait(&self) -> Result<Option<std::process::ExitStatus>, String> {
        use std::os::windows::process::ExitStatusExt;
        use windows_sys::Win32::Foundation::{WAIT_OBJECT_0, WAIT_TIMEOUT};
        use windows_sys::Win32::System::Threading::{GetExitCodeProcess, WaitForSingleObject};
        let result = unsafe { WaitForSingleObject(self.handle, 0) };
        if result == WAIT_TIMEOUT {
            return Ok(None);
        }
        if result != WAIT_OBJECT_0 {
            return Err("could not observe activated Claude Desktop process".to_string());
        }
        let mut code = 0u32;
        if unsafe { GetExitCodeProcess(self.handle, &mut code) } == 0 {
            return Err("could not read Claude Desktop exit status".to_string());
        }
        Ok(Some(std::process::ExitStatus::from_raw(code)))
    }

    fn wait(&self) -> Result<std::process::ExitStatus, String> {
        use windows_sys::Win32::Foundation::WAIT_OBJECT_0;
        use windows_sys::Win32::System::Threading::{WaitForSingleObject, INFINITE};
        if unsafe { WaitForSingleObject(self.handle, INFINITE) } != WAIT_OBJECT_0 {
            return Err("could not wait for activated Claude Desktop process".to_string());
        }
        self.try_wait()?.ok_or_else(|| {
            "Claude Desktop process remained active after its wait completed".to_string()
        })
    }
}

#[cfg(windows)]
impl Drop for ActivatedWindowsProcess {
    fn drop(&mut self) {
        unsafe {
            windows_sys::Win32::Foundation::CloseHandle(self.handle);
        }
    }
}

#[cfg(windows)]
fn activate_windows_package(
    aumid: &str,
    arguments: &[String],
) -> Result<ActivatedWindowsProcess, String> {
    use windows::core::PCWSTR;
    use windows::Win32::System::Com::{
        CoCreateInstance, CoInitializeEx, CoUninitialize, CLSCTX_LOCAL_SERVER,
        COINIT_APARTMENTTHREADED,
    };
    use windows::Win32::UI::Shell::{
        ApplicationActivationManager, IApplicationActivationManager, AO_NONE,
    };
    use windows_sys::Win32::System::Threading::{OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION};
    const SYNCHRONIZE_ACCESS: u32 = 0x0010_0000;

    let initialized = unsafe { CoInitializeEx(None, COINIT_APARTMENTTHREADED) };
    initialized
        .ok()
        .map_err(|error| format!("could not initialize Windows app activation: {error}"))?;
    let result = (|| {
        let manager: IApplicationActivationManager = unsafe {
            CoCreateInstance(
                &ApplicationActivationManager,
                None::<&windows::core::IUnknown>,
                CLSCTX_LOCAL_SERVER,
            )
        }
        .map_err(|error| format!("could not create Windows app activation manager: {error}"))?;
        let aumid = wide_null(aumid);
        let command_line = arguments
            .iter()
            .map(|argument| quote_windows_argument(argument))
            .collect::<Vec<_>>()
            .join(" ");
        let command_line = wide_null(&command_line);
        let id = unsafe {
            manager.ActivateApplication(
                PCWSTR(aumid.as_ptr()),
                PCWSTR(command_line.as_ptr()),
                AO_NONE,
            )
        }
        .map_err(|error| format!("could not activate Claude Desktop package: {error}"))?;
        let handle = unsafe {
            OpenProcess(
                PROCESS_QUERY_LIMITED_INFORMATION | SYNCHRONIZE_ACCESS,
                0,
                id,
            )
        };
        if handle.is_null() {
            return Err(
                "Claude Desktop activated but its process could not be observed".to_string(),
            );
        }
        Ok(ActivatedWindowsProcess { id, handle })
    })();
    unsafe { CoUninitialize() };
    result
}

#[cfg(windows)]
fn wide_null(value: &str) -> Vec<u16> {
    use std::os::windows::ffi::OsStrExt;
    std::ffi::OsStr::new(value)
        .encode_wide()
        .chain(std::iter::once(0))
        .collect()
}

#[cfg(any(windows, test))]
fn quote_windows_argument(value: &str) -> String {
    if !value.is_empty()
        && !value
            .chars()
            .any(|ch| ch.is_ascii_whitespace() || ch == '"')
    {
        return value.to_string();
    }
    let mut quoted = String::with_capacity(value.len() + 2);
    quoted.push('"');
    let mut backslashes = 0usize;
    for ch in value.chars() {
        if ch == '\\' {
            backslashes += 1;
            continue;
        }
        if ch == '"' {
            quoted.extend(std::iter::repeat_n('\\', backslashes * 2 + 1));
        } else {
            quoted.extend(std::iter::repeat_n('\\', backslashes));
        }
        backslashes = 0;
        quoted.push(ch);
    }
    quoted.extend(std::iter::repeat_n('\\', backslashes * 2));
    quoted.push('"');
    quoted
}

#[cfg(windows)]
fn configure_child_process(_command: &mut Command) {}

#[cfg(unix)]
fn configure_child_process(command: &mut Command) {
    use std::os::unix::process::CommandExt;
    command.process_group(0);
}

#[cfg(windows)]
fn terminate_child_process(pid: u32) {
    let _ = Command::new(crate::windows_system_executable("taskkill.exe"))
        .args(["/PID", &pid.to_string(), "/T", "/F"])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status();
}

#[cfg(unix)]
fn terminate_child_process(pid: u32) {
    unsafe {
        libc::kill(-(pid as i32), libc::SIGTERM);
    }
}

#[derive(Debug)]
struct ClaudeAppOptions {
    app: Option<PathBuf>,
    upstream: Option<String>,
    upstream_header_env: Vec<String>,
    check: bool,
    assume_yes: bool,
}

impl ClaudeAppOptions {
    fn parse(args: &[String]) -> Result<Self, String> {
        let mut app = None;
        let mut upstream = None;
        let mut upstream_header_env = Vec::new();
        let mut check = false;
        let mut assume_yes = false;
        let mut index = if args.get(1).is_some_and(|arg| arg == "claude")
            && args.get(2).is_some_and(|arg| arg == "app")
        {
            3
        } else {
            2
        };
        while index < args.len() {
            let argument = args[index].as_str();
            if let Some(value) = crate::assigned_option_value(argument, "--app")? {
                app = Some(PathBuf::from(value));
                index += 1;
                continue;
            }
            if let Some(value) = crate::assigned_option_value(argument, "--upstream")? {
                upstream = Some(value);
                index += 1;
                continue;
            }
            if let Some(value) = crate::assigned_option_value(argument, "--upstream-header-env")? {
                upstream_header_env.push(value);
                index += 1;
                continue;
            }
            if let Some(value) = crate::assigned_option_value(argument, "--plugins")? {
                crate::plugins::parse_plugin_value(&value).map_err(|error| error.to_string())?;
                index += 1;
                continue;
            }
            match args[index].as_str() {
                "--app" => {
                    let value = args
                        .get(index + 1)
                        .ok_or_else(|| "--app requires a value".to_string())?;
                    app = Some(PathBuf::from(value));
                    index += 2;
                }
                "--check" | "--dry-run" => {
                    check = true;
                    index += 1;
                }
                "--yes" => {
                    assume_yes = true;
                    index += 1;
                }
                "--upstream" => {
                    let value = args
                        .get(index + 1)
                        .ok_or_else(|| "--upstream requires a value".to_string())?;
                    upstream = Some(value.clone());
                    index += 2;
                }
                "--upstream-header-env" => {
                    let value = args
                        .get(index + 1)
                        .ok_or_else(|| "--upstream-header-env requires a value".to_string())?;
                    upstream_header_env.push(value.clone());
                    index += 2;
                }
                "--plugins" => {
                    if args
                        .get(index + 1)
                        .is_none_or(|value| value.starts_with("--"))
                    {
                        return Err("--plugins requires a value".to_string());
                    }
                    index += 2;
                }
                value => return Err(format!("unknown `pentect claude app` option: {value}")),
            }
        }
        Ok(Self {
            app,
            upstream,
            upstream_header_env,
            check,
            assume_yes,
        })
    }
}

struct ClaudeAppProxyGuard {
    proxy_url: String,
    #[cfg(not(windows))]
    spki_hash: String,
    #[cfg(windows)]
    root_certificate_der: Vec<u8>,
    #[cfg(windows)]
    ca_thumbprint: String,
    shutdown: Option<oneshot::Sender<()>>,
    thread: Option<thread::JoinHandle<()>>,
}

impl ClaudeAppProxyGuard {
    fn start() -> Result<Self, String> {
        let authority = CertificateAuthority::new()?;
        #[cfg(not(windows))]
        let spki_hash = authority.spki_hash.clone();
        #[cfg(windows)]
        let root_certificate_der = authority.issuer.der().to_vec();
        #[cfg(windows)]
        let ca_thumbprint = authority.thumbprint.clone();
        let (ready_tx, ready_rx) = mpsc::channel();
        let (shutdown_tx, shutdown_rx) = oneshot::channel();
        let thread = thread::spawn(move || {
            let runtime = match tokio::runtime::Builder::new_multi_thread()
                .worker_threads(2)
                .enable_all()
                .build()
            {
                Ok(runtime) => runtime,
                Err(error) => {
                    let _ = ready_tx.send(Err(format!(
                        "could not start Claude App proxy runtime: {error}"
                    )));
                    return;
                }
            };
            runtime.block_on(async move {
                if let Err(error) = run_proxy(authority, ready_tx, shutdown_rx).await {
                    eprintln!("[pentect] Claude App proxy stopped: {error}");
                }
            });
        });
        let proxy_url = ready_rx
            .recv_timeout(crate::GATEWAY_STARTUP_TIMEOUT)
            .map_err(|_| "Claude App proxy did not start within 30 seconds".to_string())??;
        Ok(Self {
            proxy_url,
            #[cfg(not(windows))]
            spki_hash,
            #[cfg(windows)]
            root_certificate_der,
            #[cfg(windows)]
            ca_thumbprint,
            shutdown: Some(shutdown_tx),
            thread: Some(thread),
        })
    }

    fn proxy_url(&self) -> &str {
        &self.proxy_url
    }

    #[cfg(not(windows))]
    fn spki_hash(&self) -> &str {
        &self.spki_hash
    }

    #[cfg(windows)]
    fn root_certificate_der(&self) -> &[u8] {
        &self.root_certificate_der
    }

    #[cfg(windows)]
    fn ca_thumbprint(&self) -> &str {
        &self.ca_thumbprint
    }
}

impl Drop for ClaudeAppProxyGuard {
    fn drop(&mut self) {
        if let Some(shutdown) = self.shutdown.take() {
            let _ = shutdown.send(());
        }
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
        self.proxy_url.zeroize();
        #[cfg(not(windows))]
        self.spki_hash.zeroize();
        #[cfg(windows)]
        {
            self.root_certificate_der.zeroize();
            self.ca_thumbprint.zeroize();
        }
    }
}

struct CertificateAuthority {
    issuer: CertifiedIssuer<'static, KeyPair>,
    #[cfg(not(windows))]
    spki_hash: String,
    #[cfg(windows)]
    thumbprint: String,
}

impl CertificateAuthority {
    fn new() -> Result<Self, String> {
        let key = KeyPair::generate()
            .map_err(|error| format!("could not generate Claude App proxy CA key: {error}"))?;
        #[cfg(not(windows))]
        let spki_hash =
            data_encoding::BASE64.encode(&Sha256::digest(key.subject_public_key_info()));
        let mut params = CertificateParams::new(Vec::<String>::new())
            .map_err(|error| format!("could not create Claude App proxy CA: {error}"))?;
        let mut distinguished_name = DistinguishedName::new();
        distinguished_name.push(DnType::CommonName, "Pentect ephemeral Claude App proxy");
        params.distinguished_name = distinguished_name;
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        params.key_usages = vec![
            KeyUsagePurpose::KeyCertSign,
            KeyUsagePurpose::DigitalSignature,
        ];
        let issuer = CertifiedIssuer::self_signed(params, key)
            .map_err(|error| format!("could not sign Claude App proxy CA: {error}"))?;
        #[cfg(windows)]
        let thumbprint = data_encoding::HEXUPPER.encode(&Sha1::digest(issuer.der()));
        Ok(Self {
            issuer,
            #[cfg(not(windows))]
            spki_hash,
            #[cfg(windows)]
            thumbprint,
        })
    }

    fn server_config(&self, host: &str) -> Result<Arc<ServerConfig>, String> {
        let key = KeyPair::generate()
            .map_err(|error| format!("could not generate certificate for {host}: {error}"))?;
        let mut params = CertificateParams::new(vec![host.to_string()])
            .map_err(|error| format!("could not create certificate for {host}: {error}"))?;
        let mut distinguished_name = DistinguishedName::new();
        distinguished_name.push(DnType::CommonName, host);
        params.distinguished_name = distinguished_name;
        params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        let certificate = params
            .signed_by(&key, &self.issuer)
            .map_err(|error| format!("could not sign certificate for {host}: {error}"))?;
        let private_key = PrivatePkcs8KeyDer::from(key.serialize_der());
        let mut config = ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(
                vec![
                    CertificateDer::from(certificate.der().to_vec()),
                    self.issuer.der().clone(),
                ],
                private_key.into(),
            )
            .map_err(|error| format!("could not configure TLS for {host}: {error}"))?;
        config.alpn_protocols = vec![b"http/1.1".to_vec()];
        Ok(Arc::new(config))
    }
}

struct ProxyState {
    authority: CertificateAuthority,
    server_configs: Mutex<HashMap<String, Arc<ServerConfig>>>,
    client: reqwest::Client,
    masker: Arc<Mutex<pentect_agent::ActiveToolOutputMasker>>,
    plugins: Arc<Mutex<pentect_agent::PluginMiddleware>>,
    block_unknown_formats: bool,
    restore_output: bool,
    files: Mutex<HashMap<String, crate::http_files::Coverage>>,
    file_attestations: crate::http_files::FileAttestationStore,
    pending_files: Mutex<PendingFiles>,
    websocket_connections: Arc<tokio::sync::Semaphore>,
}

#[derive(Default)]
struct PendingFiles {
    entries: HashMap<String, Vec<String>>,
    insertion_order: VecDeque<String>,
}

impl ProxyState {
    fn server_config(&self, host: &str) -> Result<Arc<ServerConfig>, String> {
        let mut configs = self
            .server_configs
            .lock()
            .map_err(|_| "Claude App certificate cache is unavailable".to_string())?;
        if let Some(config) = configs.get(host) {
            return Ok(Arc::clone(config));
        }
        let config = self.authority.server_config(host)?;
        if configs.len() >= MAX_CERTIFICATE_CACHE_ENTRIES {
            if let Some(expired) = configs.keys().next().cloned() {
                configs.remove(&expired);
            }
        }
        configs.insert(host.to_string(), Arc::clone(&config));
        Ok(config)
    }
}

async fn run_proxy(
    authority: CertificateAuthority,
    ready_tx: mpsc::Sender<Result<String, String>>,
    mut shutdown_rx: oneshot::Receiver<()>,
) -> Result<(), String> {
    let listener = TcpListener::bind(("127.0.0.1", 0))
        .await
        .map_err(|error| format!("could not bind Claude App proxy: {error}"))?;
    let address = listener
        .local_addr()
        .map_err(|error| format!("could not read Claude App proxy address: {error}"))?;
    let client = reqwest::Client::builder()
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .connect_timeout(Duration::from_secs(15))
        .read_timeout(Duration::from_secs(60))
        .pool_idle_timeout(Duration::from_secs(30))
        .tcp_nodelay(true)
        .build()
        .map_err(|error| format!("could not build Claude App upstream client: {error}"))?;
    let plugins = pentect_agent::PluginMiddleware::from_env()?;
    let state = Arc::new(ProxyState {
        authority,
        server_configs: Mutex::new(HashMap::new()),
        client,
        masker: Arc::new(Mutex::new(
            pentect_agent::ActiveToolOutputMasker::new_with_plugins(plugins.clone())?,
        )),
        plugins: Arc::new(Mutex::new(plugins)),
        block_unknown_formats: pentect_agent::unknown_formats_should_block()?,
        restore_output: pentect_agent::output_restore_enabled()?,
        files: Mutex::new(HashMap::new()),
        file_attestations: crate::http_files::FileAttestationStore::open_default()?,
        pending_files: Mutex::new(PendingFiles::default()),
        websocket_connections: Arc::new(tokio::sync::Semaphore::new(MAX_WEBSOCKET_CONNECTIONS)),
    });
    let _ = ready_tx.send(Ok(format!("http://{address}")));

    let connections = Arc::new(tokio::sync::Semaphore::new(MAX_CONNECTIONS));
    loop {
        tokio::select! {
            _ = &mut shutdown_rx => break,
            accepted = listener.accept() => {
                let (stream, _) = accepted
                    .map_err(|error| format!("Claude App proxy accept failed: {error}"))?;
                let Ok(permit) = Arc::clone(&connections).try_acquire_owned() else {
                    continue;
                };
                let state = Arc::clone(&state);
                tokio::spawn(async move {
                    let permit = Arc::new(Mutex::new(Some(permit)));
                    let service = service_fn(move |request| {
                        connect_request(request, Arc::clone(&state), Arc::clone(&permit))
                    });
                    let io = hyper_util::rt::TokioIo::new(stream);
                    if let Err(error) = http1::Builder::new()
                        .max_buf_size(64 * 1024)
                        .max_headers(128)
                        .serve_connection(io, service)
                        .with_upgrades()
                        .await
                    {
                        eprintln!("[pentect] Claude App proxy connection failed: {error}");
                    }
                });
            }
        }
    }
    Ok(())
}

async fn connect_request(
    mut request: Request<Incoming>,
    state: Arc<ProxyState>,
    connection_permit: Arc<Mutex<Option<tokio::sync::OwnedSemaphorePermit>>>,
) -> Result<Response<ProxyBody>, Infallible> {
    if request.method() != Method::CONNECT {
        return Ok(empty_response(StatusCode::METHOD_NOT_ALLOWED));
    }
    let Some(authority) = request.uri().authority().cloned() else {
        return Ok(empty_response(StatusCode::BAD_REQUEST));
    };
    let host = authority.host().to_ascii_lowercase();
    let port = authority.port_u16().unwrap_or(443);
    if port != 443 {
        return Ok(empty_response(StatusCode::FORBIDDEN));
    }
    let Some(permit) = connection_permit
        .lock()
        .ok()
        .and_then(|mut permit| permit.take())
    else {
        return Ok(empty_response(StatusCode::SERVICE_UNAVAILABLE));
    };
    let upgraded = hyper::upgrade::on(&mut request);
    if should_inspect(&host, port) {
        tokio::spawn(async move {
            let _permit = permit;
            let result = async {
                let upgraded = upgraded
                    .await
                    .map_err(|error| format!("CONNECT upgrade failed: {error}"))?;
                let stream = hyper_util::rt::TokioIo::new(upgraded);
                serve_inspected(stream, host, state).await
            }
            .await;
            if let Err(error) = result {
                eprintln!("[pentect] Claude App inspected tunnel failed: {error}");
            }
        });
    } else {
        tokio::spawn(async move {
            let _permit = permit;
            if let Err(error) = passthrough_tunnel(upgraded, &host, port).await {
                eprintln!("[pentect] Claude App network tunnel failed: {error}");
            }
        });
    }
    Ok(empty_response(StatusCode::OK))
}

async fn passthrough_tunnel(
    upgraded: hyper::upgrade::OnUpgrade,
    host: &str,
    port: u16,
) -> Result<(), String> {
    let upgraded = upgraded
        .await
        .map_err(|error| format!("CONNECT upgrade failed: {error}"))?;
    let mut client = hyper_util::rt::TokioIo::new(upgraded);
    let mut upstream = tokio::time::timeout(
        Duration::from_secs(15),
        tokio::net::TcpStream::connect((host, port)),
    )
    .await
    .map_err(|_| "could not reach required app service: connection timed out".to_string())?
    .map_err(|error| format!("could not reach required app service: {error}"))?;
    if let Err(error) = tokio::io::copy_bidirectional(&mut client, &mut upstream).await {
        if !matches!(
            error.kind(),
            io::ErrorKind::ConnectionReset
                | io::ErrorKind::ConnectionAborted
                | io::ErrorKind::BrokenPipe
                | io::ErrorKind::UnexpectedEof
        ) {
            return Err(format!("network tunnel failed: {error}"));
        }
    }
    Ok(())
}

fn should_inspect(host: &str, port: u16) -> bool {
    port == 443 && is_claude_host(host)
}

fn is_claude_host(host: &str) -> bool {
    host == "claude.ai"
        || host.ends_with(".claude.ai")
        || host == "claude.com"
        || host.ends_with(".claude.com")
}

async fn serve_inspected<T>(stream: T, host: String, state: Arc<ProxyState>) -> Result<(), String>
where
    T: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    let config = state.server_config(&host)?;
    let tls = TlsAcceptor::from(config)
        .accept(stream)
        .await
        .map_err(|error| format!("TLS handshake failed for {host}: {error}"))?;
    let service =
        service_fn(move |request| forward_inspected(request, host.clone(), Arc::clone(&state)));
    http1::Builder::new()
        .max_buf_size(64 * 1024)
        .max_headers(128)
        .serve_connection(hyper_util::rt::TokioIo::new(tls), service)
        .with_upgrades()
        .await
        .map_err(|error| format!("inspected HTTP connection failed: {error}"))
}

async fn forward_inspected(
    request: Request<Incoming>,
    host: String,
    state: Arc<ProxyState>,
) -> Result<Response<ProxyBody>, Infallible> {
    match forward_inspected_inner(request, &host, &state).await {
        Ok(response) => Ok(response),
        Err(error) => {
            let category = error.split(':').next().unwrap_or("gateway request failed");
            eprintln!("[pentect] Claude App request failed: {category}");
            Ok(
                if error.starts_with("unknown format blocked:")
                    || error.starts_with("image blocked:")
                    || error.starts_with("document blocked:")
                    || error.starts_with("file upload blocked:")
                    || error.starts_with("Files API upload")
                    || error.starts_with("plugin blocked:")
                {
                    text_response(StatusCode::UNPROCESSABLE_ENTITY, &error)
                } else if error.starts_with("payload too large:") {
                    text_response(StatusCode::PAYLOAD_TOO_LARGE, &error)
                } else {
                    text_response(StatusCode::BAD_GATEWAY, "Pentect Claude App gateway failed")
                },
            )
        }
    }
}

async fn forward_inspected_inner(
    request: Request<Incoming>,
    host: &str,
    state: &ProxyState,
) -> Result<Response<ProxyBody>, String> {
    let method = request.method().clone();
    let path_and_query = request
        .uri()
        .path_and_query()
        .map(|value| value.as_str())
        .unwrap_or("/");
    let path = request.uri().path().to_string();
    let safe_path = metadata_path(&path);
    let content_type = request
        .headers()
        .get(hyper::header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .unwrap_or("-")
        .to_string();
    let request_kind = classify_claude_app_request(&method, host, &path, &content_type);
    let protect_chat = request_kind == ClaudeAppRequest::ChatJson;
    let prepare_upload = request_kind == ClaudeAppRequest::PrepareUploadJson;
    if request_kind == ClaudeAppRequest::UnsupportedModel && state.block_unknown_formats {
        if is_claude_voice_path(&path) {
            return Err(
                "unknown format blocked: Claude App voice uses an opaque WebSocket that Pentect cannot inspect; set compatibility.unknown_formats = \"ignore\" in ~/.pentect/config.toml to pass it through without masking"
                    .to_string(),
            );
        }
        return Err(
            "unknown format blocked: Claude App selected a model transport Pentect cannot inspect; set compatibility.unknown_formats = \"ignore\" in ~/.pentect/config.toml to pass it through"
            .to_string(),
        );
    }
    if is_claude_voice_path(&path) {
        if !is_claude_voice_websocket_request(&method, host, &path, request.headers()) {
            return Err(
                "unknown format blocked: Claude App voice pass-through requires GET wss://claude.ai/api/ws/voice/.../chat_conversations/... with a valid WebSocket upgrade"
                    .to_string(),
            );
        }
        eprintln!(
            "[pentect] claude-app websocket passthrough inspected=no host={host} path={safe_path}"
        );
        let url = format!("https://{host}{path_and_query}");
        return forward_websocket_upgrade(
            request,
            &state.client,
            url,
            host,
            &safe_path,
            Arc::clone(&state.websocket_connections),
        )
        .await;
    }
    eprintln!("[pentect] claude-app > {method} {host}{safe_path} {content_type}");

    let url = format!("https://{host}{path_and_query}");
    let mut headers = request.headers().clone();
    let account_scope = state
        .file_attestations
        .account_scope_for_app_headers(&headers);
    remove_hop_by_hop_headers(&mut headers);
    headers.remove(hyper::header::HOST);
    let mut upload_coverage = None;
    let mut upload_key = None;
    let mut upload_filename = None;
    if protect_chat || prepare_upload || request_kind == ClaudeAppRequest::Upload {
        headers.insert(
            hyper::header::ACCEPT_ENCODING,
            hyper::header::HeaderValue::from_static("identity"),
        );
    }
    let body = if protect_chat {
        let body = read_request_capped(request.into_body(), "Chat").await?;
        let request_streaming = claude_app_request_streaming(&headers, &body);
        hydrate_claude_app_attested_files(&body, &account_scope, state).await?;
        let original = body.clone();
        let masker = Arc::clone(&state.masker);
        let plugins = Arc::clone(&state.plugins);
        let files = {
            let registry = state
                .files
                .lock()
                .map_err(|_| "Claude App file registry lock was poisoned".to_string())?;
            crate::http_files::scoped_file_coverages(&registry, &account_scope)
        };
        let block_unknown_formats = state.block_unknown_formats;
        let protected = tokio::task::spawn_blocking(move || {
            protect_chat_request(&original, &masker, &plugins, &files, block_unknown_formats)
        })
        .await
        .map_err(|_| "Claude App Chat protection task failed".to_string())??;
        if let Some(response) = protected.local_response {
            if request_streaming {
                return Ok(text_response(
                    StatusCode::UNPROCESSABLE_ENTITY,
                    "Plugin local responses are unavailable for streaming Claude App requests",
                ));
            }
            return Response::builder()
                .status(StatusCode::OK)
                .header(hyper::header::CONTENT_TYPE, "application/json")
                .body(
                    Full::new(response)
                        .map_err(|never| match never {})
                        .boxed_unsync(),
                )
                .map_err(|error| format!("could not build Claude App plugin response: {error}"));
        }
        headers.remove(hyper::header::CONTENT_LENGTH);
        reqwest::Body::from(protected.body)
    } else if matches!(
        request_kind,
        ClaudeAppRequest::JsonScan | ClaudeAppRequest::PrepareUploadJson
    ) {
        let body = read_request_capped(request.into_body(), "JSON").await?;
        let masker = Arc::clone(&state.masker);
        let block_unknown_formats = state.block_unknown_formats;
        let protected = tokio::task::spawn_blocking(move || {
            protect_generic_json_request(&body, &masker, block_unknown_formats)
        })
        .await
        .map_err(|_| "Claude App JSON protection task failed".to_string())??;
        headers.remove(hyper::header::CONTENT_LENGTH);
        reqwest::Body::from(protected)
    } else if request_kind == ClaudeAppRequest::Upload {
        let body = read_request_capped(request.into_body(), "upload").await?;
        upload_key = claude_filestore_upload_key(&content_type, &body);
        upload_filename = crate::http_files::multipart_file_name(&content_type, &body);
        let masker = Arc::clone(&state.masker);
        let plugins = Arc::clone(&state.plugins);
        let protected = tokio::task::spawn_blocking(move || {
            let mut masker = masker
                .lock()
                .map_err(|_| "Claude App upload masker lock was poisoned".to_string())?;
            let plugins = plugins
                .lock()
                .map_err(|_| "Claude App plugin lock was poisoned".to_string())?;
            crate::http_files::protect_multipart_upload_with_plugins(
                &content_type,
                &body,
                &mut masker,
                &plugins,
            )
        })
        .await
        .map_err(|_| "Claude App upload protection task failed".to_string())??;
        upload_coverage = Some(protected.coverage);
        headers.remove(hyper::header::CONTENT_LENGTH);
        reqwest::Body::from(protected.body)
    } else {
        let stream = request
            .into_body()
            .into_data_stream()
            .map(|result| result.map_err(io::Error::other));
        reqwest::Body::wrap_stream(stream)
    };
    let upstream = state
        .client
        .request(method.clone(), url)
        .headers(headers)
        .body(body)
        .send()
        .await
        .map_err(|error| {
            format!(
                "upstream request failed for {method} {host}{safe_path}: {}",
                reqwest_error_summary(&error)
            )
        })?;
    let status = upstream.status();
    let mut response_headers = upstream.headers().clone();
    remove_hop_by_hop_headers(&mut response_headers);
    let response_content_type = response_headers
        .get(hyper::header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.split(';').next())
        .unwrap_or("-");
    eprintln!("[pentect] claude-app < {status} {method} {host}{safe_path} {response_content_type}");

    let transform_chat_sse = protect_chat
        && status.is_success()
        && response_content_type.eq_ignore_ascii_case("text/event-stream");
    let transform_chat_json = protect_chat
        && status.is_success()
        && response_content_type.eq_ignore_ascii_case("application/json");
    if (transform_chat_sse || transform_chat_json || upload_coverage.is_some() || prepare_upload)
        && response_headers
            .get(hyper::header::CONTENT_ENCODING)
            .is_some_and(|encoding| {
                !encoding
                    .to_str()
                    .is_ok_and(|value| value.eq_ignore_ascii_case("identity"))
            })
    {
        return Err(
            "Claude App upstream returned compressed protected content despite requesting identity encoding"
                .to_string(),
        );
    }

    let mut builder = Response::builder().status(status);
    for (name, value) in &response_headers {
        if !(transform_chat_sse || transform_chat_json) || name != hyper::header::CONTENT_LENGTH {
            builder = builder.header(name, value);
        }
    }
    if let Some(coverage) = upload_coverage {
        let body = read_response_capped(upstream).await?;
        if status.is_success() {
            let attestation_upstream = "claude-app-service";
            if let Some(filename) = upload_filename.as_deref() {
                for id in uploaded_claude_file_ids(&body, filename) {
                    if state
                        .file_attestations
                        .remember_async(
                            "claude-app",
                            attestation_upstream,
                            &account_scope,
                            &id,
                            coverage,
                        )
                        .await
                        .is_err()
                    {
                        eprintln!("[pentect] file attestation unavailable; uploaded file remains untrusted");
                    } else if let Ok(mut files) = state.files.lock() {
                        crate::http_files::remember_scoped_file_coverage(
                            &mut files,
                            &account_scope,
                            id,
                            coverage,
                        );
                    } else {
                        eprintln!("[pentect] uploaded file registry unavailable; persistent attestation retained");
                    }
                }
            }
            if let Some(key) = upload_key.as_deref() {
                for id in promote_pending_claude_files(key, &account_scope, &state.pending_files)? {
                    if state
                        .file_attestations
                        .remember_async(
                            "claude-app",
                            attestation_upstream,
                            &account_scope,
                            &id,
                            coverage,
                        )
                        .await
                        .is_err()
                    {
                        eprintln!("[pentect] file attestation unavailable; uploaded file remains untrusted");
                    } else if let Ok(mut files) = state.files.lock() {
                        crate::http_files::remember_scoped_file_coverage(
                            &mut files,
                            &account_scope,
                            id,
                            coverage,
                        );
                    } else {
                        eprintln!("[pentect] uploaded file registry unavailable; persistent attestation retained");
                    }
                }
            }
        }
        let mut response = Response::builder().status(status);
        for (name, value) in &response_headers {
            if name != hyper::header::CONTENT_LENGTH {
                response = response.header(name, value);
            }
        }
        return response
            .header("x-pentect-coverage", coverage.as_header())
            .body(
                Full::new(body)
                    .map_err(|never| match never {})
                    .boxed_unsync(),
            )
            .map_err(|error| format!("could not build Claude App upload response: {error}"));
    }
    if prepare_upload {
        let body = read_response_capped(upstream).await?;
        if status.is_success() {
            remember_pending_claude_files(&body, &account_scope, &state.pending_files)?;
        }
        let mut response = Response::builder().status(status);
        for (name, value) in &response_headers {
            if name != hyper::header::CONTENT_LENGTH {
                response = response.header(name, value);
            }
        }
        return response
            .body(
                Full::new(body)
                    .map_err(|never| match never {})
                    .boxed_unsync(),
            )
            .map_err(|error| format!("could not build Claude App prepare response: {error}"));
    }

    if transform_chat_json {
        let body = read_response_capped(upstream).await?;
        let plugins = Arc::clone(&state.plugins);
        let block_unknown_formats = state.block_unknown_formats;
        let restore_output = state.restore_output;
        let body = tokio::task::spawn_blocking(move || {
            rewrite_chat_json_response(&body, &plugins, block_unknown_formats, restore_output)
        })
        .await
        .map_err(|_| "Claude App JSON response protection task failed".to_string())??;
        return builder
            .body(
                Full::new(body)
                    .map_err(|never| match never {})
                    .boxed_unsync(),
            )
            .map_err(|error| format!("could not build Claude App JSON response: {error}"));
    }

    let stream = upstream.bytes_stream().map(move |result| {
        result
            .map(Frame::data)
            .map_err(|error| Box::new(error) as ProxyBodyError)
    });
    let body = if transform_chat_sse {
        chat_sse_body(
            Box::pin(stream),
            Arc::clone(&state.plugins),
            state.restore_output,
        )
    } else {
        BodyExt::boxed_unsync(StreamBody::new(stream))
    };
    builder
        .body(body)
        .map_err(|error| format!("could not build Claude App response: {error}"))
}

fn is_websocket_upgrade(headers: &hyper::HeaderMap) -> bool {
    let upgrade = headers
        .get(hyper::header::UPGRADE)
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| value.eq_ignore_ascii_case("websocket"));
    let connection = headers
        .get(hyper::header::CONNECTION)
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| {
            value
                .split(',')
                .any(|token| token.trim().eq_ignore_ascii_case("upgrade"))
        });
    upgrade && connection
}

fn is_claude_voice_websocket_request(
    method: &Method,
    host: &str,
    path: &str,
    headers: &hyper::HeaderMap,
) -> bool {
    *method == Method::GET
        && host == "claude.ai"
        && is_claude_voice_path(path)
        && is_websocket_upgrade(headers)
}

async fn forward_websocket_upgrade(
    mut request: Request<Incoming>,
    client: &reqwest::Client,
    url: String,
    host: &str,
    safe_path: &str,
    connections: Arc<tokio::sync::Semaphore>,
) -> Result<Response<ProxyBody>, String> {
    let permit = connections
        .try_acquire_owned()
        .map_err(|_| "Claude App WebSocket capacity exhausted".to_string())?;
    let client_upgrade = hyper::upgrade::on(&mut request);
    let mut headers = request.headers().clone();
    headers.remove(hyper::header::PROXY_AUTHORIZATION);
    headers.remove("proxy-connection");

    let upstream = client
        .get(url)
        .version(hyper::Version::HTTP_11)
        .headers(headers)
        .send()
        .await
        .map_err(|error| {
            format!(
                "WebSocket upstream request failed for {host}{safe_path}: {}",
                reqwest_error_summary(&error)
            )
        })?;
    let status = upstream.status();
    let mut response_headers = upstream.headers().clone();
    if status != StatusCode::SWITCHING_PROTOCOLS {
        remove_hop_by_hop_headers(&mut response_headers);
        let mut builder = Response::builder().status(status);
        for (name, value) in &response_headers {
            if name != hyper::header::CONTENT_LENGTH {
                builder = builder.header(name, value);
            }
        }
        let stream = upstream.bytes_stream().map(|result| {
            result
                .map(Frame::data)
                .map_err(|error| Box::new(error) as ProxyBodyError)
        });
        return builder
            .body(BodyExt::boxed_unsync(StreamBody::new(stream)))
            .map_err(|error| format!("could not build Claude App WebSocket response: {error}"));
    }
    if !is_websocket_upgrade(&response_headers) {
        return Err(
            "Claude App voice upstream returned an invalid WebSocket upgrade response".to_string(),
        );
    }

    tokio::spawn(async move {
        let _permit = permit;
        let result = async {
            let client = client_upgrade
                .await
                .map_err(|error| format!("client WebSocket upgrade failed: {error}"))?;
            let mut client = hyper_util::rt::TokioIo::new(client);
            let mut upstream = upstream
                .upgrade()
                .await
                .map_err(|error| format!("upstream WebSocket upgrade failed: {error}"))?;
            tokio::io::copy_bidirectional(&mut client, &mut upstream)
                .await
                .map_err(|error| format!("WebSocket relay failed: {error}"))?;
            Ok::<(), String>(())
        }
        .await;
        if let Err(error) = result {
            eprintln!("[pentect] claude-app websocket passthrough failed: {error}");
        }
    });

    let mut builder = Response::builder().status(status);
    for (name, value) in &response_headers {
        builder = builder.header(name, value);
    }
    builder
        .body(
            Empty::<Bytes>::new()
                .map_err(|never| match never {})
                .boxed_unsync(),
        )
        .map_err(|error| format!("could not build Claude App WebSocket upgrade: {error}"))
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ClaudeAppRequest {
    Other,
    ChatJson,
    PrepareUploadJson,
    JsonScan,
    Upload,
    UnsupportedModel,
}

fn classify_claude_app_request(
    method: &Method,
    host: &str,
    path: &str,
    content_type: &str,
) -> ClaudeAppRequest {
    if !is_claude_host(host) {
        return ClaudeAppRequest::Other;
    }
    if is_claude_voice_path(path) {
        return ClaudeAppRequest::UnsupportedModel;
    }
    let is_post = *method == Method::POST;
    let media_type = content_type
        .split(';')
        .next()
        .map(str::trim)
        .unwrap_or_default();
    if is_post && is_chat_completion_path(path) {
        return if media_type.eq_ignore_ascii_case("application/json") {
            ClaudeAppRequest::ChatJson
        } else {
            ClaudeAppRequest::UnsupportedModel
        };
    }
    if is_post && is_claude_binary_model_path(path) {
        return ClaudeAppRequest::UnsupportedModel;
    }
    if is_post
        && is_claude_prepare_upload_path(path)
        && (media_type.eq_ignore_ascii_case("application/json")
            || media_type.to_ascii_lowercase().ends_with("+json"))
    {
        return ClaudeAppRequest::PrepareUploadJson;
    }
    if is_post
        && media_type.eq_ignore_ascii_case("multipart/form-data")
        && is_claude_upload_path(path)
    {
        return ClaudeAppRequest::Upload;
    }
    if (is_post || *method == Method::PUT || *method == Method::PATCH)
        && (media_type.eq_ignore_ascii_case("application/json")
            || media_type.to_ascii_lowercase().ends_with("+json"))
    {
        return ClaudeAppRequest::JsonScan;
    }
    ClaudeAppRequest::Other
}

#[cfg(test)]
fn is_chat_completion(host: &str, path: &str, content_type: &str) -> bool {
    classify_claude_app_request(&Method::POST, host, path, content_type)
        == ClaudeAppRequest::ChatJson
}

fn is_chat_completion_path(path: &str) -> bool {
    let Some(segment) = path.trim_end_matches('/').rsplit('/').next() else {
        return false;
    };
    let completion = segment.strip_prefix("retry_").unwrap_or(segment);
    completion == "completion"
        || completion.strip_prefix("completion").is_some_and(|suffix| {
            !suffix.is_empty() && suffix.bytes().all(|byte| byte.is_ascii_digit())
        })
}

fn is_claude_binary_model_path(path: &str) -> bool {
    matches!(
        path.rsplit('/').next(),
        Some("appendMessage" | "retryMessage")
    ) && path.starts_with("/v1/mobile/")
}

fn is_claude_voice_path(path: &str) -> bool {
    path.starts_with("/api/ws/voice/") && path.contains("/chat_conversations/")
}

fn is_claude_upload_path(path: &str) -> bool {
    let segments = path
        .split('/')
        .filter(|segment| !segment.is_empty())
        .collect::<Vec<_>>();
    matches!(segments.as_slice(), ["api", _, "upload"])
        || matches!(
            segments.as_slice(),
            ["api", "organizations", _, "projects", _, "upload"]
        )
        || matches!(
            segments.as_slice(),
            ["api", "organizations", _, "cowork", "attachments"]
        )
        || matches!(segments.as_slice(), ["v1", "filestore", "fs", "createFile"])
}

fn is_claude_prepare_upload_path(path: &str) -> bool {
    let segments = path
        .split('/')
        .filter(|segment| !segment.is_empty())
        .collect::<Vec<_>>();
    matches!(
        segments.as_slice(),
        [
            "api",
            "organizations",
            _,
            "conversations",
            _,
            "files",
            "prepare-upload"
        ]
    )
}

fn uploaded_claude_file_ids(body: &[u8], uploaded_filename: &str) -> Vec<String> {
    let Ok(value) = serde_json::from_slice::<serde_json::Value>(body) else {
        return Vec::new();
    };
    uploaded_file_ids(&value, uploaded_filename)
}

async fn hydrate_claude_app_attested_files(
    body: &[u8],
    account_scope: &str,
    state: &ProxyState,
) -> Result<(), String> {
    let attestations = state.file_attestations.clone();
    let body = body.to_vec();
    let scope_for_task = account_scope.to_string();
    let coverages = tokio::task::spawn_blocking(move || {
        attestations.coverages_in_json(&body, "claude-app", "claude-app-service", &scope_for_task)
    })
    .await
    .map_err(|_| "Claude App file attestation task failed".to_string())??;
    for (id, coverage) in coverages {
        let registry = state
            .files
            .lock()
            .map_err(|_| "Claude App file registry lock was poisoned".to_string())?;
        let already_known =
            crate::http_files::scoped_file_coverage(&registry, account_scope, &id).is_some();
        drop(registry);
        if already_known {
            continue;
        }
        let mut files = state
            .files
            .lock()
            .map_err(|_| "Claude App file registry lock was poisoned".to_string())?;
        crate::http_files::remember_scoped_file_coverage(&mut files, account_scope, id, coverage);
    }
    Ok(())
}

fn uploaded_file_ids(value: &serde_json::Value, uploaded_filename: &str) -> Vec<String> {
    let Some(root) = value.as_object() else {
        return Vec::new();
    };
    let mut candidates = Vec::new();
    if file_object_matches_name(root, uploaded_filename) {
        candidates.push(root);
    }
    for key in ["file", "data"] {
        if let Some(object) = root.get(key).and_then(serde_json::Value::as_object) {
            if file_object_matches_name(object, uploaded_filename) {
                candidates.push(object);
            }
        }
    }
    for key in ["files", "uploads"] {
        if let Some(values) = root.get(key).and_then(serde_json::Value::as_array) {
            candidates.extend(
                values
                    .iter()
                    .filter_map(serde_json::Value::as_object)
                    .filter(|object| file_object_matches_name(object, uploaded_filename)),
            );
        }
    }
    candidates
        .into_iter()
        .flat_map(|object| ["file_id", "file_uuid", "id", "uuid"].map(move |key| (object, key)))
        .filter_map(|(object, key)| object.get(key).and_then(serde_json::Value::as_str))
        .filter(|id| !id.is_empty() && id.len() <= 200)
        .map(str::to_string)
        .collect()
}

fn file_object_matches_name(
    object: &serde_json::Map<String, serde_json::Value>,
    uploaded_filename: &str,
) -> bool {
    ["file_name", "filename", "name", "path"]
        .into_iter()
        .filter_map(|key| object.get(key).and_then(serde_json::Value::as_str))
        .any(|candidate| {
            candidate == uploaded_filename
                || Path::new(candidate)
                    .file_name()
                    .and_then(|name| name.to_str())
                    == Some(uploaded_filename)
        })
}

fn claude_filestore_upload_key(content_type: &str, body: &[u8]) -> Option<String> {
    let params = crate::http_files::multipart_text_field(content_type, body, "params")?;
    let value: serde_json::Value = serde_json::from_str(&params).ok()?;
    let filesystem = value.get("filesystem_id")?.as_str()?;
    let path = value.get("path")?.as_str()?;
    if filesystem.is_empty() || path.is_empty() || filesystem.len() > 500 || path.len() > 4096 {
        return None;
    }
    Some(format!("{filesystem}\0{path}"))
}

fn remember_pending_claude_files(
    body: &[u8],
    account_scope: &str,
    pending: &Mutex<PendingFiles>,
) -> Result<(), String> {
    let Ok(value) = serde_json::from_slice::<serde_json::Value>(body) else {
        return Ok(());
    };
    let Some(uploads) = value.get("uploads").and_then(serde_json::Value::as_array) else {
        return Ok(());
    };
    let mut pending = pending
        .lock()
        .map_err(|_| "Claude App pending file registry lock was poisoned".to_string())?;
    for upload in uploads {
        let Some(filesystem) = upload
            .get("filesystem_id")
            .and_then(serde_json::Value::as_str)
        else {
            continue;
        };
        let Some(path) = upload.get("path").and_then(serde_json::Value::as_str) else {
            continue;
        };
        let Some(file_id) = upload
            .get("file_uuid")
            .or_else(|| upload.get("file_id"))
            .and_then(serde_json::Value::as_str)
        else {
            continue;
        };
        if filesystem.is_empty()
            || path.is_empty()
            || file_id.is_empty()
            || filesystem.len() > 500
            || path.len() > 4096
            || file_id.len() > 200
        {
            continue;
        }
        let key = scoped_pending_key(account_scope, &format!("{filesystem}\0{path}"));
        if !pending.entries.contains_key(&key) {
            pending.insertion_order.push_back(key.clone());
        }
        let ids = pending.entries.entry(key).or_default();
        if ids.len() < MAX_IDS_PER_UPLOAD && !ids.iter().any(|known| known == file_id) {
            ids.push(file_id.to_string());
        }
        while pending.entries.len() > MAX_PENDING_UPLOADS {
            let Some(expired) = pending.insertion_order.pop_front() else {
                break;
            };
            pending.entries.remove(&expired);
        }
    }
    Ok(())
}

fn promote_pending_claude_files(
    key: &str,
    account_scope: &str,
    pending: &Mutex<PendingFiles>,
) -> Result<Vec<String>, String> {
    let key = scoped_pending_key(account_scope, key);
    let ids = {
        let mut pending = pending
            .lock()
            .map_err(|_| "Claude App pending file registry lock was poisoned".to_string())?;
        pending.insertion_order.retain(|known| known != &key);
        pending.entries.remove(&key).unwrap_or_default()
    };
    Ok(ids)
}

fn scoped_pending_key(account_scope: &str, key: &str) -> String {
    format!("{account_scope}:{key}")
}

async fn read_response_capped(response: reqwest::Response) -> Result<Bytes, String> {
    let mut stream = response.bytes_stream();
    let mut body = Vec::new();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.map_err(|error| {
            format!(
                "could not read Claude App upstream response: {}",
                reqwest_error_summary(&error)
            )
        })?;
        if body.len().saturating_add(chunk.len()) > MAX_CHAT_BODY_BYTES {
            return Err("Claude App upload response exceeded the size limit".to_string());
        }
        body.extend_from_slice(&chunk);
    }
    Ok(Bytes::from(body))
}

async fn read_request_capped(body: Incoming, label: &str) -> Result<Bytes, String> {
    match Limited::new(body, MAX_CHAT_BODY_BYTES).collect().await {
        Ok(body) => Ok(body.to_bytes()),
        Err(error) if error.is::<http_body_util::LengthLimitError>() => Err(format!(
            "payload too large: Claude App {label} request exceeds {MAX_CHAT_BODY_BYTES} bytes"
        )),
        Err(_) => Err(format!("could not read Claude App {label} request")),
    }
}

fn reqwest_error_summary(error: &reqwest::Error) -> &'static str {
    if error.is_timeout() {
        "request timed out"
    } else if error.is_connect() {
        "connection failed"
    } else if error.is_body() || error.is_decode() {
        "response body failed"
    } else {
        "request failed"
    }
}

fn claude_app_request_streaming(headers: &hyper::HeaderMap, body: &Bytes) -> bool {
    let body_streaming = serde_json::from_slice::<serde_json::Value>(body)
        .ok()
        .and_then(|value| value.get("stream").and_then(serde_json::Value::as_bool))
        .unwrap_or(false);
    let accepts_event_stream = headers
        .get_all(hyper::header::ACCEPT)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(|value| value.split(','))
        .filter_map(|value| value.split(';').next())
        .any(|value| value.trim().eq_ignore_ascii_case("text/event-stream"));
    body_streaming || accepts_event_stream
}

struct ProtectedChatRequest {
    body: Bytes,
    local_response: Option<Bytes>,
}

fn protect_chat_request(
    body: &Bytes,
    masker: &Mutex<pentect_agent::ActiveToolOutputMasker>,
    plugins: &Mutex<pentect_agent::PluginMiddleware>,
    files: &HashMap<String, crate::http_files::Coverage>,
    block_unknown_formats: bool,
) -> Result<ProtectedChatRequest, String> {
    let mut value = match parse_chat_json(body, block_unknown_formats)? {
        Some(value) => value,
        None => {
            return Ok(ProtectedChatRequest {
                body: body.clone(),
                local_response: None,
            });
        }
    };
    let run = plugins
        .lock()
        .map_err(|_| "Claude App plugin lock was poisoned".to_string())?
        .run(
            pentect_agent::MiddlewareStage::Request,
            value,
            Some(serde_json::json!({"provider": "claude", "transport": "desktop-http"})),
        )?;
    if block_unknown_formats && run.coverage == pentect_agent::MiddlewareCoverage::Partial {
        return Err(
            "unknown format blocked: a Claude App plugin reported partial request coverage; set compatibility.unknown_formats = \"ignore\" in ~/.pentect/config.toml to allow it"
                .to_string(),
        );
    }
    value = run.payload;
    if let Some(outcome) = run.stopped {
        if outcome == pentect_agent::StopOutcome::Block {
            return Err(format!(
                "plugin blocked: {}",
                run.message.unwrap_or_else(|| "request blocked".to_string())
            ));
        }
        let body = serde_json::to_vec(&value)
            .map(Bytes::from)
            .map_err(|error| format!("could not encode Claude App plugin response: {error}"))?;
        return Ok(ProtectedChatRequest {
            body: Bytes::new(),
            local_response: Some(body),
        });
    }
    let inline_file_partial = {
        let plugins = plugins
            .lock()
            .map_err(|_| "Claude App plugin lock was poisoned".to_string())?;
        crate::http_files::run_anthropic_inline_file_stages(
            &value,
            &plugins,
            "claude",
            "desktop_http_json",
        )
    }?;
    if block_unknown_formats && inline_file_partial {
        return Err(
            "unknown format blocked: a Claude App file plugin reported partial inline-file coverage"
                .to_string(),
        );
    }
    let mut masker = masker
        .lock()
        .map_err(|_| "Claude App Chat masker lock was poisoned".to_string())?;
    if let Err(error) = mask_chat_value(&mut value, false, &mut masker, files) {
        if error.starts_with("image blocked:") || error.starts_with("document blocked:") {
            return Err(error);
        }
        if block_unknown_formats {
            return Err(format!(
                "Claude App Chat request blocked: content inspection is unavailable ({error})"
            ));
        }
        eprintln!("[pentect] Claude App Chat protection skipped: {error}");
        return Ok(ProtectedChatRequest {
            body: body.clone(),
            local_response: None,
        });
    }
    inject_chat_contract(&mut value);
    let protected = serde_json::to_vec(&value)
        .map(Bytes::from)
        .map_err(|error| format!("could not encode protected Claude App Chat request: {error}"))?;
    Ok(ProtectedChatRequest {
        body: protected,
        local_response: None,
    })
}

fn parse_chat_json(
    body: &Bytes,
    block_unknown_formats: bool,
) -> Result<Option<serde_json::Value>, String> {
    match serde_json::from_slice(body) {
        Ok(value) => Ok(Some(value)),
        Err(error) => {
            if block_unknown_formats {
                return Err(format!(
                    "unknown format blocked: Claude App Chat request is not valid JSON ({error}); set compatibility.unknown_formats = \"ignore\" in ~/.pentect/config.toml to pass it through"
                ));
            }
            eprintln!("[pentect] Claude App Chat protection skipped: invalid JSON: {error}");
            Ok(None)
        }
    }
}

fn protect_generic_json_request(
    body: &Bytes,
    masker: &Mutex<pentect_agent::ActiveToolOutputMasker>,
    block_unknown_formats: bool,
) -> Result<Bytes, String> {
    let mut value = match parse_chat_json(body, block_unknown_formats)? {
        Some(value) => value,
        None => return Ok(body.clone()),
    };
    let mut masker = masker
        .lock()
        .map_err(|_| "Claude App JSON masker lock was poisoned".to_string())?;
    if let Err(error) = mask_generic_json_value(&mut value, &mut masker, true) {
        if block_unknown_formats {
            return Err(format!(
                "Claude App JSON request blocked: content inspection is unavailable ({error})"
            ));
        }
        eprintln!("[pentect] Claude App JSON protection skipped: {error}");
        return Ok(body.clone());
    }
    serde_json::to_vec(&value)
        .map(Bytes::from)
        .map_err(|error| format!("could not encode protected Claude App JSON request: {error}"))
}

fn mask_generic_json_value(
    value: &mut serde_json::Value,
    masker: &mut pentect_agent::ActiveToolOutputMasker,
    top_level: bool,
) -> Result<(), String> {
    match value {
        serde_json::Value::String(text) => {
            crate::claude_http_proxy::mask_string(text, false, masker)
        }
        serde_json::Value::Array(values) => {
            for value in values {
                mask_generic_json_value(value, masker, false)?;
            }
            Ok(())
        }
        serde_json::Value::Object(object) => {
            for (key, value) in object {
                if matches!(
                    key.as_str(),
                    "signature" | "thinking_signature" | "attestation"
                ) || (top_level && matches!(key.as_str(), "authorization" | "token"))
                {
                    continue;
                }
                mask_generic_json_value(value, masker, false)?;
            }
            Ok(())
        }
        _ => Ok(()),
    }
}

fn inject_chat_contract(value: &mut serde_json::Value) {
    let Some(object) = value.as_object_mut() else {
        return;
    };
    for key in ["system", "prompt", "custom_system_prompt"] {
        if let Some(serde_json::Value::String(text)) = object.get_mut(key) {
            if !text.contains(HANDLE_CONTRACT) {
                let existing = std::mem::take(text);
                *text = format!("{HANDLE_CONTRACT}\n\n{existing}");
            }
            return;
        }
    }
    object.insert(
        "system".to_string(),
        serde_json::Value::String(HANDLE_CONTRACT.to_string()),
    );
}

fn mask_chat_value(
    value: &mut serde_json::Value,
    tool_result: bool,
    masker: &mut pentect_agent::ActiveToolOutputMasker,
    files: &HashMap<String, crate::http_files::Coverage>,
) -> Result<(), String> {
    match value {
        serde_json::Value::String(text) => {
            crate::claude_http_proxy::mask_string(text, tool_result, masker)
        }
        serde_json::Value::Array(values) => {
            let original = std::mem::take(values);
            for mut item in original {
                let note = if item
                    .get("type")
                    .and_then(serde_json::Value::as_str)
                    .is_some_and(|kind| kind.to_ascii_lowercase().contains("image"))
                {
                    match item.as_object_mut() {
                        Some(object) => inspect_chat_image(object, files)?,
                        None => None,
                    }
                } else {
                    mask_chat_value(&mut item, tool_result, masker, files)?;
                    None
                };
                values.push(item);
                if let Some(text) = note {
                    values.push(serde_json::json!({"type": "text", "text": text}));
                }
            }
            Ok(())
        }
        serde_json::Value::Object(object) => {
            let kind = object
                .get("type")
                .and_then(serde_json::Value::as_str)
                .unwrap_or_default()
                .to_ascii_lowercase();
            if kind.contains("image") {
                let _ = inspect_chat_image(object, files)?;
                return Ok(());
            }
            if kind.contains("file") || kind.contains("document") || looks_like_chat_file(object) {
                inspect_chat_document(object, tool_result, masker, files)?;
            }
            let nested_tool_result = tool_result
                || kind.contains("tool_result")
                || kind.contains("tool_output")
                || kind.contains("function_output");
            let tool_call = kind.contains("tool_use")
                || kind.contains("tool_call")
                || kind.contains("function_call");
            for (key, nested) in object {
                if tool_call && matches!(key.as_str(), "input" | "arguments") {
                    crate::claude_http_proxy::mask_value_strings(nested, masker)?;
                    continue;
                }
                if matches!(
                    key.as_str(),
                    "signature" | "thinking_signature" | "attestation"
                ) || (!nested_tool_result && is_chat_protocol_metadata_field(key))
                {
                    continue;
                }
                mask_chat_value(nested, nested_tool_result, masker, files)?;
            }
            Ok(())
        }
        _ => Ok(()),
    }
}

fn inspect_chat_image(
    object: &mut serde_json::Map<String, serde_json::Value>,
    files: &HashMap<String, crate::http_files::Coverage>,
) -> Result<Option<String>, String> {
    if chat_file_reference(object)
        .and_then(|id| files.get(id))
        .copied()
        == Some(crate::http_files::Coverage::Full)
    {
        return Ok(None);
    }
    if let Some(source) = object
        .get_mut("source")
        .and_then(serde_json::Value::as_object_mut)
    {
        if source.get("type").and_then(serde_json::Value::as_str) == Some("base64")
            && source
                .get("media_type")
                .and_then(serde_json::Value::as_str)
                .is_some_and(|media_type| media_type.starts_with("image/"))
        {
            let Some(serde_json::Value::String(encoded)) = source.get_mut("data") else {
                return unscanned_chat_image().map(|_| None);
            };
            if let Some(protected) = crate::claude_http_proxy::redact_inline_image_data(encoded)? {
                *encoded = protected.data;
                source.insert(
                    "media_type".to_string(),
                    serde_json::Value::String("image/png".to_string()),
                );
                return Ok(Some(protected.note));
            }
            return Ok(None);
        }
        return unscanned_chat_image().map(|_| None);
    }
    let key = ["image_url", "url", "data"]
        .into_iter()
        .find(|key| object.contains_key(*key));
    let Some(serde_json::Value::String(url)) = key.and_then(|key| object.get_mut(key)) else {
        return unscanned_chat_image().map(|_| None);
    };
    let Some((metadata, encoded)) = url.split_once(',') else {
        return unscanned_chat_image().map(|_| None);
    };
    if !metadata.starts_with("data:image/") || !metadata.ends_with(";base64") {
        return unscanned_chat_image().map(|_| None);
    }
    if let Some(protected) = crate::claude_http_proxy::redact_inline_image_data(encoded)? {
        *url = format!("data:image/png;base64,{}", protected.data);
        return Ok(Some(protected.note));
    }
    Ok(None)
}

fn inspect_chat_document(
    object: &mut serde_json::Map<String, serde_json::Value>,
    tool_result: bool,
    masker: &mut pentect_agent::ActiveToolOutputMasker,
    files: &HashMap<String, crate::http_files::Coverage>,
) -> Result<(), String> {
    if chat_file_reference(object)
        .and_then(|id| files.get(id))
        .copied()
        == Some(crate::http_files::Coverage::Full)
    {
        return Ok(());
    }
    if let Some(source) = object.get_mut("source") {
        if let Some(id) = ["file_id", "id"]
            .into_iter()
            .find_map(|key| source.get(key).and_then(serde_json::Value::as_str))
        {
            if files.get(id) == Some(&crate::http_files::Coverage::Full) {
                return Ok(());
            }
        }
        if source.get("type").and_then(serde_json::Value::as_str) == Some("text") {
            if let Some(serde_json::Value::String(text)) = source.get_mut("data") {
                return crate::claude_http_proxy::mask_string(text, tool_result, masker);
            }
        }
        if source.get("type").and_then(serde_json::Value::as_str) == Some("base64") {
            return crate::claude_http_proxy::inspect_base64_document(source, tool_result, masker);
        }
        return crate::claude_http_proxy::enforce_unscanned_document_policy();
    }
    if object.get("file_id").is_some()
        || object.get("file_uuid").is_some()
        || object.get("url").is_some()
    {
        return crate::claude_http_proxy::enforce_unscanned_document_policy();
    }
    let data = object
        .get("file_data")
        .or_else(|| object.get("data"))
        .and_then(serde_json::Value::as_str);
    let Some(data) = data else {
        return crate::claude_http_proxy::enforce_unscanned_document_policy();
    };
    let (media_type, encoded) = data
        .split_once(',')
        .and_then(|(metadata, encoded)| {
            metadata
                .strip_prefix("data:")
                .and_then(|metadata| metadata.strip_suffix(";base64"))
                .map(|media_type| (media_type, encoded))
        })
        .unwrap_or(("application/octet-stream", data));
    let source = serde_json::json!({
        "type": "base64",
        "media_type": media_type,
        "data": encoded,
    });
    crate::claude_http_proxy::inspect_base64_document(&source, tool_result, masker)
}

fn is_chat_protocol_metadata_field(key: &str) -> bool {
    matches!(
        key,
        "type"
            | "id"
            | "uuid"
            | "tool_use_id"
            | "role"
            | "name"
            | "index"
            | "stop_reason"
            | "signature"
            | "thinking_signature"
            | "attestation"
            | "authorization"
            | "token"
    )
}

fn looks_like_chat_file(object: &serde_json::Map<String, serde_json::Value>) -> bool {
    (object.contains_key("file_id") || object.contains_key("file_uuid"))
        && (object.contains_key("file_name")
            || object.contains_key("filename")
            || object.contains_key("mime_type")
            || object.contains_key("content_type"))
}

fn chat_file_reference(object: &serde_json::Map<String, serde_json::Value>) -> Option<&str> {
    ["file_id", "file_uuid"]
        .into_iter()
        .find_map(|key| object.get(key).and_then(serde_json::Value::as_str))
}

fn unscanned_chat_image() -> Result<(), String> {
    if pentect_agent::unscanned_images_should_block()? {
        Err("image blocked: image source could not be scanned".to_string())
    } else {
        Ok(())
    }
}

type ChatFrameStream =
    Pin<Box<dyn futures_util::Stream<Item = Result<Frame<Bytes>, ProxyBodyError>> + Send>>;
type ChatResolver = Box<dyn FnMut(&str) -> Result<String, String> + Send>;

struct ChatStreamState {
    upstream: ChatFrameStream,
    ready: VecDeque<Result<Frame<Bytes>, ProxyBodyError>>,
    finished: bool,
    transformer: Option<crate::claude_http_proxy::SseStreamTransformer<ChatResolver>>,
}

fn rewrite_chat_json_response(
    body: &Bytes,
    plugins: &Mutex<pentect_agent::PluginMiddleware>,
    block_unknown_formats: bool,
    restore_output: bool,
) -> Result<Bytes, String> {
    let mut resolve = crate::claude_http_proxy::request_scoped_resolver();
    rewrite_chat_json_response_with(
        body,
        plugins,
        block_unknown_formats,
        restore_output,
        &mut resolve,
    )
}

fn rewrite_chat_json_response_with<R>(
    body: &Bytes,
    plugins: &Mutex<pentect_agent::PluginMiddleware>,
    block_unknown_formats: bool,
    restore_output: bool,
    resolve: &mut R,
) -> Result<Bytes, String>
where
    R: FnMut(&str) -> Result<String, String>,
{
    let mut value: serde_json::Value = match serde_json::from_slice(body) {
        Ok(value) => value,
        Err(error) if block_unknown_formats => {
            return Err(format!(
                "unknown format blocked: Claude App Chat response is not valid JSON ({error})"
            ));
        }
        Err(error) => {
            eprintln!("[pentect] Claude App Chat response protection skipped: {error}");
            return Ok(body.clone());
        }
    };
    let run = plugins
        .lock()
        .map_err(|_| "Claude App plugin lock was poisoned".to_string())?
        .run(
            pentect_agent::MiddlewareStage::Response,
            value,
            Some(serde_json::json!({"provider": "claude", "transport": "desktop-http"})),
        )?;
    if block_unknown_formats && run.coverage == pentect_agent::MiddlewareCoverage::Partial {
        return Err(
            "unknown format blocked: a Claude App plugin reported partial response coverage"
                .to_string(),
        );
    }
    if run.stopped == Some(pentect_agent::StopOutcome::Block) {
        return Err(format!(
            "plugin blocked: {}",
            run.message
                .unwrap_or_else(|| "response blocked".to_string())
        ));
    }
    value = run.payload;
    {
        let plugins = plugins
            .lock()
            .map_err(|_| "Claude App plugin lock was poisoned".to_string())?
            .clone();
        run_chat_tool_plugins(&mut value, &plugins)?;
    }
    resolve_chat_tool_calls(&mut value, resolve)?;
    crate::claude_http_proxy::restore_anthropic_json_value(&mut value, restore_output, resolve)?;
    serde_json::to_vec(&value)
        .map(Bytes::from)
        .map_err(|error| format!("could not encode Claude App Chat response: {error}"))
}

fn chat_sse_body<S>(
    stream: S,
    plugins: Arc<Mutex<pentect_agent::PluginMiddleware>>,
    restore_output: bool,
) -> ProxyBody
where
    S: futures_util::Stream<Item = Result<Frame<Bytes>, ProxyBodyError>> + Send + 'static,
{
    chat_sse_body_with_limit(stream, plugins, restore_output, MAX_CHAT_BODY_BYTES)
}

fn chat_sse_body_with_limit<S>(
    stream: S,
    plugins: Arc<Mutex<pentect_agent::PluginMiddleware>>,
    restore_output: bool,
    max_pending_bytes: usize,
) -> ProxyBody
where
    S: futures_util::Stream<Item = Result<Frame<Bytes>, ProxyBodyError>> + Send + 'static,
{
    let resolve: ChatResolver = Box::new(crate::claude_http_proxy::request_scoped_resolver());
    let transformer = crate::claude_http_proxy::SseStreamTransformer::new_for_claude_app(
        resolve,
        plugins,
        restore_output,
        max_pending_bytes,
    );
    chat_sse_body_with_transformer(stream, transformer)
}

fn chat_sse_body_with_transformer<S>(
    stream: S,
    transformer: crate::claude_http_proxy::SseStreamTransformer<ChatResolver>,
) -> ProxyBody
where
    S: futures_util::Stream<Item = Result<Frame<Bytes>, ProxyBodyError>> + Send + 'static,
{
    let state = ChatStreamState {
        upstream: Box::pin(stream),
        ready: VecDeque::new(),
        finished: false,
        transformer: Some(transformer),
    };
    let stream = futures_util::stream::unfold(state, |mut state| async move {
        loop {
            if let Some(item) = state.ready.pop_front() {
                return Some((item, state));
            }
            if state.finished {
                return None;
            }
            match state.upstream.next().await {
                Some(Ok(frame)) => {
                    let Ok(chunk) = frame.into_data() else {
                        continue;
                    };
                    let Some(mut transformer) = state.transformer.take() else {
                        state.finished = true;
                        state.ready.push_back(Err(Box::new(io::Error::other(
                            "Claude App Chat transformer is unavailable",
                        ))));
                        continue;
                    };
                    let transformed = tokio::task::spawn_blocking(move || {
                        let result = transformer.push(&chunk);
                        (result, transformer)
                    })
                    .await;
                    let (result, transformer) = match transformed {
                        Ok(result) => result,
                        Err(_) => {
                            state.finished = true;
                            state.ready.push_back(Err(Box::new(io::Error::other(
                                "Claude App Chat restoration task failed",
                            ))));
                            continue;
                        }
                    };
                    state.transformer = Some(transformer);
                    match result {
                        Ok(chunks) => state
                            .ready
                            .extend(chunks.into_iter().map(|chunk| Ok(Frame::data(chunk)))),
                        Err(error) => {
                            eprintln!("[pentect] Claude App Chat response blocked: {error}");
                            state.finished = true;
                            state.ready.push_back(Err(Box::new(io::Error::new(
                                io::ErrorKind::PermissionDenied,
                                error,
                            ))));
                        }
                    }
                }
                Some(Err(error)) => {
                    state.finished = true;
                    state.ready.push_back(Err(error));
                }
                None => {
                    state.finished = true;
                    if let Some(mut transformer) = state.transformer.take() {
                        match transformer.finish() {
                            Ok(chunks) => state
                                .ready
                                .extend(chunks.into_iter().map(|chunk| Ok(Frame::data(chunk)))),
                            Err(error) => {
                                eprintln!(
                                    "[pentect] Claude App Chat response blocked at EOF: {error}"
                                );
                                state.ready.push_back(Err(Box::new(io::Error::new(
                                    io::ErrorKind::PermissionDenied,
                                    error,
                                ))));
                            }
                        }
                    }
                }
            }
        }
    });
    StreamBody::new(stream).boxed_unsync()
}

fn run_chat_tool_plugins(
    value: &mut serde_json::Value,
    plugins: &pentect_agent::PluginMiddleware,
) -> Result<(), String> {
    match value {
        serde_json::Value::Array(values) => {
            for value in values {
                run_chat_tool_plugins(value, plugins)?;
            }
        }
        serde_json::Value::Object(object) => {
            let kind = object
                .get("type")
                .and_then(serde_json::Value::as_str)
                .unwrap_or_default()
                .to_ascii_lowercase();
            let is_call = (kind.contains("tool_use")
                || kind.contains("tool_call")
                || kind.contains("function_call"))
                && ["arguments", "input"]
                    .into_iter()
                    .any(|key| object.contains_key(key));
            if is_call {
                let run = plugins.run(
                    pentect_agent::MiddlewareStage::ToolCall,
                    serde_json::Value::Object(object.clone()),
                    Some(serde_json::json!({"provider": "claude", "transport": "desktop-http"})),
                )?;
                crate::plugins::enforce_tool_plugin_coverage(run.coverage, "Claude App")?;
                if run.stopped == Some(pentect_agent::StopOutcome::Block) {
                    return Err(format!(
                        "plugin blocked: {}",
                        run.message
                            .unwrap_or_else(|| "tool call blocked".to_string())
                    ));
                }
                *object = run
                    .payload
                    .as_object()
                    .cloned()
                    .ok_or_else(|| "tool_call plugin payload must be an object".to_string())?;
            }
            for child in object.values_mut() {
                run_chat_tool_plugins(child, plugins)?;
            }
        }
        _ => {}
    }
    Ok(())
}

fn resolve_chat_tool_calls<R>(value: &mut serde_json::Value, resolve: &mut R) -> Result<(), String>
where
    R: FnMut(&str) -> Result<String, String>,
{
    match value {
        serde_json::Value::Array(values) => {
            for value in values {
                resolve_chat_tool_calls(value, resolve)?;
            }
        }
        serde_json::Value::Object(object) => {
            let kind = object
                .get("type")
                .and_then(serde_json::Value::as_str)
                .unwrap_or_default()
                .to_ascii_lowercase();
            let tool_call = kind.contains("tool_use")
                || kind.contains("tool_call")
                || kind.contains("function_call");
            if tool_call {
                let name = object
                    .get("name")
                    .and_then(serde_json::Value::as_str)
                    .map(str::to_owned);
                for key in ["arguments", "input"] {
                    if let Some(arguments) = object.get_mut(key) {
                        let (encoded, was_string) = match &*arguments {
                            serde_json::Value::String(text) => (text.clone(), true),
                            value => (
                                serde_json::to_string(value).map_err(|error| {
                                    format!("could not encode Claude App tool input: {error}")
                                })?,
                                false,
                            ),
                        };
                        let resolved = crate::claude_http_proxy::resolve_tool_input_json(
                            &encoded,
                            name.as_deref(),
                            resolve,
                        )?;
                        *arguments = if was_string {
                            serde_json::Value::String(resolved)
                        } else {
                            serde_json::from_str(&resolved).map_err(|error| {
                                format!("could not decode Claude App tool input: {error}")
                            })?
                        };
                    }
                }
            }
            for nested in object.values_mut() {
                resolve_chat_tool_calls(nested, resolve)?;
            }
        }
        _ => {}
    }
    Ok(())
}

fn metadata_path(path: &str) -> String {
    let mut safe = String::with_capacity(path.len().min(256));
    for segment in path.split('/').filter(|segment| !segment.is_empty()) {
        safe.push('/');
        if segment.len() > 36
            || segment.bytes().all(|byte| byte.is_ascii_digit())
            || looks_like_uuid(segment)
            || looks_like_opaque_id(segment)
        {
            safe.push_str(":id");
        } else {
            safe.push_str(segment);
        }
        if safe.len() >= 256 {
            safe.truncate(256);
            safe.push_str("...");
            break;
        }
    }
    if safe.len() > 1 && path.ends_with('/') {
        safe.push('/');
    }
    if safe.is_empty() {
        safe.push('/');
    }
    safe
}

fn looks_like_opaque_id(segment: &str) -> bool {
    segment.starts_with("cse_")
        || (segment.len() >= 24
            && segment
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_')))
}

fn looks_like_uuid(segment: &str) -> bool {
    segment.len() == 36
        && [8, 13, 18, 23]
            .into_iter()
            .all(|index| segment.as_bytes().get(index) == Some(&b'-'))
        && segment
            .bytes()
            .enumerate()
            .all(|(index, byte)| [8, 13, 18, 23].contains(&index) || byte.is_ascii_hexdigit())
}

fn remove_hop_by_hop_headers(headers: &mut hyper::HeaderMap) {
    let connection_headers = headers
        .get(hyper::header::CONNECTION)
        .and_then(|value| value.to_str().ok())
        .map(|value| {
            value
                .split(',')
                .filter_map(|name| name.trim().parse::<hyper::header::HeaderName>().ok())
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    for name in connection_headers {
        headers.remove(name);
    }
    for name in [
        hyper::header::CONNECTION,
        hyper::header::PROXY_AUTHENTICATE,
        hyper::header::PROXY_AUTHORIZATION,
        hyper::header::TE,
        hyper::header::TRAILER,
        hyper::header::TRANSFER_ENCODING,
        hyper::header::UPGRADE,
    ] {
        headers.remove(name);
    }
    headers.remove("proxy-connection");
}

fn empty_response(status: StatusCode) -> Response<ProxyBody> {
    Response::builder()
        .status(status)
        .body(
            Empty::<Bytes>::new()
                .map_err(|never| match never {})
                .boxed_unsync(),
        )
        .expect("static empty response")
}

fn text_response(status: StatusCode, message: &str) -> Response<ProxyBody> {
    Response::builder()
        .status(status)
        .header(hyper::header::CONTENT_TYPE, "text/plain; charset=utf-8")
        .body(
            Full::new(Bytes::copy_from_slice(message.as_bytes()))
                .map_err(|never| match never {})
                .boxed_unsync(),
        )
        .expect("static text response")
}

pub(crate) fn default_claude_app_path() -> PathBuf {
    #[cfg(windows)]
    {
        if let Some(path) = find_windows_claude_app() {
            return path;
        }
    }
    #[cfg(target_os = "macos")]
    {
        return PathBuf::from("/Applications/Claude.app/Contents/MacOS/Claude");
    }
    #[cfg(all(unix, not(target_os = "macos")))]
    {
        for path in [
            "/usr/bin/claude-desktop",
            "/usr/local/bin/claude-desktop",
            "/opt/Claude/claude",
        ] {
            let path = PathBuf::from(path);
            if path.is_file() {
                return path;
            }
        }
    }
    PathBuf::from("claude-desktop")
}

fn claude_user_data_dir() -> Result<PathBuf, String> {
    #[cfg(windows)]
    {
        std::env::var_os("APPDATA")
            .map(PathBuf::from)
            .map(|path| path.join("Claude"))
            .ok_or_else(|| "could not locate Claude Desktop user data".to_string())
    }
    #[cfg(target_os = "macos")]
    {
        std::env::var_os("HOME")
            .map(PathBuf::from)
            .map(|path| {
                path.join("Library")
                    .join("Application Support")
                    .join("Claude")
            })
            .ok_or_else(|| "could not locate Claude Desktop user data".to_string())
    }
    #[cfg(all(unix, not(target_os = "macos")))]
    {
        std::env::var_os("XDG_CONFIG_HOME")
            .map(PathBuf::from)
            .or_else(|| std::env::var_os("HOME").map(|home| PathBuf::from(home).join(".config")))
            .map(|path| path.join("Claude"))
            .ok_or_else(|| "could not locate Claude Desktop user data".to_string())
    }
}

#[cfg(windows)]
fn find_windows_claude_app() -> Option<PathBuf> {
    find_windows_claude_package().map(|package| package.executable)
}

#[cfg(windows)]
#[derive(Clone, Debug)]
struct WindowsClaudePackage {
    executable: PathBuf,
    aumid: String,
}

#[cfg(windows)]
fn find_windows_claude_package() -> Option<WindowsClaudePackage> {
    use std::os::windows::process::CommandExt;
    const CREATE_NO_WINDOW: u32 = 0x0800_0000;
    const PACKAGES_KEY: &str = r"HKCU\Software\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppModel\Repository\Packages";

    // WindowsApps intentionally denies ordinary directory enumeration. The
    // per-user AppModel repository is the supported local index for package
    // roots and does not require elevation.
    let reg = crate::windows_system_executable("reg.exe");
    let output = Command::new(&reg)
        .args(["query", PACKAGES_KEY])
        .creation_flags(CREATE_NO_WINDOW)
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let keys = String::from_utf8_lossy(&output.stdout);
    let mut candidates = keys
        .lines()
        .map(str::trim)
        .filter(|line| {
            line.rsplit('\\').next().is_some_and(|name| {
                name.starts_with("Claude_") && windows_package_matches_arch(name)
            })
        })
        .filter_map(|key| {
            let package_name = key.rsplit('\\').next()?.to_string();
            let output = Command::new(&reg)
                .args(["query", key, "/v", "PackageRootFolder"])
                .creation_flags(CREATE_NO_WINDOW)
                .output()
                .ok()?;
            if !output.status.success() {
                return None;
            }
            let root = String::from_utf8_lossy(&output.stdout)
                .lines()
                .find_map(|line| {
                    let (_, value) = line.split_once("REG_SZ")?;
                    Some(value.trim())
                })?
                .to_string();
            let executable = PathBuf::from(root).join("app").join("Claude.exe");
            let aumid = windows_package_aumid(&package_name, &executable).ok()?;
            executable.is_file().then(|| {
                (
                    windows_package_version(&package_name),
                    WindowsClaudePackage { executable, aumid },
                )
            })
        })
        .collect::<Vec<_>>();
    candidates.sort_by(|left, right| left.0.cmp(&right.0));
    candidates.pop().map(|(_, package)| package)
}

#[cfg(windows)]
fn windows_package_aumid(package_name: &str, executable: &Path) -> Result<String, String> {
    let (qualified, publisher_id) = package_name
        .rsplit_once("__")
        .ok_or_else(|| "Claude package identity has no publisher ID".to_string())?;
    let identity = qualified
        .split('_')
        .next()
        .filter(|value| !value.is_empty())
        .ok_or_else(|| "Claude package identity name is unavailable".to_string())?;
    let package_root = executable
        .parent()
        .and_then(Path::parent)
        .ok_or_else(|| "Claude package root is unavailable".to_string())?;
    let application_id = appx_application_id(&package_root.join("AppxManifest.xml"))?;
    Ok(format!("{identity}_{publisher_id}!{application_id}"))
}

#[cfg(windows)]
fn appx_application_id(path: &Path) -> Result<String, String> {
    use quick_xml::events::Event;
    const MAX_MANIFEST_BYTES: u64 = 1024 * 1024;

    let metadata = std::fs::metadata(path)
        .map_err(|error| format!("could not inspect Claude AppxManifest.xml: {error}"))?;
    if !metadata.is_file() || metadata.len() > MAX_MANIFEST_BYTES {
        return Err("Claude AppxManifest.xml is not a bounded regular file".to_string());
    }
    let source = std::fs::read(path)
        .map_err(|error| format!("could not read Claude AppxManifest.xml: {error}"))?;
    let mut reader = quick_xml::Reader::from_reader(source.as_slice());
    loop {
        match reader.read_event() {
            Ok(Event::Start(element)) | Ok(Event::Empty(element))
                if element.local_name().as_ref() == b"Application" =>
            {
                for attribute in element.attributes().flatten() {
                    if attribute.key.local_name().as_ref() == b"Id" {
                        let value = std::str::from_utf8(attribute.value.as_ref())
                            .map_err(|_| "Claude application ID is invalid".to_string())?
                            .to_string();
                        if !value.is_empty()
                            && value.len() <= 128
                            && value
                                .chars()
                                .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '.' | '-'))
                        {
                            return Ok(value);
                        }
                        return Err("Claude application ID contains invalid characters".to_string());
                    }
                }
            }
            Ok(Event::Eof) => break,
            Err(_) => return Err("Claude AppxManifest.xml is invalid".to_string()),
            _ => {}
        }
    }
    Err("Claude AppxManifest.xml has no application ID".to_string())
}

#[cfg(windows)]
fn paths_equal_case_insensitive(left: &Path, right: &Path) -> bool {
    left.as_os_str()
        .to_string_lossy()
        .eq_ignore_ascii_case(&right.as_os_str().to_string_lossy())
}

#[cfg(windows)]
fn windows_package_version(name: &str) -> Vec<u64> {
    name.split('_')
        .nth(1)
        .unwrap_or_default()
        .split('.')
        .map(|part| part.parse().unwrap_or(0))
        .collect()
}

#[cfg(windows)]
fn windows_package_matches_arch(name: &str) -> bool {
    let name = name.to_ascii_lowercase();
    if cfg!(target_arch = "aarch64") {
        name.contains("_arm64__")
    } else {
        name.contains("_x64__")
    }
}

fn claude_desktop_is_running(app: &Path) -> bool {
    let expected = app
        .canonicalize()
        .unwrap_or_else(|_| app.to_path_buf())
        .to_string_lossy()
        .to_ascii_lowercase();
    let mut system = sysinfo::System::new();
    system.refresh_processes(sysinfo::ProcessesToUpdate::All, true);
    system.processes().values().any(|process| {
        process
            .exe()
            .and_then(|path| path.canonicalize().ok())
            .is_some_and(|path| path.to_string_lossy().to_ascii_lowercase() == expected)
    })
}

#[cfg(windows)]
fn success_status() -> std::process::ExitStatus {
    use std::os::windows::process::ExitStatusExt;
    std::process::ExitStatus::from_raw(0)
}

#[cfg(unix)]
fn success_status() -> std::process::ExitStatus {
    use std::os::unix::process::ExitStatusExt;
    std::process::ExitStatus::from_raw(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn oversized_chat_sse_event_fails_closed_without_emitting_it() {
        let stream = futures_util::stream::iter(vec![Ok::<_, ProxyBodyError>(Frame::data(
            Bytes::from_static(b"12345"),
        ))]);
        let body = chat_sse_body_with_limit(
            stream,
            Arc::new(Mutex::new(pentect_agent::PluginMiddleware::default())),
            false,
            4,
        );

        let error = match body.collect().await {
            Ok(_) => panic!("oversized uninspected event must not be emitted"),
            Err(error) => error,
        };
        assert!(
            error
                .to_string()
                .contains("SSE event exceeded inspection limit"),
            "{error}"
        );
    }

    #[tokio::test]
    async fn streaming_chat_restores_text_handles_split_across_events() {
        let first = concat!(
            "event: content_block_delta\n",
            "data: {\"type\":\"content_block_delta\",\"index\":0,\"delta\":{\"type\":\"text_delta\",\"text\":\"before <<CHAR\"}}\n\n"
        );
        let second = concat!(
            "event: content_block_delta\n",
            "data: {\"type\":\"content_block_delta\",\"index\":0,\"delta\":{\"type\":\"text_delta\",\"text\":\"GE_0123456789abcdef>> after\"}}\n\n"
        );
        let stop = concat!(
            "event: content_block_stop\n",
            "data: {\"type\":\"content_block_stop\",\"index\":0}\n\n"
        );
        let stream = futures_util::stream::iter(vec![Ok::<_, ProxyBodyError>(Frame::data(
            Bytes::from(format!("{first}{second}{stop}")),
        ))]);
        let resolve: ChatResolver =
            Box::new(|text: &str| Ok(text.replace("<<CHARGE_0123456789abcdef>>", "local-value")));
        let transformer = crate::claude_http_proxy::SseStreamTransformer::new_for_claude_app(
            resolve,
            Arc::new(Mutex::new(pentect_agent::PluginMiddleware::default())),
            true,
            MAX_CHAT_BODY_BYTES,
        );

        let output = chat_sse_body_with_transformer(stream, transformer)
            .collect()
            .await
            .unwrap()
            .to_bytes();
        let output = std::str::from_utf8(&output).unwrap();
        assert!(output.contains("\"text\":\"before \""), "{output}");
        assert!(
            output.contains("\"text\":\"local-value after\""),
            "{output}"
        );
        assert!(!output.contains("<<CHARGE_"), "{output}");
    }

    #[tokio::test]
    async fn streaming_chat_reassembles_tool_input_and_multiline_data() {
        let input = concat!(
            "event: content_block_start\n",
            "data: {\"type\":\"content_block_start\",\"index\":1,\"content_block\":{\"type\":\"tool_use\",\"name\":\"http\",\"input\":{}}}\n\n",
            "event: content_block_delta\n",
            "data: {\"type\":\"content_block_delta\",\n",
            "data: \"index\":1,\"delta\":{\"type\":\"input_json_delta\",\"partial_json\":\"{\\\"token\\\":\\\"<<KEYED_SECRET_0123456789abcdef>>\\\"}\"}}\n\n",
            "event: content_block_stop\n",
            "data: {\"type\":\"content_block_stop\",\"index\":1}\n\n"
        );
        let stream = futures_util::stream::iter(vec![Ok::<_, ProxyBodyError>(Frame::data(
            Bytes::from_static(input.as_bytes()),
        ))]);
        let resolve: ChatResolver = Box::new(|text: &str| {
            Ok(text.replace("<<KEYED_SECRET_0123456789abcdef>>", "local-value"))
        });
        let transformer = crate::claude_http_proxy::SseStreamTransformer::new_for_claude_app(
            resolve,
            Arc::new(Mutex::new(pentect_agent::PluginMiddleware::default())),
            false,
            MAX_CHAT_BODY_BYTES,
        );

        let output = chat_sse_body_with_transformer(stream, transformer)
            .collect()
            .await
            .unwrap()
            .to_bytes();
        let output = std::str::from_utf8(&output).unwrap();
        assert!(output.contains("local-value"), "{output}");
        assert!(!output.contains("<<KEYED_SECRET_"), "{output}");
        assert!(!output.contains("\ndata: \"index\""), "{output}");
    }

    #[tokio::test]
    async fn streaming_chat_restoration_error_fails_closed() {
        let input = concat!(
            "event: content_block_delta\n",
            "data: {\"type\":\"content_block_delta\",\"index\":0,\"delta\":{\"type\":\"text_delta\",\"text\":\"<<SECRET_0123456789abcdef>>\"}}\n\n"
        );
        let stream = futures_util::stream::iter(vec![Ok::<_, ProxyBodyError>(Frame::data(
            Bytes::from_static(input.as_bytes()),
        ))]);
        let resolve: ChatResolver = Box::new(|_: &str| Err("memory store unavailable".to_string()));
        let transformer = crate::claude_http_proxy::SseStreamTransformer::new_for_claude_app(
            resolve,
            Arc::new(Mutex::new(pentect_agent::PluginMiddleware::default())),
            true,
            MAX_CHAT_BODY_BYTES,
        );

        let error = chat_sse_body_with_transformer(stream, transformer)
            .collect()
            .await
            .unwrap_err();
        assert!(
            error.to_string().contains("memory store unavailable"),
            "{error}"
        );
    }

    #[test]
    fn early_exit_diagnostic_does_not_recommend_an_update_or_unsafe_bypass() {
        for packaged in [false, true] {
            let error = claude_desktop_early_exit_error("exit code: 1", packaged);
            assert!(
                error.contains("exited before Pentect could attach"),
                "{error}"
            );
            assert!(error.contains("certificate will be removed"), "{error}");
            assert!(!error.contains("update Claude Desktop"), "{error}");
            assert!(!error.contains("ignore-certificate-errors"), "{error}");
        }
    }

    struct MaskingTestEnv {
        _guard: crate::EnvVarGuard,
        home: PathBuf,
        process_host_candidate: Option<PathBuf>,
    }

    impl MaskingTestEnv {
        fn install(store: &pentect_agent::InProcessMemoryStore) -> Self {
            let home = std::env::temp_dir().join(format!(
                "pentect-claude-app-test-{}-{}",
                std::process::id(),
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_nanos()
            ));
            std::fs::create_dir_all(&home).unwrap();
            let guard = crate::EnvVarGuard::set_optional([
                (
                    "PENTECT_MEMORY_STORE_ADDR",
                    Some(store.addr().to_string().into()),
                ),
                (
                    "PENTECT_MEMORY_STORE_TOKEN",
                    Some(store.token().to_string().into()),
                ),
                (
                    "PENTECT_AGENT_LAUNCHED",
                    Some(store.token().to_string().into()),
                ),
                ("PENTECT_HOME", Some(home.as_os_str().to_owned())),
                (crate::plugins::CONFIGS_ENV, None),
                (crate::plugins::BINARIES_ENV, None),
                (crate::plugins::GLOBAL_BINARIES_ENV, None),
                (crate::plugins::GLOBAL_BINARY_IDS_ENV, None),
            ]);
            let process_host_candidate = Some(
                pentect_agent::register_process_host_candidate(
                    &pentect_agent::process_host_root().unwrap(),
                    store.addr(),
                    store.token(),
                    store.process_host_read_token(),
                    store.process_host_write_token(),
                    std::process::id(),
                )
                .unwrap(),
            );
            Self {
                _guard: guard,
                home,
                process_host_candidate,
            }
        }
    }

    impl Drop for MaskingTestEnv {
        fn drop(&mut self) {
            if let Some(path) = self.process_host_candidate.take() {
                let _ = std::fs::remove_file(path);
            }
            let _ = std::fs::remove_dir_all(&self.home);
        }
    }

    #[test]
    fn options_accept_an_explicit_app_path() {
        let args = vec![
            "pentect".to_string(),
            "claude-app".to_string(),
            "--app".to_string(),
            "Claude.exe".to_string(),
        ];
        let options = ClaudeAppOptions::parse(&args).unwrap();
        assert_eq!(options.app, Some(PathBuf::from("Claude.exe")));
    }

    #[test]
    fn options_accept_the_nested_claude_app_command() {
        let args = vec![
            "pentect".to_string(),
            "claude".to_string(),
            "app".to_string(),
            "--plugins".to_string(),
            "company-policy".to_string(),
            "--app".to_string(),
            "Claude.exe".to_string(),
            "--dry-run".to_string(),
            "--yes".to_string(),
        ];
        let options = ClaudeAppOptions::parse(&args).unwrap();
        assert_eq!(options.app, Some(PathBuf::from("Claude.exe")));
        assert!(options.check);
        assert!(options.assume_yes);
    }

    #[test]
    fn options_accept_assignment_form_for_all_valued_options() {
        let args = [
            "pentect",
            "claude",
            "app",
            "--plugins=company-policy",
            "--app=Claude.exe",
            "--upstream=https://example.test/anthropic",
            "--upstream-header-env=x-api-key=ANTHROPIC_API_KEY",
            "--upstream-header-env=x-gateway-key=GATEWAY_KEY",
            "--yes",
        ]
        .map(str::to_string);
        let options = ClaudeAppOptions::parse(&args).unwrap();
        assert_eq!(options.app, Some(PathBuf::from("Claude.exe")));
        assert_eq!(
            options.upstream.as_deref(),
            Some("https://example.test/anthropic")
        );
        assert_eq!(
            options.upstream_header_env,
            ["x-api-key=ANTHROPIC_API_KEY", "x-gateway-key=GATEWAY_KEY"]
        );
        assert!(options.assume_yes);
    }

    #[test]
    fn options_reject_missing_plugin_value() {
        let args = vec![
            "pentect".to_string(),
            "claude".to_string(),
            "app".to_string(),
            "--plugins".to_string(),
            "--dry-run".to_string(),
        ];
        assert!(ClaudeAppOptions::parse(&args).is_err());
    }

    #[test]
    fn check_mode_does_not_treat_an_option_value_as_a_flag() {
        let args = vec![
            "pentect".to_string(),
            "claude".to_string(),
            "app".to_string(),
            "--app".to_string(),
            "--check".to_string(),
        ];
        assert!(!check_mode(&args).unwrap());
    }

    #[test]
    fn inspection_scope_is_exact_domain_suffix() {
        assert!(should_inspect("claude.ai", 443));
        assert!(should_inspect("assets.claude.ai", 443));
        assert!(!should_inspect("claude.ai.example.test", 443));
        assert!(!should_inspect("notclaude.ai", 443));
        assert!(!should_inspect("claude.ai", 8443));
    }

    #[test]
    fn chat_rewriting_requires_the_completion_json_endpoint() {
        assert!(is_chat_completion(
            "claude.ai",
            "/api/organizations/example/chat_conversations/example/completion",
            "application/json; charset=utf-8"
        ));
        assert!(is_chat_completion(
            "api.claude.com",
            "/api/chat_conversations/example/completion",
            "application/json"
        ));
        assert!(is_chat_completion(
            "claude.ai",
            "/api/organizations/example/chat_conversations/example/completion2",
            "application/json"
        ));
        assert!(is_chat_completion(
            "claude.ai",
            "/api/organizations/example/chat_conversations/example/retry_completion2",
            "application/json"
        ));
        assert!(is_chat_completion(
            "claude.ai",
            "/api/organizations/example/chat_conversations/example/completion/",
            "application/json"
        ));
        assert!(!is_chat_completion(
            "claude.ai.example.test",
            "/completion",
            "application/json"
        ));
        assert!(!is_chat_completion(
            "claude.ai",
            "/completion",
            "multipart/form-data"
        ));
        assert!(!is_chat_completion(
            "claude.ai",
            "/completion_status",
            "application/json"
        ));
    }

    #[test]
    fn claude_app_streaming_requests_are_detected_from_body_or_accept_header() {
        let mut headers = hyper::HeaderMap::new();
        headers.insert(
            hyper::header::ACCEPT,
            hyper::header::HeaderValue::from_static(
                "application/json, text/event-stream; charset=utf-8",
            ),
        );
        assert!(claude_app_request_streaming(
            &headers,
            &Bytes::from_static(br#"{"stream":false}"#)
        ));

        let headers = hyper::HeaderMap::new();
        assert!(claude_app_request_streaming(
            &headers,
            &Bytes::from_static(br#"{"stream":true}"#)
        ));
        assert!(!claude_app_request_streaming(
            &headers,
            &Bytes::from_static(br#"{"stream":false}"#)
        ));
    }

    #[test]
    fn unsupported_model_transports_are_classified_without_matching_unrelated_routes() {
        assert_eq!(
            classify_claude_app_request(
                &Method::POST,
                "claude.ai",
                "/v1/mobile/appendMessage",
                "application/proto"
            ),
            ClaudeAppRequest::UnsupportedModel
        );
        assert_eq!(
            classify_claude_app_request(
                &Method::GET,
                "claude.ai",
                "/api/ws/voice/organizations/o/chat_conversations/c",
                "-"
            ),
            ClaudeAppRequest::UnsupportedModel
        );
        assert_eq!(
            classify_claude_app_request(
                &Method::POST,
                "claude.ai",
                "/v1/mobile/unrelated",
                "application/proto"
            ),
            ClaudeAppRequest::Other
        );
        assert_eq!(
            classify_claude_app_request(
                &Method::POST,
                "claude.ai",
                "/api/event_logging/v2/batch",
                "application/json"
            ),
            ClaudeAppRequest::JsonScan
        );
    }

    #[test]
    fn put_and_patch_json_updates_are_classified_and_masked() {
        let _lock = crate::TEST_PROCESS_ENV_LOCK.lock().unwrap();
        let store = pentect_agent::start_in_process_memory_store().unwrap();
        let _env = MaskingTestEnv::install(&store);
        let secret = "rpa_ZYXWVUTSRQPONMLKJIHGFEDCBA0987654321fedcba";
        let body = Bytes::from(
            serde_json::to_vec(&serde_json::json!({
                "instructions": format!("RUNPOD_API_KEY={secret}")
            }))
            .unwrap(),
        );

        for (method, content_type) in [
            (Method::PUT, "application/json"),
            (Method::PATCH, "application/merge-patch+json"),
        ] {
            assert_eq!(
                classify_claude_app_request(
                    &method,
                    "claude.ai",
                    "/api/organizations/org/projects/project",
                    content_type,
                ),
                ClaudeAppRequest::JsonScan
            );
            let masker = Mutex::new(pentect_agent::ActiveToolOutputMasker::new().unwrap());
            let protected = protect_generic_json_request(&body, &masker, true).unwrap();
            let protected = String::from_utf8(protected.to_vec()).unwrap();
            assert!(!protected.contains(secret), "{method} leaked the secret");
            assert!(
                protected.contains("<<RUNPOD_API_KEY_"),
                "{method}: {protected}"
            );
        }

        assert_eq!(
            classify_claude_app_request(
                &Method::GET,
                "claude.ai",
                "/api/organizations/org/projects/project",
                "application/json",
            ),
            ClaudeAppRequest::Other
        );
    }

    #[test]
    fn voice_websocket_passthrough_requires_exact_host_path_method_and_upgrade() {
        let path = "/api/ws/voice/organizations/o/chat_conversations/c";
        let mut headers = hyper::HeaderMap::new();
        headers.insert(
            hyper::header::CONNECTION,
            hyper::header::HeaderValue::from_static("keep-alive, Upgrade"),
        );
        headers.insert(
            hyper::header::UPGRADE,
            hyper::header::HeaderValue::from_static("websocket"),
        );
        assert!(is_claude_voice_websocket_request(
            &Method::GET,
            "claude.ai",
            path,
            &headers
        ));
        assert!(!is_claude_voice_websocket_request(
            &Method::POST,
            "claude.ai",
            path,
            &headers
        ));
        assert!(!is_claude_voice_websocket_request(
            &Method::GET,
            "voice.claude.ai",
            path,
            &headers
        ));
        assert!(!is_claude_voice_websocket_request(
            &Method::GET,
            "claude.ai.example.test",
            path,
            &headers
        ));
        assert!(!is_claude_voice_websocket_request(
            &Method::GET,
            "claude.ai",
            "/api/ws/voice/organizations/o/not_conversations/c",
            &headers
        ));
        headers.remove(hyper::header::UPGRADE);
        assert!(!is_claude_voice_websocket_request(
            &Method::GET,
            "claude.ai",
            path,
            &headers
        ));
    }

    #[tokio::test]
    async fn relaxed_voice_websocket_completes_handshake_and_relays_bytes() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let upstream_listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
        let upstream_address = upstream_listener.local_addr().unwrap();
        let upstream_task = tokio::spawn(async move {
            let (stream, _) = upstream_listener.accept().await.unwrap();
            let service = service_fn(|mut request: Request<Incoming>| async move {
                assert!(is_websocket_upgrade(request.headers()));
                let upgraded = hyper::upgrade::on(&mut request);
                tokio::spawn(async move {
                    let upgraded = upgraded.await.unwrap();
                    let mut stream = hyper_util::rt::TokioIo::new(upgraded);
                    let mut bytes = vec![0_u8; b"opaque-voice-frame".len()];
                    stream.read_exact(&mut bytes).await.unwrap();
                    stream.write_all(&bytes).await.unwrap();
                });
                Ok::<_, Infallible>(
                    Response::builder()
                        .status(StatusCode::SWITCHING_PROTOCOLS)
                        .header(hyper::header::CONNECTION, "Upgrade")
                        .header(hyper::header::UPGRADE, "websocket")
                        .body(Empty::<Bytes>::new())
                        .unwrap(),
                )
            });
            http1::Builder::new()
                .serve_connection(hyper_util::rt::TokioIo::new(stream), service)
                .with_upgrades()
                .await
                .unwrap();
        });

        let proxy_listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
        let proxy_address = proxy_listener.local_addr().unwrap();
        let upstream_url =
            format!("http://{upstream_address}/api/ws/voice/organizations/o/chat_conversations/c");
        let proxy_task = tokio::spawn(async move {
            let (stream, _) = proxy_listener.accept().await.unwrap();
            let client = reqwest::Client::builder().no_proxy().build().unwrap();
            let connections = Arc::new(tokio::sync::Semaphore::new(1));
            let service = service_fn(move |request| {
                let client = client.clone();
                let upstream_url = upstream_url.clone();
                let connections = Arc::clone(&connections);
                async move {
                    let response = forward_websocket_upgrade(
                        request,
                        &client,
                        upstream_url,
                        "claude.ai",
                        "/api/ws/voice/:id/chat_conversations/:id",
                        connections,
                    )
                    .await
                    .unwrap();
                    Ok::<_, Infallible>(response)
                }
            });
            http1::Builder::new()
                .serve_connection(hyper_util::rt::TokioIo::new(stream), service)
                .with_upgrades()
                .await
                .unwrap();
        });

        let mut client = tokio::net::TcpStream::connect(proxy_address).await.unwrap();
        client
            .write_all(
                concat!(
                    "GET /api/ws/voice/organizations/o/chat_conversations/c HTTP/1.1\r\n",
                    "Host: claude.ai\r\n",
                    "Connection: Upgrade\r\n",
                    "Upgrade: websocket\r\n",
                    "Sec-WebSocket-Version: 13\r\n",
                    "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n",
                    "\r\n"
                )
                .as_bytes(),
            )
            .await
            .unwrap();
        let mut response_head = Vec::new();
        while !response_head.ends_with(b"\r\n\r\n") {
            response_head.push(client.read_u8().await.unwrap());
        }
        let response_head = String::from_utf8(response_head).unwrap();
        assert!(response_head.starts_with("HTTP/1.1 101"), "{response_head}");

        client.write_all(b"opaque-voice-frame").await.unwrap();
        let mut echoed = vec![0_u8; b"opaque-voice-frame".len()];
        client.read_exact(&mut echoed).await.unwrap();
        assert_eq!(echoed, b"opaque-voice-frame");
        drop(client);

        tokio::time::timeout(Duration::from_secs(5), proxy_task)
            .await
            .unwrap()
            .unwrap();
        tokio::time::timeout(Duration::from_secs(5), upstream_task)
            .await
            .unwrap()
            .unwrap();
    }

    #[test]
    fn only_known_claude_upload_routes_are_rewritten() {
        for path in [
            "/api/org/upload",
            "/api/organizations/org/projects/project/upload",
            "/api/organizations/org/cowork/attachments",
            "/v1/filestore/fs/createFile",
        ] {
            assert_eq!(
                classify_claude_app_request(
                    &Method::POST,
                    "claude.ai",
                    path,
                    "multipart/form-data; boundary=test"
                ),
                ClaudeAppRequest::Upload,
                "{path}"
            );
        }
        for path in ["/upload", "/api/organizations/org/dxt/upload"] {
            assert_eq!(
                classify_claude_app_request(
                    &Method::POST,
                    "claude.ai",
                    path,
                    "multipart/form-data; boundary=test"
                ),
                ClaudeAppRequest::Other,
                "{path}"
            );
        }
        assert_eq!(
            classify_claude_app_request(
                &Method::POST,
                "claude.ai",
                "/api/organizations/org/conversations/conversation/files/prepare-upload",
                "application/json"
            ),
            ClaudeAppRequest::PrepareUploadJson
        );
    }

    #[test]
    fn malformed_chat_json_obeys_the_unknown_format_policy() {
        let body = Bytes::from_static(b"{not-json");
        assert!(parse_chat_json(&body, true)
            .unwrap_err()
            .starts_with("unknown format blocked:"));
        assert!(parse_chat_json(&body, false).unwrap().is_none());
    }

    #[test]
    fn chat_request_masks_content_without_rewriting_protocol_metadata() {
        let _lock = crate::TEST_PROCESS_ENV_LOCK.lock().unwrap();
        let store = pentect_agent::start_in_process_memory_store().unwrap();
        let _env = MaskingTestEnv::install(&store);
        let secret = [
            "rpa_",
            "ZYXWVUTS",
            "RQPONMLK",
            "JIHGFEDC",
            "BA098765",
            "4321fedcba",
        ]
        .concat();
        let body = Bytes::from(
            serde_json::to_vec(&serde_json::json!({
                "model": "claude-test-model",
                "organization_uuid": "11111111-2222-3333-4444-555555555555",
                "prompt": format!("Use this value:\nRUNPOD_API_KEY={secret}\n"),
                "future_instructions": format!(
                    "A future field contains RUNPOD_API_KEY={secret}"
                ),
                "messages": [{"content": [{
                    "type": "tool_result",
                    "tool_use_id": "tool-stable-id",
                    "content": {"token": secret, "status": "ok"}
                }, {
                    "type": "tool_use",
                    "name": "configure_service",
                    "input": {
                        "token": secret,
                        "authorization": secret,
                        "id": secret,
                        "name": secret
                    }
                }]}],
                "client_context": {"locale": "ja-JP", "revision": 7}
            }))
            .unwrap(),
        );
        let masker = Mutex::new(pentect_agent::ActiveToolOutputMasker::new().unwrap());
        let plugins = Mutex::new(pentect_agent::PluginMiddleware::default());
        let protected =
            protect_chat_request(&body, &masker, &plugins, &HashMap::new(), true).unwrap();
        let value: serde_json::Value = serde_json::from_slice(&protected.body).unwrap();
        let prompt = value["prompt"].as_str().unwrap();
        assert!(!prompt.contains(&secret));
        assert!(prompt.contains("<<"));
        assert!(prompt.contains(HANDLE_CONTRACT));
        assert!(!value["future_instructions"]
            .as_str()
            .unwrap()
            .contains(&secret));
        assert_eq!(value["model"], "claude-test-model");
        assert_eq!(
            value["organization_uuid"],
            "11111111-2222-3333-4444-555555555555"
        );
        assert_eq!(value["client_context"]["revision"], 7);
        assert_eq!(
            value["messages"][0]["content"][0]["tool_use_id"],
            "tool-stable-id"
        );
        assert_ne!(
            value["messages"][0]["content"][0]["content"]["token"],
            secret
        );
        let tool_input = &value["messages"][0]["content"][1]["input"];
        for key in ["token", "authorization", "id", "name"] {
            let protected = tool_input[key].as_str().unwrap();
            assert!(!protected.contains(&secret), "{key} was not protected");
            assert!(protected.contains("<<"), "{key} has no handle");
        }

        let telemetry = Bytes::from(
            serde_json::to_vec(&serde_json::json!({
                "event": "client-error",
                "detail": format!("accidentally captured:\nRUNPOD_API_KEY={secret}\n")
            }))
            .unwrap(),
        );
        let protected = protect_generic_json_request(&telemetry, &masker, true).unwrap();
        assert!(!String::from_utf8_lossy(&protected).contains(&secret));
    }

    #[test]
    fn generic_json_preserves_only_top_level_auth_fields() {
        let _lock = crate::TEST_PROCESS_ENV_LOCK.lock().unwrap();
        let store = pentect_agent::start_in_process_memory_store().unwrap();
        let _env = MaskingTestEnv::install(&store);
        let secret = [
            "rpa_",
            "ZYXWVUTS",
            "RQPONMLK",
            "JIHGFEDC",
            "BA098765",
            "4321fedcba",
        ]
        .concat();
        let keyed_secret = format!("RUNPOD_API_KEY={secret}");
        let body = Bytes::from(
            serde_json::to_vec(&serde_json::json!({
                "token": keyed_secret,
                "authorization": keyed_secret,
                "event": {
                    "token": keyed_secret,
                    "authorization": keyed_secret,
                }
            }))
            .unwrap(),
        );
        let masker = Mutex::new(pentect_agent::ActiveToolOutputMasker::new().unwrap());
        let protected = protect_generic_json_request(&body, &masker, true).unwrap();
        let value: serde_json::Value = serde_json::from_slice(&protected).unwrap();

        assert_eq!(value["token"], keyed_secret);
        assert_eq!(value["authorization"], keyed_secret);
        for key in ["token", "authorization"] {
            let nested = value["event"][key].as_str().unwrap();
            assert!(!nested.contains(&secret), "nested {key} was not protected");
            assert!(nested.contains("<<"), "nested {key} has no handle");
        }
    }

    #[test]
    fn uploaded_file_ids_are_registered_without_trusting_unrelated_ids() {
        let ids = uploaded_claude_file_ids(
            br#"{"id":"organization-id","nested":{"file_uuid":"file-123","filename":"other.txt"},"file":{"id":"file-456","type":"file","filename":"a.txt"}}"#,
            "a.txt",
        );
        assert_eq!(ids, ["file-456"]);
    }

    #[test]
    fn direct_upload_preparation_is_promoted_only_after_the_file_is_protected() {
        let content_type = "multipart/form-data; boundary=pentect-test";
        let body = concat!(
            "--pentect-test\r\n",
            "Content-Disposition: form-data; name=\"params\"\r\n",
            "Content-Type: application/json\r\n\r\n",
            "{\"filesystem_id\":\"fs-1\",\"path\":\"/uploads/a.txt\"}\r\n",
            "--pentect-test\r\n",
            "Content-Disposition: form-data; name=\"file\"; filename=\"a.txt\"\r\n",
            "Content-Type: text/plain\r\n\r\n",
            "hello\r\n",
            "--pentect-test--\r\n"
        );
        let key = claude_filestore_upload_key(content_type, body.as_bytes()).unwrap();
        let pending = Mutex::new(PendingFiles::default());
        remember_pending_claude_files(
            br#"{"uploads":[{"filesystem_id":"fs-1","path":"/uploads/a.txt","file_uuid":"file-1"}]}"#,
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            &pending,
        )
        .unwrap();
        let promoted = promote_pending_claude_files(
            &key,
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            &pending,
        )
        .unwrap();
        assert_eq!(promoted, ["file-1"]);
    }

    #[test]
    fn pending_upload_eviction_keeps_the_newest_correlations() {
        let pending = Mutex::new(PendingFiles::default());
        for index in 0..=MAX_PENDING_UPLOADS {
            let body = serde_json::to_vec(&serde_json::json!({
                "uploads": [{
                    "filesystem_id": "fs",
                    "path": format!("/{index}.txt"),
                    "file_uuid": format!("file-{index}")
                }]
            }))
            .unwrap();
            remember_pending_claude_files(
                &body,
                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                &pending,
            )
            .unwrap();
        }
        let pending = pending.lock().unwrap();
        assert_eq!(pending.entries.len(), MAX_PENDING_UPLOADS);
        assert!(!pending.entries.contains_key(&scoped_pending_key(
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "fs\0/0.txt",
        )));
        assert!(pending.entries.contains_key(&scoped_pending_key(
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            &format!("fs\0/{MAX_PENDING_UPLOADS}.txt"),
        )));
    }

    #[test]
    fn completed_tool_calls_restore_nested_inputs_but_normal_text_stays_opaque() {
        let handle = "<<SECRET_0011223344556677>>";
        let mut value = serde_json::json!({
            "content": [
                {"type": "text", "text": format!("show {handle}")},
                {"type": "tool_use", "name": "http", "input": {
                    "headers": {"x-token": handle},
                    "body": [handle]
                }}
            ]
        });
        let mut resolve = |text: &str| Ok(text.replace(handle, "local-value"));
        resolve_chat_tool_calls(&mut value, &mut resolve).unwrap();
        assert_eq!(value["content"][0]["text"], format!("show {handle}"));
        assert_eq!(
            value["content"][1]["input"]["headers"]["x-token"],
            "local-value"
        );
        assert_eq!(value["content"][1]["input"]["body"][0], "local-value");
    }

    #[test]
    fn chat_contract_is_added_when_request_has_no_prompt_field() {
        let mut value = serde_json::json!({"messages": []});
        inject_chat_contract(&mut value);
        assert_eq!(value["system"], HANDLE_CONTRACT);
    }

    #[test]
    fn metadata_paths_hide_identifiers_and_long_segments() {
        assert_eq!(
            metadata_path(
                "/api/organizations/d65b35c5-7372-4d95-805b-6e59d6b07e24/chat_conversations"
            ),
            "/api/organizations/:id/chat_conversations"
        );
        assert_eq!(
            metadata_path("/cdn-cgi/challenge/abcdefghijklmnopqrstuvwxyz0123456789AB"),
            "/cdn-cgi/challenge/:id"
        );
        assert_eq!(
            metadata_path("/v1/code/sessions/cse_01Ni2WadyEAmYhNEa9JK4hLH/events"),
            "/v1/code/sessions/:id/events"
        );
    }

    #[test]
    fn nonstream_chat_response_runs_tool_and_output_restoration() {
        let handle = "<<SECRET_0011223344556677>>";
        let body = Bytes::from(
            serde_json::to_vec(&serde_json::json!({
                "content": [
                    {"type": "text", "text": format!("show {handle}")},
                    {"type": "tool_use", "name": "http", "input": {
                        "headers": {"x-token": handle}
                    }}
                ]
            }))
            .unwrap(),
        );
        let plugins = Mutex::new(pentect_agent::PluginMiddleware::default());
        let mut resolve = |text: &str| Ok(text.replace(handle, "local-value"));
        let rewritten =
            rewrite_chat_json_response_with(&body, &plugins, true, true, &mut resolve).unwrap();
        let value: serde_json::Value = serde_json::from_slice(&rewritten).unwrap();
        assert_eq!(value["content"][0]["text"], "show local-value");
        assert_eq!(
            value["content"][1]["input"]["headers"]["x-token"],
            "local-value"
        );
    }

    #[test]
    fn proxy_removes_standard_and_connection_named_hop_headers() {
        let mut headers = hyper::HeaderMap::new();
        headers.insert(
            hyper::header::CONNECTION,
            hyper::header::HeaderValue::from_static("keep-alive, x-private-hop"),
        );
        headers.insert(
            hyper::header::HeaderName::from_static("x-private-hop"),
            hyper::header::HeaderValue::from_static("remove"),
        );
        headers.insert(
            hyper::header::HeaderName::from_static("x-end-to-end"),
            hyper::header::HeaderValue::from_static("keep"),
        );
        remove_hop_by_hop_headers(&mut headers);
        assert!(!headers.contains_key(hyper::header::CONNECTION));
        assert!(!headers.contains_key("x-private-hop"));
        assert_eq!(headers["x-end-to-end"], "keep");
    }

    #[test]
    fn ephemeral_ca_builds_host_certificate() {
        let authority = CertificateAuthority::new().unwrap();
        #[cfg(not(windows))]
        assert!(!authority.spki_hash.is_empty());
        #[cfg(windows)]
        {
            assert_eq!(authority.thumbprint.len(), 40);
            assert!(authority
                .thumbprint
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit()));
            assert!(!authority.issuer.der().is_empty());
        }
        authority.server_config("claude.ai").unwrap();
    }

    #[cfg(windows)]
    #[test]
    fn windows_ca_journal_accepts_only_sha1_thumbprints() {
        let thumbprint = "00112233445566778899AABBCCDDEEFF00112233";
        assert!(validate_ca_thumbprint(thumbprint).is_ok());
        let current = parse_windows_ca_journal(&format!("{thumbprint}\n1234\n")).unwrap();
        assert_eq!(current.owner, Some(1234));
        let legacy = parse_windows_ca_journal(thumbprint).unwrap();
        assert_eq!(legacy.owner, None);
        assert!(parse_windows_ca_journal(&format!("{thumbprint}\n1234\nextra")).is_err());
        for invalid in [
            "",
            "0011",
            "00112233445566778899AABBCCDDEEFF0011223G",
            "00112233445566778899AABBCCDDEEFF00112233 --force",
        ] {
            assert!(validate_ca_thumbprint(invalid).is_err(), "{invalid}");
        }
    }

    #[cfg(windows)]
    fn assert_windows_ca_visibility_in_fresh_process(thumbprint: &str, expected: bool) {
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--ignored",
                "--exact",
                "claude_app_proxy::tests::windows_user_ca_presence_probe",
                "--nocapture",
            ])
            .env("PENTECT_TEST_WINDOWS_CA_THUMBPRINT", thumbprint)
            .env(
                "PENTECT_TEST_WINDOWS_CA_EXPECTED",
                if expected { "1" } else { "0" },
            )
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "fresh-process CA visibility probe failed:\nstdout:\n{}\nstderr:\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }

    #[cfg(windows)]
    #[test]
    #[ignore = "helper launched by windows_user_ca_round_trip"]
    fn windows_user_ca_presence_probe() {
        let thumbprint = std::env::var("PENTECT_TEST_WINDOWS_CA_THUMBPRINT").unwrap();
        let expected = std::env::var("PENTECT_TEST_WINDOWS_CA_EXPECTED").unwrap() == "1";
        assert_eq!(windows_user_ca_present(&thumbprint).unwrap(), expected);
    }

    #[cfg(windows)]
    fn remove_windows_test_ca_store(name: &str) {
        use windows::Win32::Security::Cryptography::{
            CertUnregisterSystemStore, CERT_SYSTEM_STORE_CURRENT_USER,
        };

        let name = windows::core::HSTRING::from(name);
        let removed = unsafe {
            CertUnregisterSystemStore(
                name.as_ptr() as *const std::ffi::c_void,
                CERT_SYSTEM_STORE_CURRENT_USER,
            )
        };
        assert!(removed.as_bool(), "could not remove temporary test store");
    }

    #[cfg(windows)]
    #[test]
    #[ignore = "mutates an ephemeral current-user certificate test store"]
    fn windows_user_ca_round_trip() {
        use std::sync::atomic::{AtomicBool, Ordering};

        let finished = Arc::new(AtomicBool::new(false));
        let watchdog = Arc::clone(&finished);
        std::thread::spawn(move || {
            for _ in 0..300 {
                std::thread::sleep(Duration::from_millis(100));
                if watchdog.load(Ordering::Relaxed) {
                    return;
                }
            }
            eprintln!("windows CA round trip exceeded 30 seconds");
            std::process::abort();
        });
        let _lock = crate::TEST_PROCESS_ENV_LOCK.lock().unwrap();
        let previous = std::env::var_os("LOCALAPPDATA");
        let state = std::env::temp_dir().join(format!(
            "pentect-claude-ca-round-trip-{}",
            std::process::id()
        ));
        std::fs::create_dir_all(&state).unwrap();
        std::env::set_var("LOCALAPPDATA", &state);
        let previous_store = std::env::var_os("PENTECT_TEST_WINDOWS_CA_STORE");
        let store_name = format!("PentectClaudeCaTest-{}", std::process::id());
        std::env::set_var("PENTECT_TEST_WINDOWS_CA_STORE", &store_name);

        let authority = CertificateAuthority::new().unwrap();
        eprintln!("windows CA round trip: checking initial absence");
        assert!(!windows_user_ca_present(&authority.thumbprint).unwrap());
        eprintln!("windows CA round trip: installing");
        let guard =
            WindowsUserCaGuard::install(authority.issuer.der(), &authority.thumbprint).unwrap();
        eprintln!("windows CA round trip: checking presence from a fresh process");
        assert_windows_ca_visibility_in_fresh_process(&authority.thumbprint, true);
        assert!(windows_ca_journal_path().unwrap().is_file());
        assert!(!windows_ca_cleanup_pending().unwrap());
        cleanup_stale_windows_user_ca().unwrap();
        assert_windows_ca_visibility_in_fresh_process(&authority.thumbprint, true);
        assert!(windows_ca_journal_path().unwrap().is_file());
        eprintln!("windows CA round trip: removing");
        drop(guard);
        eprintln!("windows CA round trip: checking final absence from a fresh process");
        assert_windows_ca_visibility_in_fresh_process(&authority.thumbprint, false);
        assert!(!windows_ca_cleanup_pending().unwrap());

        // An upgrade can leave a stale legacy journal while a newer session is
        // active. Cleanup must remove only the stale certificate and preserve
        // the active session's certificate and journal.
        let legacy_authority = CertificateAuthority::new().unwrap();
        let legacy_guard = WindowsUserCaGuard::install(
            legacy_authority.issuer.der(),
            &legacy_authority.thumbprint,
        )
        .unwrap();
        std::fs::rename(
            windows_ca_journal_path().unwrap(),
            legacy_windows_ca_journal_path().unwrap(),
        )
        .unwrap();
        let current_authority = CertificateAuthority::new().unwrap();
        let current_guard = WindowsUserCaGuard::install(
            current_authority.issuer.der(),
            &current_authority.thumbprint,
        )
        .unwrap();
        std::fs::write(
            legacy_windows_ca_journal_path().unwrap(),
            &legacy_authority.thumbprint,
        )
        .unwrap();
        std::mem::forget(legacy_guard);

        assert_windows_ca_visibility_in_fresh_process(&legacy_authority.thumbprint, true);
        assert_windows_ca_visibility_in_fresh_process(&current_authority.thumbprint, true);
        assert!(windows_ca_cleanup_pending().unwrap());
        cleanup_stale_windows_user_ca().unwrap();
        assert_windows_ca_visibility_in_fresh_process(&legacy_authority.thumbprint, false);
        assert_windows_ca_visibility_in_fresh_process(&current_authority.thumbprint, true);
        assert!(!legacy_windows_ca_journal_path().unwrap().exists());
        assert!(windows_ca_journal_path().unwrap().exists());
        assert!(!windows_ca_cleanup_pending().unwrap());
        drop(current_guard);
        assert_windows_ca_visibility_in_fresh_process(&current_authority.thumbprint, false);
        assert!(!windows_ca_journal_path().unwrap().exists());
        remove_windows_test_ca_store(&store_name);

        match previous {
            Some(value) => std::env::set_var("LOCALAPPDATA", value),
            None => std::env::remove_var("LOCALAPPDATA"),
        }
        match previous_store {
            Some(value) => std::env::set_var("PENTECT_TEST_WINDOWS_CA_STORE", value),
            None => std::env::remove_var("PENTECT_TEST_WINDOWS_CA_STORE"),
        }
        let _ = std::fs::remove_dir_all(state);
        finished.store(true, Ordering::Relaxed);
    }

    #[cfg(windows)]
    #[test]
    fn windows_package_versions_sort_numerically() {
        assert!(
            windows_package_version("Claude_1.10.0.0_x64__id")
                > windows_package_version("Claude_1.9.99.0_x64__id")
        );
        assert!(windows_package_matches_arch(
            if cfg!(target_arch = "aarch64") {
                "Claude_1.10.0.0_arm64__id"
            } else {
                "Claude_1.10.0.0_x64__id"
            }
        ));
    }

    #[cfg(windows)]
    #[test]
    fn appx_manifest_builds_the_claude_aumid() {
        let root =
            std::env::temp_dir().join(format!("pentect-claude-appx-test-{}", std::process::id()));
        let app = root.join("app");
        std::fs::create_dir_all(&app).unwrap();
        std::fs::write(app.join("Claude.exe"), b"fixture").unwrap();
        std::fs::write(
            root.join("AppxManifest.xml"),
            br#"<Package><Applications><Application Id="Claude" Executable="app\Claude.exe" /></Applications></Package>"#,
        )
        .unwrap();
        assert_eq!(
            windows_package_aumid(
                "Claude_1.34493.1.0_x64__publisher123",
                &app.join("Claude.exe")
            )
            .unwrap(),
            "Claude_publisher123!Claude"
        );
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn activation_arguments_quote_paths_with_spaces() {
        assert_eq!(quote_windows_argument("--flag=value"), "--flag=value");
        assert_eq!(quote_windows_argument(""), "\"\"");
        assert_eq!(
            quote_windows_argument("--user-data-dir=C:\\Users\\Test User\\Claude"),
            "\"--user-data-dir=C:\\Users\\Test User\\Claude\""
        );
        assert_eq!(
            quote_windows_argument(r#"--settings={"theme": "dark"}"#),
            r#""--settings={\"theme\": \"dark\"}""#
        );
        assert_eq!(
            quote_windows_argument("--value=C:\\path\\\\\"quoted value\"\\"),
            "\"--value=C:\\path\\\\\\\\\\\"quoted value\\\"\\\\\""
        );
    }

    #[cfg(windows)]
    #[test]
    fn activation_arguments_round_trip_through_windows_parser() {
        use windows::core::PCWSTR;
        use windows::Win32::Foundation::{LocalFree, HLOCAL};
        use windows::Win32::UI::Shell::CommandLineToArgvW;

        for expected in [
            "",
            "--flag=value",
            "--user-data-dir=C:\\Users\\Test User\\Claude\\",
            r#"--settings={"theme": "dark"}"#,
            "--value=C:\\path\\\\\"quoted value\"\\",
        ] {
            let command = wide_null(&format!("program.exe {}", quote_windows_argument(expected)));
            let mut count = 0;
            let arguments = unsafe { CommandLineToArgvW(PCWSTR(command.as_ptr()), &mut count) };
            assert!(!arguments.is_null());
            assert_eq!(count, 2, "argument was split: {expected}");
            let actual = unsafe { (*arguments.add(1)).to_string().unwrap() };
            unsafe {
                let _ = LocalFree(Some(HLOCAL(arguments.cast())));
            }
            assert_eq!(actual, expected);
        }
    }
}

//! Process-local routing for OpenAI-compatible clients whose native
//! configuration cannot be expressed by the shared launcher families alone.

use std::ffi::{OsStr, OsString};
use std::path::PathBuf;
use std::process::Command;
use zeroize::Zeroize;

pub(crate) const JUNIE_API_KEY_ENV: &str = "PENTECT_JUNIE_API_KEY";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum OpenAiWireApi {
    ChatCompletions,
    Responses,
}

impl OpenAiWireApi {
    fn endpoint(self) -> &'static str {
        match self {
            Self::ChatCompletions => "v1/chat/completions",
            Self::Responses => "v1/responses",
        }
    }

    fn junie_name(self) -> &'static str {
        match self {
            Self::ChatCompletions => "OpenAICompletion",
            Self::Responses => "OpenAIResponses",
        }
    }
}

/// Force every Goose model role documented by Goose through the same
/// process-local OpenAI-compatible endpoint. Environment variables override
/// Goose's persisted configuration and disappear with the child process.
pub(crate) fn configure_goose(
    command: &mut Command,
    proxy_base_url: &str,
    model: &str,
    api_key: &OsStr,
) {
    command
        .env("GOOSE_PROVIDER", "openai")
        .env("GOOSE_PROVIDER__TYPE", "openai")
        .env("GOOSE_PROVIDER__HOST", proxy_base_url)
        .env("GOOSE_PROVIDER__API_KEY", api_key)
        .env("GOOSE_MODEL", model)
        .env("GOOSE_FAST_MODEL", model)
        .env("GOOSE_PLANNER_PROVIDER", "openai")
        .env("GOOSE_PLANNER_MODEL", model);
}

/// A Junie custom-model profile stored in a random, short-lived directory.
/// The profile contains only the local gateway URL and an environment-variable
/// reference. The upstream credential is never serialized.
#[derive(Debug)]
pub(crate) struct JunieModelProfile {
    directory: PathBuf,
    _file: crate::secure_temp::SecureTempFile,
    profile_id: String,
}

impl JunieModelProfile {
    pub(crate) fn create(
        proxy_base_url: &str,
        model: &str,
        api: OpenAiWireApi,
    ) -> Result<Self, String> {
        let directory = create_private_directory()?;
        let endpoint = format!(
            "{}/{}",
            proxy_base_url.trim_end_matches('/'),
            api.endpoint()
        );
        let contents = serde_json::to_vec(&serde_json::json!({
            "id": model,
            "baseUrl": endpoint,
            "apiType": api.junie_name(),
            "apiKey": format!("${{{JUNIE_API_KEY_ENV}}}"),
        }))
        .map_err(|error| format!("could not encode temporary Junie model profile: {error}"))?;
        let file = match crate::secure_temp::SecureTempFile::create(
            &directory,
            "pentect-",
            ".json",
            &contents,
            "Junie model profile",
        ) {
            Ok(file) => file,
            Err(error) => {
                let _ = std::fs::remove_dir_all(&directory);
                return Err(error);
            }
        };
        let profile_id = file
            .path()
            .file_stem()
            .and_then(OsStr::to_str)
            .ok_or_else(|| "temporary Junie profile name is not UTF-8".to_string())?
            .to_string();
        Ok(Self {
            directory,
            _file: file,
            profile_id,
        })
    }

    pub(crate) fn apply(&self, command: &mut Command, api_key: &OsStr) {
        command.env(JUNIE_API_KEY_ENV, api_key);
        // Appended after caller arguments so a user-supplied model cannot
        // select an endpoint outside Pentect for this launch.
        command.args([
            OsString::from("--model-location"),
            self.directory.as_os_str().to_owned(),
            OsString::from("--model"),
            OsString::from(format!("custom:{}", self.profile_id)),
        ]);
    }

    #[cfg(test)]
    fn path(&self) -> &std::path::Path {
        self._file.path()
    }
}

impl Drop for JunieModelProfile {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.directory);
    }
}

fn create_private_directory() -> Result<PathBuf, String> {
    let mut nonce = [0_u8; 16];
    getrandom::getrandom(&mut nonce)
        .map_err(|error| format!("OS CSPRNG unavailable for Junie profile: {error}"))?;
    let name = format!(
        "pentect-junie-{}-{}",
        std::process::id(),
        data_encoding::HEXLOWER.encode(&nonce)
    );
    nonce.zeroize();
    let directory = std::env::temp_dir().join(name);
    #[cfg(unix)]
    let builder = {
        use std::os::unix::fs::DirBuilderExt;
        let mut builder = std::fs::DirBuilder::new();
        builder.mode(0o700);
        builder
    };
    #[cfg(not(unix))]
    let builder = std::fs::DirBuilder::new();
    builder
        .create(&directory)
        .map_err(|error| format!("could not create temporary Junie profile directory: {error}"))?;
    if let Err(error) = crate::secure_temp::restrict_to_current_user(&directory) {
        let _ = std::fs::remove_dir(&directory);
        return Err(error);
    }
    Ok(directory)
}

#[cfg(test)]
mod tests {
    use super::*;

    const SYNTHETIC_KEY: &str = "sk-test-never-valid-AKIAIOSFODNN7EXAMPLE";

    fn command_env(command: &Command, name: &str) -> Option<OsString> {
        command.get_envs().find_map(|(key, value)| {
            (key == OsStr::new(name))
                .then(|| value.map(OsStr::to_owned))
                .flatten()
        })
    }

    #[test]
    fn goose_overrides_main_fast_and_planner_routes_without_writing_config() {
        let mut command = Command::new("goose");
        configure_goose(
            &mut command,
            "http://127.0.0.1:43123/random",
            "gpt-test",
            OsStr::new(SYNTHETIC_KEY),
        );
        assert_eq!(command_env(&command, "GOOSE_PROVIDER").unwrap(), "openai");
        assert_eq!(
            command_env(&command, "GOOSE_PROVIDER__HOST").unwrap(),
            "http://127.0.0.1:43123/random"
        );
        assert_eq!(command_env(&command, "GOOSE_MODEL").unwrap(), "gpt-test");
        assert_eq!(
            command_env(&command, "GOOSE_FAST_MODEL").unwrap(),
            "gpt-test"
        );
        assert_eq!(
            command_env(&command, "GOOSE_PLANNER_PROVIDER").unwrap(),
            "openai"
        );
        assert_eq!(
            command_env(&command, "GOOSE_PROVIDER__API_KEY").unwrap(),
            SYNTHETIC_KEY
        );
    }

    #[test]
    fn junie_profile_uses_full_chat_endpoint_and_env_reference() {
        let profile = JunieModelProfile::create(
            "http://127.0.0.1:43123/random/",
            "gpt-test",
            OpenAiWireApi::ChatCompletions,
        )
        .unwrap();
        let value: serde_json::Value =
            serde_json::from_slice(&std::fs::read(profile.path()).unwrap()).unwrap();
        assert_eq!(
            value["baseUrl"],
            "http://127.0.0.1:43123/random/v1/chat/completions"
        );
        assert_eq!(value["apiType"], "OpenAICompletion");
        assert_eq!(value["id"], "gpt-test");
        assert_eq!(value["apiKey"], "${PENTECT_JUNIE_API_KEY}");
        assert!(
            !String::from_utf8_lossy(&std::fs::read(profile.path()).unwrap())
                .contains(SYNTHETIC_KEY)
        );
    }

    #[test]
    fn junie_profile_supports_responses_and_is_removed_on_drop() {
        let profile = JunieModelProfile::create(
            "http://127.0.0.1:43123/random",
            "gpt-test",
            OpenAiWireApi::Responses,
        )
        .unwrap();
        let directory = profile.directory.clone();
        let value: serde_json::Value =
            serde_json::from_slice(&std::fs::read(profile.path()).unwrap()).unwrap();
        assert_eq!(
            value["baseUrl"],
            "http://127.0.0.1:43123/random/v1/responses"
        );
        assert_eq!(value["apiType"], "OpenAIResponses");
        drop(profile);
        assert!(!directory.exists());
    }

    #[test]
    fn junie_appends_protected_model_selection_and_keeps_key_out_of_arguments() {
        let profile = JunieModelProfile::create(
            "http://127.0.0.1:43123/random",
            "gpt-test",
            OpenAiWireApi::ChatCompletions,
        )
        .unwrap();
        let mut command = Command::new("junie");
        command.arg("--task").arg("inspect this repository");
        profile.apply(&mut command, OsStr::new(SYNTHETIC_KEY));
        let args = command
            .get_args()
            .map(|arg| arg.to_string_lossy().into_owned())
            .collect::<Vec<_>>();
        assert_eq!(args[0..2], ["--task", "inspect this repository"]);
        assert_eq!(args[2], "--model-location");
        assert_eq!(args[4], "--model");
        assert!(args[5].starts_with("custom:pentect-"));
        assert!(!args.iter().any(|arg| arg.contains(SYNTHETIC_KEY)));
        assert_eq!(
            command_env(&command, JUNIE_API_KEY_ENV).unwrap(),
            SYNTHETIC_KEY
        );
    }

    #[cfg(unix)]
    #[test]
    fn junie_profile_directory_and_file_are_owner_only() {
        use std::os::unix::fs::PermissionsExt;

        let profile = JunieModelProfile::create(
            "http://127.0.0.1:43123/random",
            "gpt-test",
            OpenAiWireApi::ChatCompletions,
        )
        .unwrap();
        assert_eq!(
            std::fs::metadata(&profile.directory)
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o700
        );
        assert_eq!(
            std::fs::metadata(profile.path())
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
    }
}

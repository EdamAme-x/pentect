//! Static metadata for supported AI clients.
//!
//! Launch-time behavior remains in the protocol-specific launchers. Keeping
//! names, executable overrides and supported routing options here makes adding
//! a client a data change instead of spreading string matches across the CLI.

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Protocol {
    OpenAi,
    Anthropic,
    CloudCode,
    Gemini,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Launcher {
    CodexConfig,
    ClaudeSettings,
    OpenAi(OpenAiInjection),
    EndpointEnv,
    Ide(crate::ide_clients::IdeClient),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum OpenAiInjection {
    InlineConfig,
    TempExtension,
    ForcedArgs,
    GooseEnv,
    JunieProfile,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ClientDescriptor {
    pub(crate) name: &'static str,
    pub(crate) aliases: &'static [&'static str],
    pub(crate) default_command: &'static str,
    pub(crate) path_flag: &'static str,
    pub(crate) protocol: Protocol,
    pub(crate) launcher: Launcher,
    pub(crate) accepts_model: bool,
    pub(crate) accepts_api: bool,
    pub(crate) upstream_env: &'static [&'static str],
    pub(crate) default_upstream: Option<&'static str>,
}

pub(crate) const CODEX: ClientDescriptor = ClientDescriptor {
    name: "codex",
    aliases: &[],
    default_command: "codex",
    path_flag: "--codex",
    protocol: Protocol::OpenAi,
    launcher: Launcher::CodexConfig,
    accepts_model: false,
    accepts_api: false,
    upstream_env: &["OPENAI_BASE_URL"],
    default_upstream: None,
};

pub(crate) const CLAUDE: ClientDescriptor = ClientDescriptor {
    name: "claude",
    aliases: &[],
    default_command: "claude",
    path_flag: "--claude",
    protocol: Protocol::Anthropic,
    launcher: Launcher::ClaudeSettings,
    accepts_model: false,
    accepts_api: false,
    upstream_env: &["ANTHROPIC_BASE_URL"],
    default_upstream: None,
};

pub(crate) const OPENCODE: ClientDescriptor = ClientDescriptor {
    name: "opencode",
    aliases: &[],
    default_command: "opencode",
    path_flag: "--opencode",
    protocol: Protocol::OpenAi,
    launcher: Launcher::OpenAi(OpenAiInjection::InlineConfig),
    accepts_model: true,
    accepts_api: true,
    upstream_env: &["OPENAI_BASE_URL"],
    default_upstream: Some("https://api.openai.com/v1"),
};

pub(crate) const PI: ClientDescriptor = ClientDescriptor {
    name: "pi",
    aliases: &[],
    default_command: "pi",
    path_flag: "--pi",
    protocol: Protocol::OpenAi,
    launcher: Launcher::OpenAi(OpenAiInjection::TempExtension),
    accepts_model: true,
    accepts_api: true,
    upstream_env: &["OPENAI_BASE_URL"],
    default_upstream: Some("https://api.openai.com/v1"),
};

pub(crate) const ANTIGRAVITY: ClientDescriptor = ClientDescriptor {
    name: "antigravity",
    aliases: &["agy"],
    default_command: "agy",
    path_flag: "--agy",
    protocol: Protocol::CloudCode,
    launcher: Launcher::EndpointEnv,
    accepts_model: false,
    accepts_api: false,
    upstream_env: &["CLOUD_CODE_URL"],
    default_upstream: Some("https://daily-cloudcode-pa.googleapis.com"),
};

pub(crate) const AIDER: ClientDescriptor = ClientDescriptor {
    name: "aider",
    aliases: &[],
    default_command: "aider",
    path_flag: "--aider",
    protocol: Protocol::OpenAi,
    launcher: Launcher::OpenAi(OpenAiInjection::ForcedArgs),
    accepts_model: true,
    accepts_api: false,
    // OPENAI_API_BASE is Aider's documented compatible-provider setting.
    // AIDER_OPENAI_API_BASE is the generated CLI option environment alias.
    upstream_env: &[
        "AIDER_OPENAI_API_BASE",
        "OPENAI_API_BASE",
        "OPENAI_BASE_URL",
    ],
    default_upstream: Some("https://api.openai.com/v1"),
};

pub(crate) const GOOSE: ClientDescriptor = ClientDescriptor {
    name: "goose",
    aliases: &[],
    default_command: "goose",
    path_flag: "--goose",
    protocol: Protocol::OpenAi,
    launcher: Launcher::OpenAi(OpenAiInjection::GooseEnv),
    accepts_model: true,
    // Goose's documented OpenAI provider uses Chat Completions.
    accepts_api: false,
    upstream_env: &["GOOSE_PROVIDER__HOST"],
    default_upstream: Some("https://api.openai.com/v1"),
};

pub(crate) const JUNIE: ClientDescriptor = ClientDescriptor {
    name: "junie",
    aliases: &[],
    default_command: "junie",
    path_flag: "--junie",
    protocol: Protocol::OpenAi,
    launcher: Launcher::OpenAi(OpenAiInjection::JunieProfile),
    accepts_model: true,
    accepts_api: true,
    upstream_env: &["OPENAI_BASE_URL"],
    default_upstream: Some("https://api.openai.com/v1"),
};

pub(crate) const CONTINUE: ClientDescriptor = ClientDescriptor {
    name: "continue",
    aliases: &["cn"],
    default_command: "cn",
    path_flag: "--continue",
    protocol: Protocol::OpenAi,
    launcher: Launcher::Ide(crate::ide_clients::IdeClient::Continue),
    accepts_model: true,
    accepts_api: false,
    upstream_env: &["OPENAI_BASE_URL"],
    default_upstream: Some("https://api.openai.com/v1"),
};

pub(crate) const CLINE: ClientDescriptor = ClientDescriptor {
    name: "cline",
    aliases: &[],
    default_command: "cline",
    path_flag: "--cline",
    protocol: Protocol::OpenAi,
    launcher: Launcher::Ide(crate::ide_clients::IdeClient::Cline),
    accepts_model: true,
    accepts_api: false,
    upstream_env: &["OPENAI_BASE_URL"],
    default_upstream: Some("https://api.openai.com/v1"),
};

pub(crate) const ROO: ClientDescriptor = ClientDescriptor {
    name: "roo",
    aliases: &[],
    default_command: "code",
    path_flag: "--roo",
    protocol: Protocol::OpenAi,
    launcher: Launcher::Ide(crate::ide_clients::IdeClient::Roo),
    accepts_model: true,
    accepts_api: false,
    upstream_env: &["OPENAI_BASE_URL"],
    default_upstream: Some("https://api.openai.com/v1"),
};

pub(crate) const ZED: ClientDescriptor = ClientDescriptor {
    name: "zed",
    aliases: &[],
    default_command: "zed",
    path_flag: "--zed",
    protocol: Protocol::OpenAi,
    launcher: Launcher::Ide(crate::ide_clients::IdeClient::Zed),
    accepts_model: true,
    accepts_api: false,
    upstream_env: &["OPENAI_BASE_URL"],
    default_upstream: Some("https://api.openai.com/v1"),
};

pub(crate) const GEMINI: ClientDescriptor = ClientDescriptor {
    name: "gemini",
    aliases: &[],
    default_command: "gemini",
    path_flag: "--gemini",
    protocol: Protocol::Gemini,
    launcher: Launcher::EndpointEnv,
    accepts_model: false,
    accepts_api: false,
    upstream_env: &["GOOGLE_GEMINI_BASE_URL"],
    default_upstream: Some("https://generativelanguage.googleapis.com"),
};

pub(crate) const CLIENTS: &[ClientDescriptor] = &[
    CODEX,
    CLAUDE,
    OPENCODE,
    PI,
    ANTIGRAVITY,
    AIDER,
    GOOSE,
    JUNIE,
    CONTINUE,
    CLINE,
    ROO,
    ZED,
    GEMINI,
];

pub(crate) fn find(command: &str) -> Option<&'static ClientDescriptor> {
    CLIENTS
        .iter()
        .find(|client| command == client.name || client.aliases.contains(&command))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn descriptors_have_unique_names_and_path_flags() {
        let mut commands = std::collections::BTreeSet::new();
        for (index, client) in CLIENTS.iter().enumerate() {
            assert!(!client.name.is_empty());
            assert!(client.path_flag.starts_with("--"));
            assert!(commands.insert(client.name));
            for alias in client.aliases {
                assert!(commands.insert(alias), "duplicate client command {alias}");
            }
            for other in &CLIENTS[index + 1..] {
                assert_ne!(client.name, other.name);
                assert_ne!(client.path_flag, other.path_flag);
                assert!(!other.aliases.contains(&client.name));
                assert!(!client.aliases.contains(&other.name));
            }
        }
    }

    #[test]
    fn launchers_match_their_protocol_and_required_metadata() {
        for client in CLIENTS {
            match client.launcher {
                Launcher::CodexConfig | Launcher::OpenAi(_) | Launcher::Ide(_) => {
                    assert_eq!(client.protocol, Protocol::OpenAi, "{}", client.name);
                }
                Launcher::ClaudeSettings => {
                    assert_eq!(client.protocol, Protocol::Anthropic, "{}", client.name);
                }
                Launcher::EndpointEnv => {
                    assert_eq!(client.upstream_env.len(), 1, "{}", client.name);
                    assert!(client.default_upstream.is_some(), "{}", client.name);
                }
            }
        }
    }

    #[test]
    fn registry_resolves_names_and_aliases() {
        assert_eq!(find("codex"), Some(&CODEX));
        assert_eq!(find("agy"), Some(&ANTIGRAVITY));
        assert_eq!(find("unknown"), None);
    }
}

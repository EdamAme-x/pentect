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
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ClientDescriptor {
    pub(crate) name: &'static str,
    pub(crate) aliases: &'static [&'static str],
    pub(crate) default_command: &'static str,
    pub(crate) path_flag: &'static str,
    pub(crate) protocol: Protocol,
    pub(crate) accepts_model: bool,
    pub(crate) accepts_api: bool,
    pub(crate) upstream_env: &'static [&'static str],
}

pub(crate) const CODEX: ClientDescriptor = ClientDescriptor {
    name: "codex",
    aliases: &[],
    default_command: "codex",
    path_flag: "--codex",
    protocol: Protocol::OpenAi,
    accepts_model: false,
    accepts_api: false,
    upstream_env: &["OPENAI_BASE_URL"],
};

pub(crate) const CLAUDE: ClientDescriptor = ClientDescriptor {
    name: "claude",
    aliases: &[],
    default_command: "claude",
    path_flag: "--claude",
    protocol: Protocol::Anthropic,
    accepts_model: false,
    accepts_api: false,
    upstream_env: &["ANTHROPIC_BASE_URL"],
};

pub(crate) const OPENCODE: ClientDescriptor = ClientDescriptor {
    name: "opencode",
    aliases: &[],
    default_command: "opencode",
    path_flag: "--opencode",
    protocol: Protocol::OpenAi,
    accepts_model: true,
    accepts_api: true,
    upstream_env: &["OPENAI_BASE_URL"],
};

pub(crate) const PI: ClientDescriptor = ClientDescriptor {
    name: "pi",
    aliases: &[],
    default_command: "pi",
    path_flag: "--pi",
    protocol: Protocol::OpenAi,
    accepts_model: true,
    accepts_api: true,
    upstream_env: &["OPENAI_BASE_URL"],
};

pub(crate) const ANTIGRAVITY: ClientDescriptor = ClientDescriptor {
    name: "antigravity",
    aliases: &["agy"],
    default_command: "agy",
    path_flag: "--agy",
    protocol: Protocol::CloudCode,
    accepts_model: false,
    accepts_api: false,
    upstream_env: &["CLOUD_CODE_URL"],
};

pub(crate) const AIDER: ClientDescriptor = ClientDescriptor {
    name: "aider",
    aliases: &[],
    default_command: "aider",
    path_flag: "--aider",
    protocol: Protocol::OpenAi,
    accepts_model: true,
    accepts_api: false,
    // OPENAI_API_BASE is Aider's documented compatible-provider setting.
    // AIDER_OPENAI_API_BASE is the generated CLI option environment alias.
    upstream_env: &[
        "AIDER_OPENAI_API_BASE",
        "OPENAI_API_BASE",
        "OPENAI_BASE_URL",
    ],
};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn descriptors_have_unique_names_and_path_flags() {
        let clients = [CODEX, CLAUDE, OPENCODE, PI, ANTIGRAVITY, AIDER];
        for (index, client) in clients.iter().enumerate() {
            assert!(!client.name.is_empty());
            assert!(client.path_flag.starts_with("--"));
            for other in &clients[index + 1..] {
                assert_ne!(client.name, other.name);
                assert_ne!(client.path_flag, other.path_flag);
                assert!(!other.aliases.contains(&client.name));
                assert!(!client.aliases.contains(&other.name));
            }
        }
    }
}

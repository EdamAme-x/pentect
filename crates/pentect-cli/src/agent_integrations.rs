use serde_json::Value;
use std::path::{Path, PathBuf};

const BRIDGE_CLIENT_JS: &str = r#"
import { spawn } from "node:child_process";

function replaceObject(target, source) {
  for (const key of Object.keys(target)) delete target[key];
  Object.assign(target, source);
}

function replaceArray(target, source) {
  target.splice(0, target.length, ...source);
}

function createPentectBridge() {
  const child = spawn(process.env.PENTECT_BIN || "pentect", ["bridge"], {
    stdio: ["pipe", "pipe", "ignore"],
    windowsHide: true,
  });
  let nextId = 1;
  let pending = new Map();
  let buffered = "";
  let closed = false;

  const fail = () => {
    if (closed) return;
    closed = true;
    for (const { reject } of pending.values()) reject(new Error("Pentect unavailable"));
    pending.clear();
  };

  child.stdout.setEncoding("utf8");
  child.stdout.on("data", (chunk) => {
    buffered += chunk;
    for (;;) {
      const end = buffered.indexOf("\n");
      if (end < 0) break;
      const line = buffered.slice(0, end);
      buffered = buffered.slice(end + 1);
      let response;
      try {
        response = JSON.parse(line);
      } catch {
        fail();
        return;
      }
      const waiter = pending.get(response.id);
      if (!waiter) continue;
      pending.delete(response.id);
      if (response.ok) {
        waiter.resolve(response.value);
      } else {
        const error = new Error(response.error?.message || "Operation unavailable");
        error.code = response.error?.code;
        error.phase = response.error?.phase;
        error.executed = response.error?.executed === true;
        waiter.reject(error);
      }
    }
  });
  child.on("error", fail);
  child.on("exit", fail);

  return {
    request(op, fields = {}) {
      if (closed) return Promise.reject(new Error("Pentect unavailable"));
      const id = nextId++;
      return new Promise((resolve, reject) => {
        pending.set(id, { resolve, reject });
        child.stdin.write(`${JSON.stringify({ id, op, ...fields })}\n`, (error) => {
          if (!error) return;
          pending.delete(id);
          reject(new Error("Pentect unavailable"));
        });
      });
    },
    close() {
      closed = true;
      child.kill();
      pending.clear();
    },
  };
}
"#;

const OPENCODE_PLUGIN_BODY: &str = r#"
const SAFE_TEXT = "[Content unavailable]";

export const PentectPlugin = async () => {
  const bridge = createPentectBridge();
  return {
    "experimental.chat.system.transform": async (_input, output) => {
      const contract = process.env.PENTECT_AGENT_CONTRACT;
      if (contract && !output.system.includes(contract)) output.system.push(contract);
    },
    "chat.message": async (_input, output) => {
      const original = structuredClone(output.parts);
      replaceArray(output.parts, [{ type: "text", text: SAFE_TEXT }]);
      try {
        const withSafeImages = await bridge.request("media", { value: original });
        for (const part of withSafeImages) {
          if (part && part.type === "text" && typeof part.text === "string") {
            part.text = await bridge.request("prompt", { value: part.text });
          }
        }
        replaceArray(output.parts, withSafeImages);
      } catch {
        throw new Error("Message unavailable");
      }
    },
    "tool.execute.before": async (input, output) => {
      try {
        const next = await bridge.request("before", { tool: input.tool, value: output.args });
        replaceObject(output.args, next);
      } catch {
        throw new Error("Tool unavailable");
      }
    },
    "tool.execute.after": async (input, output) => {
      const original = structuredClone(output);
      replaceObject(output, { title: original.title || "Tool", output: SAFE_TEXT, metadata: {} });
      try {
        const next = await bridge.request("after", {
          tool: input.tool,
          input: input.args,
          value: original,
        });
        replaceObject(output, next);
      } catch {
        output.output = "Tool completed, but its output was unavailable. Check side effects before retrying.";
      }
    },
    dispose: async () => bridge.close(),
  };
};
"#;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum IntegrationKind {
    OpenCode,
}

pub(crate) struct TempAgentIntegration {
    root: PathBuf,
    path: PathBuf,
}

impl TempAgentIntegration {
    pub(crate) fn create(kind: IntegrationKind) -> Result<Self, String> {
        let mut nonce = [0u8; 16];
        getrandom::getrandom(&mut nonce)
            .map_err(|_| "could not create agent integration".to_string())?;
        let root = std::env::temp_dir().join(format!(
            "pentect-agent-{}-{}",
            std::process::id(),
            data_encoding::HEXLOWER.encode(&nonce)
        ));
        std::fs::create_dir(&root).map_err(|_| "could not create agent integration".to_string())?;
        let file_name = match kind {
            IntegrationKind::OpenCode => "opencode.mjs",
        };
        let path = root.join(file_name);
        let body = match kind {
            IntegrationKind::OpenCode => format!("{BRIDGE_CLIENT_JS}\n{OPENCODE_PLUGIN_BODY}"),
        };
        if std::fs::write(&path, body).is_err() {
            let _ = std::fs::remove_dir_all(&root);
            return Err("could not create agent integration".to_string());
        }
        Ok(Self { root, path })
    }

    pub(crate) fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for TempAgentIntegration {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.root);
    }
}

pub(crate) fn opencode_config_with_plugin(
    existing: Option<&str>,
    plugin_path: &Path,
) -> Result<String, String> {
    let mut config = match existing.filter(|value| !value.trim().is_empty()) {
        Some(value) => serde_json::from_str::<Value>(value)
            .map_err(|_| "OPENCODE_CONFIG_CONTENT must be valid JSON".to_string())?,
        None => Value::Object(Default::default()),
    };
    let object = config
        .as_object_mut()
        .ok_or_else(|| "OPENCODE_CONFIG_CONTENT must be a JSON object".to_string())?;
    let plugins = object
        .entry("plugin")
        .or_insert_with(|| Value::Array(Vec::new()))
        .as_array_mut()
        .ok_or_else(|| "OPENCODE_CONFIG_CONTENT.plugin must be an array".to_string())?;
    let path = plugin_path.to_string_lossy().into_owned();
    if !plugins.iter().any(|value| value.as_str() == Some(&path)) {
        plugins.push(Value::String(path));
    }
    serde_json::to_string(&config).map_err(|_| "could not create OpenCode config".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scripts_cover_prompt_tool_and_result_boundaries() {
        let opencode = format!("{BRIDGE_CLIENT_JS}{OPENCODE_PLUGIN_BODY}");
        assert!(opencode.contains("chat.message"));
        assert!(opencode.contains("tool.execute.before"));
        assert!(opencode.contains("tool.execute.after"));
        assert!(opencode.contains(
            "Tool completed, but its output was unavailable. Check side effects before retrying."
        ));
        assert!(!OPENCODE_PLUGIN_BODY.contains("error?.executed"));
    }

    #[test]
    fn opencode_config_preserves_existing_values() {
        let path = Path::new("C:/tmp/pentect-opencode.mjs");
        let rendered =
            opencode_config_with_plugin(Some(r#"{"model":"example","plugin":["existing"]}"#), path)
                .unwrap();
        let value: Value = serde_json::from_str(&rendered).unwrap();
        assert_eq!(value["model"], "example");
        assert_eq!(value["plugin"][0], "existing");
        assert!(value["plugin"].as_array().unwrap().len() == 2);
    }

    #[test]
    fn temporary_integration_is_removed_on_drop() {
        let path = {
            let integration = TempAgentIntegration::create(IntegrationKind::OpenCode).unwrap();
            assert!(integration.path().is_file());
            integration.path().to_path_buf()
        };
        assert!(!path.exists());
    }

    #[test]
    fn generated_integrations_are_valid_javascript_when_node_is_available() {
        if std::process::Command::new("node")
            .arg("--version")
            .output()
            .is_err()
        {
            return;
        }
        let integration = TempAgentIntegration::create(IntegrationKind::OpenCode).unwrap();
        let output = std::process::Command::new("node")
            .arg("--check")
            .arg(integration.path())
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
}

use pentect_agent::ActiveToolOutputMasker;
use serde_json::Value;

pub(crate) fn mask_model_definition(
    value: &mut Value,
    provider: &str,
    masker: &mut ActiveToolOutputMasker,
) -> Result<(), String> {
    let mut nodes = 0_usize;
    mask_value(value, provider, 0, &mut nodes, masker)
}

fn mask_value(
    value: &mut Value,
    provider: &str,
    depth: usize,
    nodes: &mut usize,
    masker: &mut ActiveToolOutputMasker,
) -> Result<(), String> {
    const MAX_DEFINITION_DEPTH: usize = 64;
    const MAX_DEFINITION_NODES: usize = 65_536;
    if depth > MAX_DEFINITION_DEPTH {
        return Err(format!("{provider} model definition exceeds nesting limit"));
    }
    *nodes = nodes
        .checked_add(1)
        .ok_or_else(|| format!("{provider} model definition is too large"))?;
    if *nodes > MAX_DEFINITION_NODES {
        return Err(format!("{provider} model definition exceeds item limit"));
    }
    match value {
        // Definitions can originate from an MCP server or extension. Treat
        // them as external content so they cannot opt out of masking.
        Value::String(text) => crate::claude_http_proxy::mask_string(text, true, masker),
        Value::Array(items) => {
            for item in items {
                mask_value(item, provider, depth + 1, nodes, masker)?;
            }
            Ok(())
        }
        Value::Object(object) => {
            for item in object.values_mut() {
                mask_value(item, provider, depth + 1, nodes, masker)?;
            }
            Ok(())
        }
        _ => Ok(()),
    }
}

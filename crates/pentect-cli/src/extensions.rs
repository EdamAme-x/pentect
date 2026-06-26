use std::path::{Path, PathBuf};

const PENTECT_DIR: &str = ".pentect";
const EXTENSIONS_DIR: &str = "extensions";
const MANIFEST_FILE: &str = "extension.toml";

pub(crate) fn parse_extension_value(value: &str) -> Result<Vec<String>, String> {
    let mut names = Vec::new();
    for raw in value.split(',') {
        let name = raw.trim();
        if name.is_empty() {
            continue;
        }
        validate_extension_name(name)?;
        if !names.iter().any(|existing| existing == name) {
            names.push(name.to_string());
        }
    }
    if names.is_empty() {
        return Err("--extensions requires at least one extension name".to_string());
    }
    Ok(names)
}

pub(crate) fn prepare(names: &[String]) -> Result<(), String> {
    if names.is_empty() {
        return Ok(());
    }
    let root = extensions_root();
    std::fs::create_dir_all(&root)
        .map_err(|e| format!("could not create '{}': {e}", root.display()))?;
    for name in names {
        validate_extension_name(name)?;
        let dir = root.join(name);
        std::fs::create_dir_all(&dir)
            .map_err(|e| format!("could not create '{}': {e}", dir.display()))?;
        let manifest = dir.join(MANIFEST_FILE);
        if !manifest.exists() {
            let src = format!("name = \"{name}\"\n");
            std::fs::write(&manifest, src)
                .map_err(|e| format!("could not write '{}': {e}", manifest.display()))?;
        }
    }
    validate_packs(names)?;
    Ok(())
}

pub(crate) fn env_value(names: &[String]) -> Option<String> {
    (!names.is_empty()).then(|| names.join(","))
}

pub(crate) fn pack_paths(names: &[String]) -> Result<Vec<PathBuf>, String> {
    prepare(names)?;
    pack_paths_without_prepare(names)
}

pub(crate) fn collect_from_args(args: &[String]) -> Result<Vec<String>, String> {
    let mut names = Vec::new();
    let mut i = 0usize;
    while i < args.len() {
        if args[i] == "--extensions" {
            let Some(value) = args.get(i + 1) else {
                return Err("--extensions requires a value".to_string());
            };
            if value.starts_with("--") {
                return Err("--extensions requires a value".to_string());
            }
            for name in parse_extension_value(value)? {
                if !names.iter().any(|existing| existing == &name) {
                    names.push(name);
                }
            }
            i += 2;
        } else {
            i += 1;
        }
    }
    Ok(names)
}

fn extensions_root() -> PathBuf {
    PathBuf::from(PENTECT_DIR).join(EXTENSIONS_DIR)
}

fn validate_extension_name(name: &str) -> Result<(), String> {
    let mut chars = name.chars();
    let Some(first) = chars.next() else {
        return Err("extension name must not be empty".to_string());
    };
    if !first.is_ascii_alphanumeric() {
        return Err(format!("invalid extension name: {name}"));
    }
    if name.len() > 64
        || !chars.all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '-' | '_' | '.'))
    {
        return Err(format!("invalid extension name: {name}"));
    }
    Ok(())
}

fn toml_files_in_dir(dir: &Path) -> Result<Vec<PathBuf>, String> {
    let mut files = Vec::new();
    for entry in std::fs::read_dir(dir).map_err(|e| {
        format!(
            "could not read extension directory '{}': {e}",
            dir.display()
        )
    })? {
        let path = entry
            .map_err(|e| {
                format!(
                    "could not read extension directory '{}': {e}",
                    dir.display()
                )
            })?
            .path();
        if path.extension().is_some_and(|ext| ext == "toml") {
            files.push(path);
        }
    }
    files.sort();
    Ok(files)
}

fn validate_packs(names: &[String]) -> Result<(), String> {
    for path in pack_paths_without_prepare(names)? {
        let display = path.display();
        let src = std::fs::read_to_string(&path)
            .map_err(|e| format!("could not read extension pack '{display}': {e}"))?;
        pentect_core::load_pack(&src)
            .map_err(|e| format!("extension pack '{display}' is invalid: {e}"))?;
    }
    Ok(())
}

fn pack_paths_without_prepare(names: &[String]) -> Result<Vec<PathBuf>, String> {
    let mut paths = Vec::new();
    for name in names {
        validate_extension_name(name)?;
        let dir = extensions_root().join(name);
        let pack = dir.join("pack.toml");
        if pack.exists() {
            paths.push(pack);
        }
        let packs_dir = dir.join("packs");
        if packs_dir.exists() {
            paths.extend(toml_files_in_dir(&packs_dir)?);
        }
    }
    paths.sort();
    Ok(paths)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_extension_names() {
        assert_eq!(
            parse_extension_value("openai-privacy-filter,local.rules").unwrap(),
            vec!["openai-privacy-filter", "local.rules"]
        );
        assert!(parse_extension_value("../x").is_err());
        assert!(parse_extension_value("").is_err());
    }
}

use std::path::PathBuf;

#[derive(Clone, Debug)]
pub(super) struct ScanOpts {
    pub(super) paths: Vec<PathBuf>,
    pub(super) json: bool,
    pub(super) no_fail: bool,
    pub(super) gitignore: bool,
    pub(super) binary: BinaryMode,
    pub(super) excludes: Vec<String>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum BinaryMode {
    Skip,
    Text,
}

impl BinaryMode {
    fn parse(value: &str) -> Result<Self, String> {
        match value {
            "skip" => Ok(Self::Skip),
            "text" => Ok(Self::Text),
            _ => Err("binary must be skip or text".to_string()),
        }
    }
}

impl ScanOpts {
    pub(super) fn parse(args: &[String]) -> Result<Self, String> {
        let mut paths = Vec::new();
        let mut json = false;
        let mut no_fail = false;
        let mut gitignore = false;
        let mut binary = BinaryMode::Skip;
        let mut excludes = Vec::new();
        let mut i = 2usize;
        while i < args.len() {
            match args[i].as_str() {
                "--json" => {
                    json = true;
                    i += 1;
                }
                "--no-fail" => {
                    no_fail = true;
                    i += 1;
                }
                "--gitignore" => {
                    gitignore = true;
                    i += 1;
                }
                "--binary" => {
                    let flag = args[i].clone();
                    let value = required_value(args, &mut i, &flag)?;
                    binary = BinaryMode::parse(&value)?;
                }
                "--exclude" => {
                    let flag = args[i].clone();
                    let value = required_value(args, &mut i, &flag)?;
                    excludes.push(value);
                }
                "--pack" | "--pack-dir" | "--extensions" => {
                    let flag = args[i].clone();
                    let _ = required_value(args, &mut i, &flag)?;
                }
                flag if flag.starts_with("--") => {
                    return Err(format!("unknown option: {flag}"));
                }
                path => {
                    paths.push(PathBuf::from(path));
                    i += 1;
                }
            }
        }
        if paths.is_empty() {
            paths.push(PathBuf::from("."));
        }
        Ok(Self {
            paths,
            json,
            no_fail,
            gitignore,
            binary,
            excludes,
        })
    }
}

fn required_value(args: &[String], i: &mut usize, flag: &str) -> Result<String, String> {
    let Some(value) = args.get(*i + 1) else {
        return Err(format!("{flag} requires a value"));
    };
    if value.starts_with("--") {
        return Err(format!("{flag} requires a value"));
    }
    *i += 2;
    Ok(value.clone())
}

use std::path::PathBuf;

#[derive(Clone, Debug)]
pub(super) struct ScanOpts {
    pub(super) paths: Vec<PathBuf>,
    pub(super) core_only: bool,
    pub(super) json: bool,
    pub(super) no_fail: bool,
    pub(super) gitignore: bool,
    pub(super) excludes: Vec<String>,
}

impl ScanOpts {
    pub(super) fn parse(args: &[String]) -> Result<Self, String> {
        let mut paths = Vec::new();
        let mut core_only = false;
        let mut json = false;
        let mut no_fail = false;
        let mut gitignore = false;
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
                "--core" => {
                    core_only = true;
                    i += 1;
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
            core_only,
            json,
            no_fail,
            gitignore,
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

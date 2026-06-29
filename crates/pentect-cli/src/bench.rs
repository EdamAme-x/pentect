use crate::{die, infer_kind};
use pentect_core::{ByteRange, Category, Engine, Input, Profile, Span};
use serde::Deserialize;
use serde_json::json;
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::time::Instant;

pub(crate) fn cmd_bench(args: &[String]) {
    let opts = match BenchOpts::parse(args) {
        Ok(opts) => opts,
        Err(e) => die(e),
    };
    let report = match opts.dataset {
        Dataset::CredData { ref path } => run_creddata(path, &opts),
    };
    let report = match report {
        Ok(report) => report,
        Err(e) => die(e),
    };
    if opts.json {
        println!("{}", report.to_json());
    } else {
        println!(
            "pentect bench creddata rows={} files={} precision={:.3} recall={:.3} f1={:.3}",
            report.rows, report.files, report.precision, report.recall, report.f1
        );
        println!(
            "tp={} fp={} fn={} line_only={} unlabeled={} missing_files={} invalid_rows={} skipped_rows={} elapsed_ms={}",
            report.tp,
            report.fp,
            report.fn_,
            report.line_only,
            report.unlabeled,
            report.missing_files,
            report.invalid_rows,
            report.skipped_rows,
            report.elapsed_ms
        );
        if !report.by_category.is_empty() {
            let mut parts = Vec::new();
            for (category, metric) in &report.by_category {
                parts.push(format!(
                    "{}:{}/{}/{}",
                    category, metric.tp, metric.fp, metric.fn_
                ));
            }
            println!("categories {}", parts.join(" "));
        }
    }
    if let Some(min) = opts.min_precision {
        if report.precision < min {
            std::process::exit(1);
        }
    }
    if let Some(min) = opts.min_recall {
        if report.recall < min {
            std::process::exit(1);
        }
    }
}

#[derive(Clone, Debug)]
struct BenchOpts {
    dataset: Dataset,
    json: bool,
    limit: Option<usize>,
    repo: Option<String>,
    ignore_x: bool,
    min_precision: Option<f64>,
    min_recall: Option<f64>,
}

#[derive(Clone, Debug)]
enum Dataset {
    CredData { path: PathBuf },
}

impl BenchOpts {
    fn parse(args: &[String]) -> Result<Self, String> {
        let Some(dataset) = args.get(2).map(String::as_str) else {
            return Err("bench creddata PATH".to_string());
        };
        match dataset {
            "creddata" => Self::parse_creddata(args),
            other => Err(format!("unknown benchmark: {other}")),
        }
    }

    fn parse_creddata(args: &[String]) -> Result<Self, String> {
        let Some(path) = args.get(3) else {
            return Err("bench creddata PATH".to_string());
        };
        let mut json = false;
        let mut limit = None;
        let mut repo = None;
        let mut ignore_x = false;
        let mut min_precision = None;
        let mut min_recall = None;
        let mut i = 4usize;
        while i < args.len() {
            match args[i].as_str() {
                "--json" => {
                    json = true;
                    i += 1;
                }
                "--ignore-x" => {
                    ignore_x = true;
                    i += 1;
                }
                "--limit" => {
                    limit = Some(parse_usize_arg(args, &mut i, "--limit")?);
                }
                "--repo" => {
                    repo = Some(required_value(args, &mut i, "--repo")?);
                }
                "--min-precision" => {
                    min_precision = Some(parse_f64_arg(args, &mut i, "--min-precision")?);
                }
                "--min-recall" => {
                    min_recall = Some(parse_f64_arg(args, &mut i, "--min-recall")?);
                }
                flag if flag.starts_with("--") => return Err(format!("unknown option: {flag}")),
                value => return Err(format!("unexpected argument for bench: {value}")),
            }
        }
        Ok(Self {
            dataset: Dataset::CredData {
                path: PathBuf::from(path),
            },
            json,
            limit,
            repo,
            ignore_x,
            min_precision,
            min_recall,
        })
    }
}

fn parse_usize_arg(args: &[String], i: &mut usize, flag: &str) -> Result<usize, String> {
    let value = required_value(args, i, flag)?;
    value
        .parse::<usize>()
        .map_err(|_| format!("{flag} requires a positive integer"))
}

fn parse_f64_arg(args: &[String], i: &mut usize, flag: &str) -> Result<f64, String> {
    let value = required_value(args, i, flag)?;
    let parsed = value
        .parse::<f64>()
        .map_err(|_| format!("{flag} requires a number"))?;
    if !(0.0..=1.0).contains(&parsed) {
        return Err(format!("{flag} must be between 0 and 1"));
    }
    Ok(parsed)
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

fn run_creddata(root: &Path, opts: &BenchOpts) -> Result<BenchReport, String> {
    let meta_dir = root.join("meta");
    let data_dir = root.join("data");
    if !meta_dir.is_dir() {
        return Err(format!(
            "CredData meta directory not found: {}",
            meta_dir.display()
        ));
    }
    if !data_dir.is_dir() {
        return Err(format!(
            "CredData data directory not found: {}",
            data_dir.display()
        ));
    }

    let started = Instant::now();
    let rows = load_creddata_rows(root, &meta_dir, opts)?;
    let mut by_file: BTreeMap<PathBuf, Vec<CredRow>> = BTreeMap::new();
    for row in rows {
        by_file.entry(row.path.clone()).or_default().push(row);
    }

    let engine = Engine::with_profile(Profile::Strict);
    let mut report = BenchReport {
        files: by_file.len(),
        ..BenchReport::default()
    };

    for (path, rows) in by_file {
        let raw = match std::fs::read_to_string(&path) {
            Ok(raw) => normalize_newlines(raw),
            Err(_) => {
                report.missing_files += 1;
                report.skipped_rows += rows.len();
                continue;
            }
        };
        let line_index = LineIndex::new(&raw);
        let mut cases = Vec::new();
        for row in rows {
            match BenchCase::from_row(row, &line_index) {
                Some(case) => {
                    report.rows += 1;
                    for category in category_parts(&case.category) {
                        report
                            .by_category
                            .entry(category.to_string())
                            .or_default()
                            .total_rows += 1;
                    }
                    if case.truth == Truth::True {
                        report.true_rows += 1;
                    } else {
                        report.false_rows += 1;
                    }
                    cases.push(case);
                }
                None => {
                    report.invalid_rows += 1;
                }
            }
        }
        if cases.is_empty() {
            continue;
        }

        let spans = engine
            .analyze_spans(Input {
                kind: infer_kind(&path),
                data: raw,
            })
            .spans
            .into_iter()
            .filter(|span| span.category == Category::Secret)
            .collect::<Vec<_>>();
        score_file(&cases, &spans, &mut report);
    }

    report.elapsed_ms = started.elapsed().as_millis();
    report.finish();
    Ok(report)
}

fn load_creddata_rows(
    root: &Path,
    meta_dir: &Path,
    opts: &BenchOpts,
) -> Result<Vec<CredRow>, String> {
    let mut files = csv_files(meta_dir)?;
    files.sort();
    let mut out = Vec::new();
    'files: for path in files {
        let mut reader = csv::ReaderBuilder::new()
            .flexible(true)
            .from_path(&path)
            .map_err(|e| format!("could not read '{}': {e}", path.display()))?;
        for row in reader.deserialize::<CredCsvRow>() {
            let row =
                row.map_err(|e| format!("invalid CredData row in '{}': {e}", path.display()))?;
            if let Some(repo) = &opts.repo {
                if row.repo_name != *repo {
                    continue;
                }
            }
            if opts.ignore_x && row.ground_truth == "X" {
                continue;
            }
            if row.ground_truth != "T" && row.ground_truth != "F" && row.ground_truth != "X" {
                continue;
            }
            let path = dataset_file_path(root, &row.file_path);
            out.push(CredRow {
                path,
                line_start: row.line_start,
                line_end: row.line_end,
                truth: if row.ground_truth == "T" {
                    Truth::True
                } else {
                    Truth::False
                },
                value_start: row.value_start,
                value_end: row.value_end,
                category: row.category,
            });
            if opts.limit.is_some_and(|limit| out.len() >= limit) {
                break 'files;
            }
        }
    }
    Ok(out)
}

fn csv_files(meta_dir: &Path) -> Result<Vec<PathBuf>, String> {
    let mut out = Vec::new();
    for entry in std::fs::read_dir(meta_dir)
        .map_err(|e| format!("could not read '{}': {e}", meta_dir.display()))?
    {
        let path = entry
            .map_err(|e| format!("could not read '{}': {e}", meta_dir.display()))?
            .path();
        if path.extension().and_then(|ext| ext.to_str()) == Some("csv") {
            out.push(path);
        }
    }
    Ok(out)
}

fn dataset_file_path(root: &Path, file_path: &str) -> PathBuf {
    let mut out = root.to_path_buf();
    for part in file_path.split('/') {
        if part.is_empty() || part == "." {
            continue;
        }
        out.push(part);
    }
    out
}

fn score_file(cases: &[BenchCase], spans: &[Span], report: &mut BenchReport) {
    let mut true_hits = BTreeSet::new();
    let mut line_only_hits = BTreeSet::new();
    for (i, case) in cases.iter().enumerate() {
        if case.truth != Truth::True {
            continue;
        }
        if spans
            .iter()
            .any(|span| span.range.overlaps(&case.strict_range))
        {
            true_hits.insert(i);
        } else if spans
            .iter()
            .any(|span| span.range.overlaps(&case.line_range))
        {
            line_only_hits.insert(i);
        }
    }

    for (i, case) in cases.iter().enumerate() {
        match case.truth {
            Truth::True if true_hits.contains(&i) => {
                report.tp += 1;
                for category in category_parts(&case.category) {
                    report
                        .by_category
                        .entry(category.to_string())
                        .or_default()
                        .tp += 1;
                }
            }
            Truth::True => {
                report.fn_ += 1;
                if line_only_hits.contains(&i) {
                    report.line_only += 1;
                }
                for category in category_parts(&case.category) {
                    let metric = report.by_category.entry(category.to_string()).or_default();
                    metric.fn_ += 1;
                    if line_only_hits.contains(&i) {
                        metric.line_only += 1;
                    }
                }
            }
            Truth::False => {}
        }
    }

    for span in spans {
        if cases
            .iter()
            .any(|case| case.truth == Truth::True && span.range.overlaps(&case.strict_range))
        {
            continue;
        }
        if let Some(case) = cases
            .iter()
            .find(|case| case.truth == Truth::False && span.range.overlaps(&case.line_range))
        {
            report.fp += 1;
            for category in category_parts(&case.category) {
                report
                    .by_category
                    .entry(category.to_string())
                    .or_default()
                    .fp += 1;
            }
        } else {
            report.unlabeled += 1;
        }
    }
}

fn category_parts(category: &str) -> impl Iterator<Item = &str> {
    category
        .split(':')
        .map(str::trim)
        .filter(|part| !part.is_empty())
}

fn normalize_newlines(raw: String) -> String {
    raw.replace("\r\n", "\n").replace('\r', "\n")
}

#[derive(Debug, Deserialize)]
struct CredCsvRow {
    #[serde(rename = "RepoName")]
    repo_name: String,
    #[serde(rename = "FilePath")]
    file_path: String,
    #[serde(rename = "LineStart")]
    line_start: usize,
    #[serde(rename = "LineEnd")]
    line_end: usize,
    #[serde(rename = "GroundTruth")]
    ground_truth: String,
    #[serde(rename = "ValueStart", deserialize_with = "empty_usize")]
    value_start: Option<usize>,
    #[serde(rename = "ValueEnd", deserialize_with = "empty_usize")]
    value_end: Option<usize>,
    #[serde(rename = "Category")]
    category: String,
}

fn empty_usize<'de, D>(deserializer: D) -> Result<Option<usize>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let value = Option::<String>::deserialize(deserializer)?;
    let Some(value) = value else {
        return Ok(None);
    };
    let value = value.trim();
    if value.is_empty() {
        return Ok(None);
    }
    value
        .parse::<usize>()
        .map(Some)
        .map_err(serde::de::Error::custom)
}

#[derive(Clone, Debug)]
struct CredRow {
    path: PathBuf,
    line_start: usize,
    line_end: usize,
    truth: Truth,
    value_start: Option<usize>,
    value_end: Option<usize>,
    category: String,
}

#[derive(Clone, Debug)]
struct BenchCase {
    truth: Truth,
    strict_range: ByteRange,
    line_range: ByteRange,
    category: String,
}

impl BenchCase {
    fn from_row(row: CredRow, lines: &LineIndex) -> Option<Self> {
        let line_range = lines.line_range(row.line_start, row.line_end)?;
        let strict_range = match (row.value_start, row.value_end) {
            (Some(start), Some(end)) if row.line_start == row.line_end && start < end => lines
                .value_range(row.line_start, start, end)
                .unwrap_or(line_range),
            _ => line_range,
        };
        Some(Self {
            truth: row.truth,
            strict_range,
            line_range,
            category: row.category,
        })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Truth {
    True,
    False,
}

#[derive(Clone, Debug)]
struct LineIndex {
    text: String,
    starts: Vec<usize>,
}

impl LineIndex {
    fn new(text: &str) -> Self {
        let mut starts = vec![0];
        for (i, byte) in text.bytes().enumerate() {
            if byte == b'\n' {
                starts.push(i + 1);
            }
        }
        Self {
            text: text.to_string(),
            starts,
        }
    }

    fn line_range(&self, line_start: usize, line_end: usize) -> Option<ByteRange> {
        if line_start == 0 || line_end < line_start {
            return None;
        }
        let start = *self.starts.get(line_start - 1)?;
        let end = self.line_end(line_end)?;
        Some(ByteRange::new(start, end))
    }

    fn value_range(&self, line: usize, start_col: usize, end_col: usize) -> Option<ByteRange> {
        let line_start = *self.starts.get(line.checked_sub(1)?)?;
        let line_end = self.line_end(line)?;
        let text = &self.text[line_start..line_end];
        let start = line_start + char_col_to_byte(text, start_col);
        let end = line_start + char_col_to_byte(text, end_col);
        (start < end && end <= line_end).then_some(ByteRange::new(start, end))
    }

    fn line_end(&self, line: usize) -> Option<usize> {
        if line == 0 || line > self.starts.len() {
            return None;
        }
        let next = self.starts.get(line).copied().unwrap_or(self.text.len());
        Some(next.saturating_sub(usize::from(
            next > 0 && self.text.as_bytes()[next - 1] == b'\n',
        )))
    }
}

fn char_col_to_byte(text: &str, col: usize) -> usize {
    if col == 0 {
        return 0;
    }
    text.char_indices()
        .nth(col)
        .map(|(i, _)| i)
        .unwrap_or(text.len())
}

#[derive(Clone, Debug, Default)]
struct BenchReport {
    rows: usize,
    files: usize,
    true_rows: usize,
    false_rows: usize,
    tp: usize,
    fp: usize,
    fn_: usize,
    line_only: usize,
    unlabeled: usize,
    missing_files: usize,
    invalid_rows: usize,
    skipped_rows: usize,
    precision: f64,
    recall: f64,
    f1: f64,
    elapsed_ms: u128,
    by_category: BTreeMap<String, CategoryMetric>,
}

impl BenchReport {
    fn finish(&mut self) {
        self.precision = ratio(self.tp, self.tp + self.fp);
        self.recall = ratio(self.tp, self.tp + self.fn_);
        self.f1 = if self.precision + self.recall == 0.0 {
            0.0
        } else {
            2.0 * self.precision * self.recall / (self.precision + self.recall)
        };
        for metric in self.by_category.values_mut() {
            metric.finish();
        }
    }

    fn to_json(&self) -> String {
        json!({
            "dataset": "creddata",
            "rows": self.rows,
            "files": self.files,
            "true_rows": self.true_rows,
            "false_rows": self.false_rows,
            "tp": self.tp,
            "fp": self.fp,
            "fn": self.fn_,
            "line_only": self.line_only,
            "unlabeled": self.unlabeled,
            "missing_files": self.missing_files,
            "invalid_rows": self.invalid_rows,
            "skipped_rows": self.skipped_rows,
            "precision": self.precision,
            "recall": self.recall,
            "f1": self.f1,
            "elapsed_ms": self.elapsed_ms,
            "by_category": self.by_category,
        })
        .to_string()
    }
}

#[derive(Clone, Debug, Default, serde::Serialize)]
struct CategoryMetric {
    total_rows: usize,
    tp: usize,
    fp: usize,
    #[serde(rename = "fn")]
    fn_: usize,
    line_only: usize,
    precision: f64,
    recall: f64,
    f1: f64,
}

impl CategoryMetric {
    fn finish(&mut self) {
        self.precision = ratio(self.tp, self.tp + self.fp);
        self.recall = ratio(self.tp, self.tp + self.fn_);
        self.f1 = if self.precision + self.recall == 0.0 {
            0.0
        } else {
            2.0 * self.precision * self.recall / (self.precision + self.recall)
        };
    }
}

fn ratio(num: usize, den: usize) -> f64 {
    if den == 0 {
        1.0
    } else {
        num as f64 / den as f64
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn creddata_runner_scores_true_and_false_rows() {
        let root = temp_root("pentect-creddata-bench");
        let meta = root.join("meta");
        let data = root.join("data").join("repo").join("_");
        std::fs::create_dir_all(&meta).unwrap();
        std::fs::create_dir_all(&data).unwrap();
        let true_line = "RUNPOD_API_KEY=rpa_FAKEPENTECTBENCH1234567890abcd";
        let false_line = "RUNPOD_API_KEY=rpa_FALSEPENTECTBENCH1234567890abcd";
        std::fs::write(data.join("f.env"), format!("{true_line}\n{false_line}\n")).unwrap();
        let start = true_line.find("rpa_").unwrap();
        let end = true_line.len();
        std::fs::write(
            meta.join("repo.csv"),
            format!(
                "Id,FileID,Domain,RepoName,FilePath,LineStart,LineEnd,GroundTruth,ValueStart,ValueEnd,CryptographyKey,PredefinedPattern,Category\n\
                 1,f,GitHub,repo,data/repo/_/f.env,1,1,T,{start},{end},,,API:Key\n\
                 2,f,GitHub,repo,data/repo/_/f.env,2,2,F,{start},{end},,,API:Key\n"
            ),
        )
        .unwrap();

        let args = vec![
            "pentect".to_string(),
            "bench".to_string(),
            "creddata".to_string(),
            root.to_string_lossy().to_string(),
        ];
        let opts = BenchOpts::parse(&args).unwrap();
        let report = run_creddata(&root, &opts).unwrap();

        assert_eq!(report.true_rows, 1);
        assert_eq!(report.false_rows, 1);
        assert_eq!(report.tp, 1);
        assert!(report.fp >= 1, "expected false row detection");
        assert_eq!(report.fn_, 0);

        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn bench_args_parse_thresholds() {
        let args = vec![
            "pentect".to_string(),
            "bench".to_string(),
            "creddata".to_string(),
            "CredData".to_string(),
            "--json".to_string(),
            "--limit".to_string(),
            "10".to_string(),
            "--repo".to_string(),
            "abc".to_string(),
            "--ignore-x".to_string(),
            "--min-precision".to_string(),
            "0.8".to_string(),
            "--min-recall".to_string(),
            "0.7".to_string(),
        ];
        let opts = BenchOpts::parse(&args).unwrap();
        assert!(opts.json);
        assert_eq!(opts.limit, Some(10));
        assert_eq!(opts.repo.as_deref(), Some("abc"));
        assert!(opts.ignore_x);
        assert_eq!(opts.min_precision, Some(0.8));
        assert_eq!(opts.min_recall, Some(0.7));
    }

    #[test]
    fn line_index_uses_zero_based_value_columns() {
        let text = "abc=secret\nnext";
        let lines = LineIndex::new(text);
        assert_eq!(lines.value_range(1, 4, 10), Some(ByteRange::new(4, 10)));
    }

    fn temp_root(prefix: &str) -> PathBuf {
        let root = std::env::temp_dir().join(format!(
            "{}-{}-{}",
            prefix,
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_millis()
        ));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).unwrap();
        root
    }
}

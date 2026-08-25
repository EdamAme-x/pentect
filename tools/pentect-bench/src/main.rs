use pentect_core::normalize::NormalizedView;
use pentect_core::{
    infer_kind, ByteRange, Category, Context, CredSweeperFilterProbe, CredSweeperNativeDetector,
    CredSweeperNativeFinding, Engine, Input, Profile, Region, RegionKind, Span,
};
use serde::{Deserialize, Serialize};
use serde_json::json;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::fmt::Write as _;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{mpsc, Arc};
use std::time::Instant;

fn main() {
    let args = std::env::args().skip(1).collect::<Vec<_>>();
    cmd_bench(&args);
}

fn die(msg: impl std::fmt::Display) -> ! {
    eprintln!("[pentect-bench] {msg}");
    std::process::exit(2);
}

fn cmd_bench(args: &[String]) {
    if args.first().map(String::as_str) == Some("credsweeper-scan") {
        if args.len() < 2 {
            die("usage: pentect-bench credsweeper-scan PATH...");
        }
        let mut credentials = Vec::new();
        for value in &args[1..] {
            let path = Path::new(value);
            let raw = std::fs::read_to_string(path)
                .map(normalize_newlines)
                .unwrap_or_else(|error| {
                    die(format!("could not read '{}': {error}", path.display()))
                });
            let line_index = LineIndex::new(&raw);
            credentials.extend(detect_credsweeper_json(path, &raw, &line_index));
        }
        println!(
            "{}",
            serde_json::to_string(&credentials).unwrap_or_else(|error| die(error))
        );
        return;
    }
    if args.first().map(String::as_str) == Some("credsweeper-filter-probe") {
        let Some(path) = args.get(1) else {
            die("usage: pentect-bench credsweeper-filter-probe PROBES.json");
        };
        let source = std::fs::read(path).unwrap_or_else(|error| die(error));
        let probes: Vec<CredSweeperFilterProbe> =
            serde_json::from_slice(&source).unwrap_or_else(|error| die(error));
        let results = probes
            .iter()
            .map(CredSweeperFilterProbe::is_filtered)
            .collect::<Vec<_>>();
        println!(
            "{}",
            serde_json::to_string(&results).unwrap_or_else(|error| die(error))
        );
        return;
    }
    if args.first().map(String::as_str) == Some("credsweeper-parity") {
        let opts = match CredSweeperParityOpts::parse(args) {
            Ok(opts) => opts,
            Err(e) => die(e),
        };
        let report = match run_credsweeper_parity(&opts) {
            Ok(report) => report,
            Err(e) => die(e),
        };
        if opts.json {
            println!("{}", report.to_json());
        } else {
            println!(
                "pentect-bench credsweeper-parity rust={} oracle={} common={} missing={} extra={} precision={:.3} recall={:.3} f1={:.3}",
                report.rust_count,
                report.oracle_count,
                report.common,
                report.missing,
                report.extra,
                report.precision,
                report.recall,
                report.f1
            );
            for example in &report.missing_examples {
                println!("missing {}", example);
            }
            for example in &report.extra_examples {
                println!("extra {}", example);
            }
        }
        if report.precision < opts.min_precision
            || report.recall < opts.min_recall
            || !report.ml_probability_within_tolerance
        {
            std::process::exit(1);
        }
        return;
    }

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
    if let Some(path) = &opts.save_credsweeper_json {
        if let Err(e) = save_credsweeper_json(path, &report.credsweeper_json) {
            die(e);
        }
    }
    if let Some(path) = &opts.save_credsweeper_paths {
        if let Err(e) = save_credsweeper_paths(path, &report.credsweeper_paths) {
            die(e);
        }
    }
    if opts.json {
        println!("{}", report.to_json());
    } else {
        println!(
            "pentect-bench creddata rows={} files={} precision={:.3} recall={:.3} f1={:.3}",
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
        if !report.by_detection.is_empty() {
            let mut parts = report
                .by_detection
                .iter()
                .map(|(label, metric)| {
                    (
                        metric.fp,
                        format!("{}:{}/{}/{}", label, metric.tp, metric.fp, metric.unlabeled),
                    )
                })
                .collect::<Vec<_>>();
            parts.sort_by(|a, b| b.0.cmp(&a.0).then(a.1.cmp(&b.1)));
            println!(
                "detections {}",
                parts
                    .into_iter()
                    .take(12)
                    .map(|(_, part)| part)
                    .collect::<Vec<_>>()
                    .join(" ")
            );
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
    examples: usize,
    min_precision: Option<f64>,
    min_recall: Option<f64>,
    save_credsweeper_json: Option<PathBuf>,
    save_credsweeper_paths: Option<PathBuf>,
}

#[derive(Clone, Debug)]
enum Dataset {
    CredData { path: PathBuf },
}

impl BenchOpts {
    fn parse(args: &[String]) -> Result<Self, String> {
        let Some(dataset) = args.first().map(String::as_str) else {
            return Err("pentect-bench creddata PATH".to_string());
        };
        match dataset {
            "creddata" => Self::parse_creddata(args),
            other => Err(format!("unknown benchmark: {other}")),
        }
    }

    fn parse_creddata(args: &[String]) -> Result<Self, String> {
        let Some(path) = args.get(1) else {
            return Err("pentect-bench creddata PATH".to_string());
        };
        let mut json = false;
        let mut limit = None;
        let mut repo = None;
        let mut ignore_x = false;
        let mut examples = 0usize;
        let mut min_precision = None;
        let mut min_recall = None;
        let mut save_credsweeper_json = None;
        let mut save_credsweeper_paths = None;
        let mut i = 2usize;
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
                "--examples" => {
                    examples = parse_usize_arg(args, &mut i, "--examples")?;
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
                "--save-credsweeper-json" => {
                    save_credsweeper_json = Some(PathBuf::from(required_value(
                        args,
                        &mut i,
                        "--save-credsweeper-json",
                    )?));
                }
                "--save-credsweeper-paths" => {
                    save_credsweeper_paths = Some(PathBuf::from(required_value(
                        args,
                        &mut i,
                        "--save-credsweeper-paths",
                    )?));
                }
                flag if flag.starts_with("--") => return Err(format!("unknown option: {flag}")),
                value => return Err(format!("unexpected argument for pentect-bench: {value}")),
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
            examples,
            min_precision,
            min_recall,
            save_credsweeper_json,
            save_credsweeper_paths,
        })
    }
}

#[derive(Clone, Debug)]
struct CredSweeperParityOpts {
    rust_json: PathBuf,
    oracle_json: PathBuf,
    json: bool,
    examples: usize,
    min_precision: f64,
    min_recall: f64,
}

impl CredSweeperParityOpts {
    fn parse(args: &[String]) -> Result<Self, String> {
        let Some(rust_json) = args.get(1) else {
            return Err("pentect-bench credsweeper-parity RUST_JSON ORACLE_JSON".to_string());
        };
        let Some(oracle_json) = args.get(2) else {
            return Err("pentect-bench credsweeper-parity RUST_JSON ORACLE_JSON".to_string());
        };
        let mut json = false;
        let mut examples = 10usize;
        let mut min_precision = 1.0;
        let mut min_recall = 1.0;
        let mut i = 3usize;
        while i < args.len() {
            match args[i].as_str() {
                "--json" => {
                    json = true;
                    i += 1;
                }
                "--examples" => {
                    examples = parse_usize_arg(args, &mut i, "--examples")?;
                }
                "--min-precision" => {
                    min_precision = parse_f64_arg(args, &mut i, "--min-precision")?;
                }
                "--min-recall" => {
                    min_recall = parse_f64_arg(args, &mut i, "--min-recall")?;
                }
                flag if flag.starts_with("--") => return Err(format!("unknown option: {flag}")),
                value => return Err(format!("unexpected argument for pentect-bench: {value}")),
            }
        }
        Ok(Self {
            rust_json: PathBuf::from(rust_json),
            oracle_json: PathBuf::from(oracle_json),
            json,
            examples,
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

    let mut report = BenchReport {
        files: by_file.len(),
        ..BenchReport::default()
    };
    let files = by_file.into_iter().collect::<Vec<_>>();
    report.credsweeper_paths = files
        .iter()
        .map(|(path, _)| path.display().to_string())
        .collect();

    for file_report in
        score_creddata_files(files, opts.examples, opts.save_credsweeper_json.is_some())?
    {
        report.merge(file_report, opts.examples);
    }

    report.elapsed_ms = started.elapsed().as_millis();
    report.finish();
    Ok(report)
}

fn score_creddata_files(
    files: Vec<(PathBuf, Vec<CredRow>)>,
    example_limit: usize,
    export_credsweeper_json: bool,
) -> Result<Vec<BenchReport>, String> {
    if files.is_empty() {
        return Ok(Vec::new());
    }
    let workers = std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(1)
        .min(8)
        .min(files.len());
    let files = Arc::new(files);
    let next = Arc::new(AtomicUsize::new(0));
    let (tx, rx) = mpsc::channel();

    std::thread::scope(|scope| {
        for _ in 0..workers {
            let files = Arc::clone(&files);
            let next = Arc::clone(&next);
            let tx = tx.clone();
            scope.spawn(move || {
                let mut engine =
                    Engine::secret_scan_with_profile_and_packs(Profile::Strict, Vec::new());
                loop {
                    let index = next.fetch_add(1, Ordering::Relaxed);
                    let Some((path, rows)) = files.get(index) else {
                        break;
                    };
                    let result = score_creddata_file(
                        path,
                        rows,
                        &mut engine,
                        example_limit,
                        export_credsweeper_json,
                    );
                    if tx.send((index, result)).is_err() {
                        break;
                    }
                }
            });
        }
        drop(tx);
        let mut reports = rx.into_iter().collect::<Vec<_>>();
        reports.sort_by_key(|(index, _)| *index);
        reports
            .into_iter()
            .map(|(_, result)| result)
            .collect::<Result<Vec<_>, _>>()
    })
}

fn score_creddata_file(
    path: &Path,
    rows: &[CredRow],
    engine: &mut Engine,
    example_limit: usize,
    export_credsweeper_json: bool,
) -> Result<BenchReport, String> {
    let raw = match std::fs::read_to_string(path) {
        Ok(raw) => normalize_newlines(raw),
        Err(_) => {
            return Ok(BenchReport {
                missing_files: 1,
                skipped_rows: rows.len(),
                ..BenchReport::default()
            });
        }
    };
    let line_index = LineIndex::new(&raw);
    let mut cases = Vec::new();
    let mut report = BenchReport::default();
    for row in rows.iter().cloned() {
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
        return Ok(report);
    }

    let spans = engine
        .analyze_spans(Input {
            kind: infer_kind(path),
            data: raw.clone(),
        })
        .spans
        .into_iter()
        .filter(|span| span.category == Category::Secret)
        .collect::<Vec<_>>();
    score_file(&raw, &cases, &spans, &mut report, example_limit);
    if export_credsweeper_json {
        report.credsweeper_json = detect_credsweeper_json(path, &raw, &line_index);
    }
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

fn score_file(
    raw: &str,
    cases: &[BenchCase],
    spans: &[Span],
    report: &mut BenchReport,
    example_limit: usize,
) {
    let index = ScoreIndex::new(cases, spans);
    let mut true_hits = BTreeMap::new();
    let mut line_only_hits = BTreeSet::new();
    for (i, case) in cases.iter().enumerate() {
        if case.truth != Truth::True {
            continue;
        }
        if let Some(span) = index.strongest_overlap(case.strict_range) {
            true_hits.insert(i, detection_key(span));
        } else if index.any_span_overlap(case.line_range) {
            line_only_hits.insert(i);
        }
    }

    for (i, case) in cases.iter().enumerate() {
        match case.truth {
            Truth::True if true_hits.contains_key(&i) => {
                report.tp += 1;
                let key = &true_hits[&i];
                report.by_detection.entry(key.clone()).or_default().tp += 1;
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
                let line_only = line_only_hits.contains(&i);
                if line_only {
                    report.line_only += 1;
                }
                maybe_push_example(
                    report,
                    example_limit,
                    if line_only { "line_only" } else { "fn" },
                    "missed",
                    case.category.as_str(),
                    case.path.as_path(),
                    case.line_start,
                    raw,
                    case.strict_range,
                );
                for category in category_parts(&case.category) {
                    let metric = report.by_category.entry(category.to_string()).or_default();
                    metric.fn_ += 1;
                    if line_only {
                        metric.line_only += 1;
                    }
                }
            }
            Truth::False => {}
        }
    }

    for span in spans {
        if index.any_true_case_overlap(span.range) {
            continue;
        }
        if let Some(case) = index.first_false_case_overlap(span.range) {
            report.fp += 1;
            let key = detection_key(span);
            report.by_detection.entry(key.clone()).or_default().fp += 1;
            maybe_push_example(
                report,
                example_limit,
                "fp",
                &key,
                case.category.as_str(),
                case.path.as_path(),
                case.line_start,
                raw,
                span.range,
            );
            for category in category_parts(&case.category) {
                report
                    .by_category
                    .entry(category.to_string())
                    .or_default()
                    .fp += 1;
            }
        } else {
            report.unlabeled += 1;
            let key = detection_key(span);
            report
                .by_detection
                .entry(key.clone())
                .or_default()
                .unlabeled += 1;
            maybe_push_example(
                report,
                example_limit,
                "unlabeled",
                &key,
                "",
                Path::new(""),
                line_number(raw, span.range.start),
                raw,
                span.range,
            );
        }
    }
}

struct ScoreIndex<'a> {
    cases: &'a [BenchCase],
    spans: &'a [Span],
    spans_by_start: Vec<usize>,
    true_cases_by_start: Vec<usize>,
    false_cases_by_start: Vec<usize>,
}

impl<'a> ScoreIndex<'a> {
    fn new(cases: &'a [BenchCase], spans: &'a [Span]) -> Self {
        let mut spans_by_start = (0..spans.len()).collect::<Vec<_>>();
        spans_by_start.sort_by_key(|&i| (spans[i].range.start, i));

        let mut true_cases_by_start = cases
            .iter()
            .enumerate()
            .filter_map(|(i, case)| (case.truth == Truth::True).then_some(i))
            .collect::<Vec<_>>();
        true_cases_by_start.sort_by_key(|&i| (cases[i].strict_range.start, i));

        let mut false_cases_by_start = cases
            .iter()
            .enumerate()
            .filter_map(|(i, case)| (case.truth == Truth::False).then_some(i))
            .collect::<Vec<_>>();
        false_cases_by_start.sort_by_key(|&i| (cases[i].line_range.start, i));

        Self {
            cases,
            spans,
            spans_by_start,
            true_cases_by_start,
            false_cases_by_start,
        }
    }

    fn strongest_overlap(&self, range: ByteRange) -> Option<&'a Span> {
        let mut best = None;
        for span_index in self.span_candidates(range) {
            let span = &self.spans[span_index];
            if !span.range.overlaps(&range) {
                continue;
            }
            let replace = match best {
                None => true,
                Some(best_index) => match span.cmp_strength(&self.spans[best_index]) {
                    std::cmp::Ordering::Greater => true,
                    std::cmp::Ordering::Equal => span_index > best_index,
                    std::cmp::Ordering::Less => false,
                },
            };
            if replace {
                best = Some(span_index);
            }
        }
        best.map(|i| &self.spans[i])
    }

    fn any_span_overlap(&self, range: ByteRange) -> bool {
        self.span_candidates(range)
            .any(|i| self.spans[i].range.overlaps(&range))
    }

    fn any_true_case_overlap(&self, range: ByteRange) -> bool {
        let end = self
            .true_cases_by_start
            .partition_point(|&i| self.cases[i].strict_range.start < range.end);
        self.true_cases_by_start[..end]
            .iter()
            .any(|&i| self.cases[i].strict_range.overlaps(&range))
    }

    fn first_false_case_overlap(&self, range: ByteRange) -> Option<&'a BenchCase> {
        let end = self
            .false_cases_by_start
            .partition_point(|&i| self.cases[i].line_range.start < range.end);
        self.false_cases_by_start[..end]
            .iter()
            .copied()
            .filter(|&i| self.cases[i].line_range.overlaps(&range))
            .min()
            .map(|i| &self.cases[i])
    }

    fn span_candidates(&self, range: ByteRange) -> impl Iterator<Item = usize> + '_ {
        let end = self
            .spans_by_start
            .partition_point(|&i| self.spans[i].range.start < range.end);
        self.spans_by_start[..end].iter().copied()
    }
}

fn detect_credsweeper_json(
    path: &Path,
    raw: &str,
    line_index: &LineIndex,
) -> Vec<CredSweeperJsonCredential> {
    let detector = CredSweeperNativeDetector::builtin();
    let path_string = path.to_string_lossy().to_string();
    let region = Region {
        span: ByteRange::new(0, raw.len()),
        ctx: Context {
            path: Some(path_string.clone()),
            key: None,
            hints: Vec::new(),
            kind: RegionKind::PlainText,
            format: infer_kind(path),
        },
    };
    let view = NormalizedView::build(&region, raw);
    detector
        .detect_findings(&view)
        .into_iter()
        .filter_map(|finding| {
            let line_data_list =
                line_index.credsweeper_line_data(path_string.as_str(), &finding)?;
            Some(CredSweeperJsonCredential {
                rule: finding.rule_name,
                severity: finding.severity,
                confidence: finding.confidence_name,
                ml_probability: finding.ml_probability,
                line_data_list,
            })
        })
        .collect()
}

fn save_credsweeper_json(
    path: &Path,
    credentials: &[CredSweeperJsonCredential],
) -> Result<(), String> {
    let data = serde_json::to_vec_pretty(credentials)
        .map_err(|e| format!("could not serialize CredSweeper json: {e}"))?;
    std::fs::write(path, data).map_err(|e| format!("could not write '{}': {e}", path.display()))
}

fn save_credsweeper_paths(path: &Path, paths: &[String]) -> Result<(), String> {
    let mut data = paths.join("\n");
    if !data.is_empty() {
        data.push('\n');
    }
    std::fs::write(path, data).map_err(|e| format!("could not write '{}': {e}", path.display()))
}

fn run_credsweeper_parity(opts: &CredSweeperParityOpts) -> Result<CredSweeperParityReport, String> {
    let rust_credentials = load_credsweeper_json(&opts.rust_json)?;
    let oracle_credentials = load_credsweeper_json(&opts.oracle_json)?;
    let ml_probability_max_delta =
        credsweeper_ml_probability_max_delta(&rust_credentials, &oracle_credentials);
    let rust = credsweeper_parity_multiset(&rust_credentials);
    let oracle = credsweeper_parity_multiset(&oracle_credentials);
    Ok(CredSweeperParityReport::build(
        rust,
        oracle,
        opts.examples,
        ml_probability_max_delta,
    ))
}

fn load_credsweeper_json(path: &Path) -> Result<Vec<CredSweeperJsonCredential>, String> {
    let data = std::fs::read_to_string(path)
        .map_err(|e| format!("could not read '{}': {e}", path.display()))?;
    let data = data.strip_prefix('\u{feff}').unwrap_or(&data);
    serde_json::from_str(data)
        .map_err(|e| format!("could not parse CredSweeper json '{}': {e}", path.display()))
}

fn credsweeper_parity_multiset(
    credentials: &[CredSweeperJsonCredential],
) -> BTreeMap<CredSweeperParityKey, usize> {
    let mut out = BTreeMap::new();
    for credential in credentials {
        for line_data in &credential.line_data_list {
            *out.entry(CredSweeperParityKey::new(credential, line_data))
                .or_insert(0) += 1;
        }
    }
    out
}

const CREDSWEEPER_ML_PROBABILITY_TOLERANCE: f64 = 0.0001;

fn credsweeper_ml_probability_max_delta(
    rust: &[CredSweeperJsonCredential],
    oracle: &[CredSweeperJsonCredential],
) -> f64 {
    fn probabilities(
        credentials: &[CredSweeperJsonCredential],
    ) -> BTreeMap<CredSweeperParityKey, Vec<f64>> {
        let mut out = BTreeMap::<_, Vec<_>>::new();
        for credential in credentials {
            let Some(probability) = credential.ml_probability else {
                continue;
            };
            for line_data in &credential.line_data_list {
                out.entry(CredSweeperParityKey::new(credential, line_data))
                    .or_default()
                    .push(probability);
            }
        }
        for values in out.values_mut() {
            values.sort_by(f64::total_cmp);
        }
        out
    }

    let rust = probabilities(rust);
    let oracle = probabilities(oracle);
    let mut max_delta = 0.0_f64;
    for (key, rust_values) in &rust {
        let Some(oracle_values) = oracle.get(key) else {
            continue;
        };
        for (rust_value, oracle_value) in rust_values.iter().zip(oracle_values) {
            let delta = (rust_value - oracle_value).abs();
            if !delta.is_finite() {
                return f64::INFINITY;
            }
            max_delta = max_delta.max(delta);
        }
    }
    max_delta
}

#[allow(clippy::too_many_arguments)]
fn maybe_push_example(
    report: &mut BenchReport,
    example_limit: usize,
    kind: &str,
    detection: &str,
    category: &str,
    path: &Path,
    line: usize,
    raw: &str,
    range: ByteRange,
) {
    if report.examples.len() >= example_limit {
        return;
    }
    report.examples.push(BenchExample {
        kind: kind.to_string(),
        detection: detection.to_string(),
        category: category.to_string(),
        path: path.display().to_string(),
        line,
        value: clipped(&raw[range.start..range.end], 120),
        excerpt: excerpt(raw, range),
    });
}

fn line_number(raw: &str, offset: usize) -> usize {
    raw.as_bytes()[..offset.min(raw.len())]
        .iter()
        .filter(|&&b| b == b'\n')
        .count()
        + 1
}

fn excerpt(raw: &str, range: ByteRange) -> String {
    let line_start = raw[..range.start]
        .rfind('\n')
        .map_or(0, |offset| offset + 1);
    let line_end = raw[range.end..]
        .find('\n')
        .map_or(raw.len(), |offset| range.end + offset);
    let line = raw[line_start..line_end].trim();
    clipped(line, 240)
}

fn clipped(value: &str, max_chars: usize) -> String {
    if value.chars().count() <= max_chars {
        value.to_string()
    } else {
        value
            .chars()
            .take(max_chars.saturating_sub(3))
            .chain("...".chars())
            .collect()
    }
}

fn detection_key(span: &Span) -> String {
    format!("{}:{}", span.source.as_str(), span.label)
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
    path: PathBuf,
    line_start: usize,
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
            path: row.path,
            line_start: row.line_start,
        })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Truth {
    True,
    False,
}

#[derive(Clone, Debug)]
struct LineIndex<'a> {
    text: &'a str,
    starts: Vec<usize>,
}

impl<'a> LineIndex<'a> {
    fn new(text: &'a str) -> Self {
        let mut starts = vec![0];
        for (i, byte) in text.bytes().enumerate() {
            if byte == b'\n' {
                starts.push(i + 1);
            }
        }
        Self { text, starts }
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

    fn credsweeper_line_data(
        &self,
        path: &str,
        finding: &CredSweeperNativeFinding,
    ) -> Option<Vec<CredSweeperJsonLineData>> {
        let mut out = Vec::new();
        if !finding.line_data.is_empty() {
            for line_data in &finding.line_data {
                out.extend(self.credsweeper_line_data_part(
                    path,
                    line_data.range,
                    line_data.variable.as_deref(),
                    line_data.variable_start,
                    line_data.variable_end,
                )?);
            }
            return Some(out);
        }
        out.extend(self.credsweeper_line_data_part(
            path,
            finding.range,
            finding.variable.as_deref(),
            finding.variable_start,
            finding.variable_end,
        )?);
        Some(out)
    }

    fn credsweeper_line_data_part(
        &self,
        path: &str,
        range: ByteRange,
        variable: Option<&str>,
        variable_start: Option<usize>,
        variable_end: Option<usize>,
    ) -> Option<Vec<CredSweeperJsonLineData>> {
        let start_line = self.line_for_offset(range.start)?;
        let end_line = if range.is_empty() {
            start_line
        } else {
            self.line_for_offset(range.end - 1)?
        };
        let mut out = Vec::new();
        for line_num in start_line..=end_line {
            let line_start = *self.starts.get(line_num.checked_sub(1)?)?;
            let line_end = self.line_end(line_num)?;
            let value_start_byte = if line_num == start_line {
                range.start
            } else {
                line_start
            };
            let value_end_byte = if line_num == end_line {
                range.end
            } else {
                line_end
            };
            if value_start_byte > value_end_byte || value_end_byte > line_end {
                return None;
            }
            let line = self.text[line_start..line_end].to_string();
            let value = self.text[value_start_byte..value_end_byte].to_string();
            let (variable, variable_start, variable_end) = if line_num == start_line {
                match (variable, variable_start, variable_end) {
                    (Some(variable), Some(start), Some(end)) => {
                        match local_line_offsets(line_start, line_end, start, end) {
                            Some((start, end)) => (
                                Some(variable.to_string()),
                                char_col_from_byte(&self.text[line_start..line_end], start)
                                    as isize,
                                char_col_from_byte(&self.text[line_start..line_end], end) as isize,
                            ),
                            None => (None, -2, -2),
                        }
                    }
                    _ => (None, -2, -2),
                }
            } else {
                (None, -2, -2)
            };
            out.push(CredSweeperJsonLineData {
                line,
                line_num,
                path: path.to_string(),
                info: String::new(),
                variable,
                variable_start,
                variable_end,
                value_start: char_col_from_byte(
                    &self.text[line_start..line_end],
                    value_start_byte - line_start,
                ),
                value_end: char_col_from_byte(
                    &self.text[line_start..line_end],
                    value_end_byte - line_start,
                ),
                entropy: shannon_entropy(&value),
                value,
            });
        }
        Some(out)
    }

    fn line_for_offset(&self, offset: usize) -> Option<usize> {
        if offset > self.text.len() {
            return None;
        }
        let idx = self.starts.partition_point(|start| *start <= offset);
        Some(idx.max(1))
    }
}

fn local_line_offsets(
    line_start: usize,
    line_end: usize,
    start: usize,
    end: usize,
) -> Option<(usize, usize)> {
    if start >= end {
        return None;
    }
    let line_len = line_end.saturating_sub(line_start);
    if end <= line_len {
        return Some((start, end));
    }
    if line_start <= start && end <= line_end {
        return Some((start - line_start, end - line_start));
    }
    None
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

fn char_col_from_byte(text: &str, byte: usize) -> usize {
    text[..byte.min(text.len())].chars().count()
}

fn shannon_entropy(value: &str) -> f64 {
    if value.is_empty() {
        return 0.0;
    }
    let mut counts = BTreeMap::new();
    for ch in value.chars() {
        *counts.entry(ch).or_insert(0usize) += 1;
    }
    let len = value.chars().count() as f64;
    let entropy = counts
        .values()
        .map(|count| {
            let p = *count as f64 / len;
            -p * p.log2()
        })
        .sum::<f64>();
    (entropy * 100_000.0).round() / 100_000.0
}

#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd)]
struct CredSweeperParityKey {
    rule: String,
    severity: String,
    confidence: String,
    has_ml_probability: bool,
    path: String,
    line: String,
    line_num: usize,
    info: String,
    value_start: usize,
    value_end: usize,
    variable_start: isize,
    variable_end: isize,
    variable: Option<String>,
    value: String,
    entropy_bits: u64,
}

impl CredSweeperParityKey {
    fn new(credential: &CredSweeperJsonCredential, line_data: &CredSweeperJsonLineData) -> Self {
        Self {
            rule: credential.rule.clone(),
            severity: credential.severity.clone(),
            confidence: credential.confidence.clone(),
            has_ml_probability: credential.ml_probability.is_some(),
            path: normalize_parity_path(&line_data.path),
            line: line_data.line.clone(),
            line_num: line_data.line_num,
            info: line_data.info.clone(),
            value_start: line_data.value_start,
            value_end: line_data.value_end,
            variable_start: line_data.variable_start,
            variable_end: line_data.variable_end,
            variable: line_data.variable.clone(),
            value: line_data.value.clone(),
            entropy_bits: line_data.entropy.to_bits(),
        }
    }

    fn to_example(&self, count: usize) -> CredSweeperParityExample {
        CredSweeperParityExample {
            count,
            rule: self.rule.clone(),
            path: self.path.clone(),
            line_num: self.line_num,
            value_start: self.value_start,
            value_end: self.value_end,
            variable_start: self.variable_start,
            variable_end: self.variable_end,
            value_len: self.value.chars().count(),
            value_sha256: sha256_hex_prefix(&self.value, 16),
        }
    }
}

#[derive(Clone, Debug, Serialize)]
struct CredSweeperParityExample {
    count: usize,
    rule: String,
    path: String,
    line_num: usize,
    value_start: usize,
    value_end: usize,
    variable_start: isize,
    variable_end: isize,
    value_len: usize,
    value_sha256: String,
}

impl fmt::Display for CredSweeperParityExample {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "count={} rule={} path={} line={} cols={}-{} var_cols={}-{} len={} sha256={}",
            self.count,
            self.rule,
            self.path,
            self.line_num,
            self.value_start,
            self.value_end,
            self.variable_start,
            self.variable_end,
            self.value_len,
            self.value_sha256
        )
    }
}

#[derive(Clone, Debug, Serialize)]
struct CredSweeperParityReport {
    dataset: &'static str,
    #[serde(rename = "rust")]
    rust_count: usize,
    #[serde(rename = "oracle")]
    oracle_count: usize,
    common: usize,
    missing: usize,
    extra: usize,
    precision: f64,
    recall: f64,
    f1: f64,
    ml_probability_max_delta: f64,
    ml_probability_tolerance: f64,
    ml_probability_within_tolerance: bool,
    missing_examples: Vec<CredSweeperParityExample>,
    extra_examples: Vec<CredSweeperParityExample>,
}

impl CredSweeperParityReport {
    fn build(
        rust: BTreeMap<CredSweeperParityKey, usize>,
        oracle: BTreeMap<CredSweeperParityKey, usize>,
        example_limit: usize,
        ml_probability_max_delta: f64,
    ) -> Self {
        let rust_count = multiset_len(&rust);
        let oracle_count = multiset_len(&oracle);
        let mut common = 0usize;
        let mut missing = 0usize;
        let mut extra = 0usize;
        let mut missing_examples = Vec::new();
        let mut extra_examples = Vec::new();

        for (key, oracle_seen) in &oracle {
            let rust_seen = rust.get(key).copied().unwrap_or(0);
            common += (*oracle_seen).min(rust_seen);
            if *oracle_seen > rust_seen {
                let count = *oracle_seen - rust_seen;
                missing += count;
                if missing_examples.len() < example_limit {
                    missing_examples.push(key.to_example(count));
                }
            }
        }

        for (key, rust_seen) in &rust {
            let oracle_seen = oracle.get(key).copied().unwrap_or(0);
            if *rust_seen > oracle_seen {
                let count = *rust_seen - oracle_seen;
                extra += count;
                if extra_examples.len() < example_limit {
                    extra_examples.push(key.to_example(count));
                }
            }
        }

        let precision = ratio(common, rust_count);
        let recall = ratio(common, oracle_count);
        let f1 = if precision + recall == 0.0 {
            0.0
        } else {
            2.0 * precision * recall / (precision + recall)
        };
        Self {
            dataset: "credsweeper-parity",
            rust_count,
            oracle_count,
            common,
            missing,
            extra,
            precision,
            recall,
            f1,
            ml_probability_max_delta,
            ml_probability_tolerance: CREDSWEEPER_ML_PROBABILITY_TOLERANCE,
            ml_probability_within_tolerance: ml_probability_max_delta
                <= CREDSWEEPER_ML_PROBABILITY_TOLERANCE,
            missing_examples,
            extra_examples,
        }
    }

    fn to_json(&self) -> String {
        match serde_json::to_string(self) {
            Ok(data) => data,
            Err(e) => json!({ "error": e.to_string() }).to_string(),
        }
    }
}

fn multiset_len<T: Ord>(values: &BTreeMap<T, usize>) -> usize {
    values.values().sum()
}

fn normalize_parity_path(path: &str) -> String {
    path.replace('\\', "/")
}

fn sha256_hex_prefix(value: &str, hex_chars: usize) -> String {
    let digest = Sha256::digest(value.as_bytes());
    let mut out = String::with_capacity(hex_chars);
    for byte in digest {
        let _ = write!(out, "{byte:02x}");
        if out.len() >= hex_chars {
            out.truncate(hex_chars);
            break;
        }
    }
    out
}

#[derive(Clone, Debug, Deserialize, Serialize)]
struct CredSweeperJsonCredential {
    rule: String,
    #[serde(default)]
    severity: String,
    #[serde(default)]
    confidence: String,
    #[serde(default)]
    ml_probability: Option<f64>,
    #[serde(default)]
    line_data_list: Vec<CredSweeperJsonLineData>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
struct CredSweeperJsonLineData {
    #[serde(default)]
    line: String,
    #[serde(default)]
    line_num: usize,
    #[serde(default)]
    path: String,
    #[serde(default)]
    info: String,
    #[serde(default)]
    variable: Option<String>,
    #[serde(default)]
    variable_start: isize,
    #[serde(default)]
    variable_end: isize,
    #[serde(default)]
    value: String,
    #[serde(default)]
    value_start: usize,
    #[serde(default)]
    value_end: usize,
    #[serde(default)]
    entropy: f64,
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
    by_detection: BTreeMap<String, DetectionMetric>,
    examples: Vec<BenchExample>,
    credsweeper_json: Vec<CredSweeperJsonCredential>,
    credsweeper_paths: Vec<String>,
}

impl BenchReport {
    fn merge(&mut self, other: BenchReport, example_limit: usize) {
        self.rows += other.rows;
        self.true_rows += other.true_rows;
        self.false_rows += other.false_rows;
        self.tp += other.tp;
        self.fp += other.fp;
        self.fn_ += other.fn_;
        self.line_only += other.line_only;
        self.unlabeled += other.unlabeled;
        self.missing_files += other.missing_files;
        self.invalid_rows += other.invalid_rows;
        self.skipped_rows += other.skipped_rows;
        for (category, metric) in other.by_category {
            self.by_category.entry(category).or_default().add(metric);
        }
        for (detection, metric) in other.by_detection {
            self.by_detection.entry(detection).or_default().add(metric);
        }
        self.credsweeper_json.extend(other.credsweeper_json);
        if self.examples.len() < example_limit {
            self.examples.extend(
                other
                    .examples
                    .into_iter()
                    .take(example_limit - self.examples.len()),
            );
        }
    }

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
        for metric in self.by_detection.values_mut() {
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
            "by_detection": self.by_detection,
            "examples": self.examples,
        })
        .to_string()
    }
}

#[derive(Clone, Debug, serde::Serialize)]
struct BenchExample {
    kind: String,
    detection: String,
    category: String,
    path: String,
    line: usize,
    value: String,
    excerpt: String,
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

#[derive(Clone, Debug, Default, serde::Serialize)]
struct DetectionMetric {
    tp: usize,
    fp: usize,
    unlabeled: usize,
    precision: f64,
}

impl DetectionMetric {
    fn add(&mut self, other: DetectionMetric) {
        self.tp += other.tp;
        self.fp += other.fp;
        self.unlabeled += other.unlabeled;
    }

    fn finish(&mut self) {
        self.precision = ratio(self.tp, self.tp + self.fp);
    }
}

impl CategoryMetric {
    fn add(&mut self, other: CategoryMetric) {
        self.total_rows += other.total_rows;
        self.tp += other.tp;
        self.fp += other.fp;
        self.fn_ += other.fn_;
        self.line_only += other.line_only;
    }

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

        let args = vec!["creddata".to_string(), root.to_string_lossy().to_string()];
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
            "creddata".to_string(),
            "CredData".to_string(),
            "--json".to_string(),
            "--limit".to_string(),
            "10".to_string(),
            "--repo".to_string(),
            "abc".to_string(),
            "--ignore-x".to_string(),
            "--examples".to_string(),
            "3".to_string(),
            "--min-precision".to_string(),
            "0.8".to_string(),
            "--min-recall".to_string(),
            "0.7".to_string(),
            "--save-credsweeper-json".to_string(),
            "out.json".to_string(),
            "--save-credsweeper-paths".to_string(),
            "paths.txt".to_string(),
        ];
        let opts = BenchOpts::parse(&args).unwrap();
        assert!(opts.json);
        assert_eq!(opts.limit, Some(10));
        assert_eq!(opts.repo.as_deref(), Some("abc"));
        assert!(opts.ignore_x);
        assert_eq!(opts.examples, 3);
        assert_eq!(opts.min_precision, Some(0.8));
        assert_eq!(opts.min_recall, Some(0.7));
        assert_eq!(
            opts.save_credsweeper_json.as_deref(),
            Some(Path::new("out.json"))
        );
        assert_eq!(
            opts.save_credsweeper_paths.as_deref(),
            Some(Path::new("paths.txt"))
        );
    }

    #[test]
    fn creddata_runner_records_credsweeper_paths() {
        let root = temp_root("pentect-creddata-paths");
        let meta = root.join("meta");
        let data = root.join("data").join("repo").join("_");
        std::fs::create_dir_all(&meta).unwrap();
        std::fs::create_dir_all(&data).unwrap();
        std::fs::write(data.join("f.env"), "KEY=false-positive\n").unwrap();
        std::fs::write(
            meta.join("repo.csv"),
            "Id,FileID,Domain,RepoName,FilePath,LineStart,LineEnd,GroundTruth,ValueStart,ValueEnd,CryptographyKey,PredefinedPattern,Category\n\
             1,f,GitHub,repo,data/repo/_/f.env,1,1,F,4,18,,,Key\n",
        )
        .unwrap();

        let args = vec!["creddata".to_string(), root.to_string_lossy().to_string()];
        let opts = BenchOpts::parse(&args).unwrap();
        let report = run_creddata(&root, &opts).unwrap();

        assert_eq!(report.credsweeper_paths.len(), 1);
        assert!(
            report.credsweeper_paths[0].ends_with("data/repo/_/f.env")
                || report.credsweeper_paths[0].ends_with("data\\repo\\_\\f.env")
        );
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn credsweeper_parity_args_parse() {
        let args = vec![
            "credsweeper-parity".to_string(),
            "rust.json".to_string(),
            "oracle.json".to_string(),
            "--json".to_string(),
            "--examples".to_string(),
            "4".to_string(),
            "--min-precision".to_string(),
            "0.999".to_string(),
            "--min-recall".to_string(),
            "0.998".to_string(),
        ];
        let opts = CredSweeperParityOpts::parse(&args).unwrap();
        assert_eq!(opts.rust_json, PathBuf::from("rust.json"));
        assert_eq!(opts.oracle_json, PathBuf::from("oracle.json"));
        assert!(opts.json);
        assert_eq!(opts.examples, 4);
        assert_eq!(opts.min_precision, 0.999);
        assert_eq!(opts.min_recall, 0.998);
    }

    #[test]
    fn credsweeper_parity_matches_identical_multisets() {
        let credentials = vec![sample_credsweeper_credential(
            "api-key",
            "src\\app.env",
            7,
            "RUNPOD_API_KEY",
            "value-one",
        )];
        let rust = credsweeper_parity_multiset(&credentials);
        let oracle = credsweeper_parity_multiset(&credentials);
        let report = CredSweeperParityReport::build(rust, oracle, 10, 0.0);

        assert_eq!(report.rust_count, 1);
        assert_eq!(report.oracle_count, 1);
        assert_eq!(report.common, 1);
        assert_eq!(report.missing, 0);
        assert_eq!(report.extra, 0);
        assert_eq!(report.precision, 1.0);
        assert_eq!(report.recall, 1.0);
    }

    #[test]
    fn credsweeper_parity_uses_the_official_cross_platform_ml_delta() {
        let mut rust = vec![sample_credsweeper_credential(
            "Password",
            "src/app.env",
            7,
            "PASSWORD",
            "value-one",
        )];
        let mut oracle = rust.clone();
        rust[0].ml_probability = Some(0.999_733_626_842_498_8);
        oracle[0].ml_probability = Some(0.999_733_686_447_143_6);
        let delta = credsweeper_ml_probability_max_delta(&rust, &oracle);
        let report = CredSweeperParityReport::build(
            credsweeper_parity_multiset(&rust),
            credsweeper_parity_multiset(&oracle),
            10,
            delta,
        );
        assert_eq!(report.common, 1);
        assert!(report.ml_probability_within_tolerance);
        assert!(report.ml_probability_max_delta < 0.0001);

        oracle[0].ml_probability = Some(0.9995);
        let delta = credsweeper_ml_probability_max_delta(&rust, &oracle);
        let report = CredSweeperParityReport::build(
            credsweeper_parity_multiset(&rust),
            credsweeper_parity_multiset(&oracle),
            10,
            delta,
        );
        assert!(!report.ml_probability_within_tolerance);
    }

    #[test]
    fn credsweeper_parity_rejects_missing_ml_probability() {
        let rust = vec![sample_credsweeper_credential(
            "Password",
            "src/app.env",
            7,
            "PASSWORD",
            "value-one",
        )];
        let mut oracle = rust.clone();
        oracle[0].ml_probability = Some(0.9);
        let report = CredSweeperParityReport::build(
            credsweeper_parity_multiset(&rust),
            credsweeper_parity_multiset(&oracle),
            10,
            credsweeper_ml_probability_max_delta(&rust, &oracle),
        );
        assert_eq!(report.common, 0);
        assert_eq!(report.missing, 1);
        assert_eq!(report.extra, 1);
    }

    #[test]
    fn credsweeper_parity_reports_diff_without_raw_values() {
        let rust_credentials = vec![sample_credsweeper_credential(
            "api-key",
            "src/app.env",
            7,
            "RUNPOD_API_KEY",
            "rust-only-value",
        )];
        let oracle_credentials = vec![sample_credsweeper_credential(
            "api-key",
            "src/app.env",
            7,
            "RUNPOD_API_KEY",
            "oracle-only-value",
        )];
        let report = CredSweeperParityReport::build(
            credsweeper_parity_multiset(&rust_credentials),
            credsweeper_parity_multiset(&oracle_credentials),
            10,
            0.0,
        );

        assert_eq!(report.common, 0);
        assert_eq!(report.missing, 1);
        assert_eq!(report.extra, 1);
        let missing = report.missing_examples[0].to_string();
        let extra = report.extra_examples[0].to_string();
        assert!(!missing.contains("oracle-only-value"), "{missing}");
        assert!(!extra.contains("rust-only-value"), "{extra}");
        assert!(missing.contains("len=17"), "{missing}");
        assert!(extra.contains("len=15"), "{extra}");
        assert!(missing.contains("sha256="), "{missing}");
    }

    #[test]
    fn credsweeper_parity_loads_utf8_bom_json() {
        let root = temp_root("pentect-credsweeper-parity-json");
        let path = root.join("oracle.json");
        let credentials = vec![sample_credsweeper_credential(
            "api-key",
            "src/app.env",
            1,
            "KEY",
            "value-one",
        )];
        let json = serde_json::to_string(&credentials).unwrap();
        std::fs::write(&path, format!("\u{feff}{json}")).unwrap();

        let loaded = load_credsweeper_json(&path).unwrap();

        assert_eq!(loaded.len(), 1);
        assert_eq!(loaded[0].rule, "api-key");
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn line_index_uses_zero_based_value_columns() {
        let text = "abc=secret\nnext";
        let lines = LineIndex::new(text);
        assert_eq!(lines.value_range(1, 4, 10), Some(ByteRange::new(4, 10)));
    }

    #[test]
    fn credsweeper_line_data_keeps_zero_width_empty_lines() {
        let text = "header\n\nbody";
        let lines = LineIndex::new(text);
        let data = lines
            .credsweeper_line_data_part("fixture", ByteRange::new(7, 7), None, None, None)
            .unwrap();
        assert_eq!(data.len(), 1);
        assert_eq!(data[0].line_num, 2);
        assert_eq!(data[0].value_start, 0);
        assert_eq!(data[0].value_end, 0);
        assert!(data[0].value.is_empty());
    }

    fn sample_credsweeper_credential(
        rule: &str,
        path: &str,
        line_num: usize,
        variable: &str,
        value: &str,
    ) -> CredSweeperJsonCredential {
        CredSweeperJsonCredential {
            rule: rule.to_string(),
            severity: "medium".to_string(),
            confidence: "moderate".to_string(),
            ml_probability: None,
            line_data_list: vec![CredSweeperJsonLineData {
                line: format!("{variable}={value}"),
                line_num,
                path: path.to_string(),
                info: String::new(),
                variable: Some(variable.to_string()),
                variable_start: 0,
                variable_end: variable.len() as isize,
                value: value.to_string(),
                value_start: variable.len() + 1,
                value_end: variable.len() + 1 + value.len(),
                entropy: shannon_entropy(value),
            }],
        }
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

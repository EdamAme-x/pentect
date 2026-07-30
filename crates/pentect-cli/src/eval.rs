use pentect_core::{Config, Engine, Input, Profile};
use serde_json::json;

pub(crate) fn cmd_eval(args: &[String]) {
    let json_output = match parse_args(args) {
        Ok(value) => value,
        Err(e) => crate::die(e),
    };
    let report = run_eval();
    if json_output {
        println!("{}", report.to_json());
    } else {
        println!(
            "precision={:.3} recall={:.3} tp={} fp={} fn={}",
            report.precision(),
            report.recall(),
            report.tp,
            report.fp,
            report.fn_
        );
    }
    if report.fn_ > 0 || report.fp > 0 {
        std::process::exit(1);
    }
}

#[derive(Clone, Debug)]
struct Case {
    text: &'static str,
    targets: &'static [&'static str],
}

#[derive(Clone, Debug, Default)]
struct EvalReport {
    cases: usize,
    tp: usize,
    fp: usize,
    fn_: usize,
}

impl EvalReport {
    fn precision(&self) -> f64 {
        ratio(self.tp, self.tp + self.fp)
    }

    fn recall(&self) -> f64 {
        ratio(self.tp, self.tp + self.fn_)
    }

    fn to_json(&self) -> String {
        json!({
            "cases": self.cases,
            "precision": self.precision(),
            "recall": self.recall(),
            "tp": self.tp,
            "fp": self.fp,
            "fn": self.fn_,
        })
        .to_string()
    }
}

fn parse_args(args: &[String]) -> Result<bool, String> {
    let mut json_output = false;
    for arg in &args[2..] {
        match arg.as_str() {
            "--json" => json_output = true,
            flag if flag.starts_with("--") => return Err(format!("unknown option: {flag}")),
            value => return Err(format!("unexpected argument for eval: {value}")),
        }
    }
    Ok(json_output)
}

fn run_eval() -> EvalReport {
    let engine = Engine::with_profile(Profile::Strict);
    let cfg = Config::insecure_testing();
    let mut report = EvalReport::default();
    for case in positive_cases() {
        report.cases += 1;
        let result = engine.mask(Input::text(case.text), &cfg);
        for target in case.targets {
            if result.masked.contains(target) {
                report.fn_ += 1;
            } else {
                report.tp += 1;
            }
        }
    }
    for case in negative_cases() {
        report.cases += 1;
        let result = engine.mask(Input::text(*case), &cfg);
        report.fp += result.summary.masked_count;
    }
    report
}

fn positive_cases() -> &'static [Case] {
    &[
        Case {
            text: "RUNPOD_API_KEY=rpa_FAKEPENTECTEVAL1234567890abcdef",
            targets: &["rpa_FAKEPENTECTEVAL1234567890abcdef"],
        },
        Case {
            text: "Authorization: Bearer sk-ABCDEFGHIJKLMNOPQRSTUVWX",
            targets: &["sk-ABCDEFGHIJKLMNOPQRSTUVWX"],
        },
        Case {
            text: "wallet recovery phrase: legal winner thank year wave sausage worth useful legal winner thank yellow",
            targets: &["legal winner thank year wave sausage worth useful legal winner thank yellow"],
        },
        Case {
            text: "client_secret: tenant-7-trial",
            targets: &["tenant-7-trial"],
        },
    ]
}

fn negative_cases() -> &'static [&'static str] {
    &[
        "secret handle boundary design note",
        "token budget and api design notes",
        "password field docs describe input type=password",
        "BIP39 wordlist excerpt: abandon ability able about above absent absorb abstract absurd abuse access accident",
    ]
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
    fn eval_readiness_has_full_recall() {
        let report = run_eval();
        assert_eq!(report.fn_, 0);
        assert_eq!(report.fp, 0);
        assert!(report.recall() >= 1.0);
        assert!(report.precision() >= 1.0);
    }

    #[test]
    fn eval_args_are_small() {
        let args = vec!["pentect".into(), "eval".into(), "--json".into()];
        assert!(parse_args(&args).unwrap());
    }
}

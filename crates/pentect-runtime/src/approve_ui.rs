use crate::Result;
use anyhow::{bail, Context};
use std::io::{self, BufRead, IsTerminal, Write};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ApprovalDecision {
    Once,
    Always,
    Decline,
}

pub struct ApprovalRequest {
    pub prompt: String,
    pub body: String,
    pub approve_label: String,
    pub deny_label: String,
    pub allow_always: bool,
    pub warnings: Vec<String>,
}

pub fn run(request: &ApprovalRequest) -> Result<ApprovalDecision> {
    if !io::stdin().is_terminal() || !io::stdout().is_terminal() {
        bail!("approval UI requires an interactive terminal");
    }

    let mut stdout = io::stdout();
    render_request(&mut stdout, request).context("could not render approval UI")?;
    read_decision(&mut io::stdin().lock(), &mut stdout, request)
}

fn read_decision<R: BufRead, W: Write>(
    input: &mut R,
    output: &mut W,
    request: &ApprovalRequest,
) -> Result<ApprovalDecision> {
    loop {
        write!(output, "> ").context("could not write approval prompt")?;
        output.flush().context("could not flush approval prompt")?;

        let mut line = String::new();
        input
            .read_line(&mut line)
            .context("could not read approval choice")?;
        let choice = line.trim().to_ascii_lowercase();
        match choice.as_str() {
            "" | "o" | "once" | "y" | "yes" => return Ok(ApprovalDecision::Once),
            "a" | "always" if request.allow_always => return Ok(ApprovalDecision::Always),
            "d" | "decline" | "n" | "no" | "q" | "quit" => return Ok(ApprovalDecision::Decline),
            _ => {
                writeln!(output, "choose: {}", choices(request))
                    .context("could not write approval help")?;
            }
        }
    }
}

fn render_request<W: Write>(output: &mut W, request: &ApprovalRequest) -> Result<()> {
    writeln!(output, "pentect {}", request.prompt)?;
    writeln!(output)?;
    writeln!(output, "{}", request.body.trim_end())?;
    if !request.warnings.is_empty() {
        writeln!(output)?;
        for warning in &request.warnings {
            writeln!(output, "warning: {warning}")?;
        }
    }
    writeln!(output)?;
    writeln!(output, "{}", choices(request))?;
    Ok(())
}

fn choices(request: &ApprovalRequest) -> String {
    if request.allow_always {
        format!(
            "Enter/o {}, a always, d {}",
            request.approve_label, request.deny_label
        )
    } else {
        format!(
            "Enter/o {}, d {}",
            request.approve_label, request.deny_label
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn approval_prompt_is_plain_and_compact() {
        let request = ApprovalRequest {
            prompt: "Run?".to_string(),
            body: "command\ncurl https://api.example.test/health".to_string(),
            approve_label: "once".to_string(),
            deny_label: "decline".to_string(),
            allow_always: true,
            warnings: vec!["may send secret".to_string()],
        };
        let mut out = Vec::new();
        render_request(&mut out, &request).unwrap();
        let rendered = String::from_utf8(out).unwrap();

        assert!(rendered.contains("pentect Run?"));
        assert!(rendered.contains("curl https://api.example.test/health"));
        assert!(rendered.contains("warning: may send secret"));
        assert!(rendered.contains("Enter/o once, a always, d decline"));
        assert!(!rendered.contains('\x1b'));
        assert!(!rendered.contains("environment policy"));
        assert!(!rendered.contains("resolves placeholders"));
    }

    #[test]
    fn approval_choice_parser_accepts_small_vocab() {
        let request = ApprovalRequest {
            prompt: "Run?".to_string(),
            body: "echo ok".to_string(),
            approve_label: "once".to_string(),
            deny_label: "decline".to_string(),
            allow_always: true,
            warnings: Vec::new(),
        };
        let mut input = b"a\n".as_slice();
        let mut output = Vec::new();

        let decision = read_decision(&mut input, &mut output, &request).unwrap();

        assert_eq!(decision, ApprovalDecision::Always);
    }
}

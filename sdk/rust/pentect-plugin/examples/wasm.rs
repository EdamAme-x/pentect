use pentect_plugin::{Finding, Inspect, PluginResult};

fn inspect(context: &mut Inspect) -> PluginResult {
    let findings = context
        .input()
        .text
        .match_indices("ACME-")
        .filter_map(|(start, value)| {
            let end = start + value.len() + 8;
            context
                .input()
                .text
                .get(start + value.len()..end)
                .filter(|suffix| suffix.bytes().all(|byte| byte.is_ascii_digit()))
                .map(|_| (start, end))
        })
        .collect::<Vec<_>>();
    for (start, end) in findings {
        context.add_finding(Finding::new(start, end, "ACME_ID"))?;
    }
    Ok(())
}

pentect_plugin::export!(inspect);

fn main() {}

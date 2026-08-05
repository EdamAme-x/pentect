use pentect_plugin::{Finding, Inspect, PluginResult};

fn inspect(context: &mut Inspect) -> PluginResult {
    for (start, value) in context.input().text.match_indices("ACME-") {
        let end = start + value.len() + 8;
        if context
            .input()
            .text
            .get(start + value.len()..end)
            .is_some_and(|suffix| suffix.bytes().all(|byte| byte.is_ascii_digit()))
        {
            context.add_finding(Finding::new(start, end, "ACME_ID"))?;
        }
    }
    Ok(())
}

pentect_plugin::export!(inspect);

fn main() {}

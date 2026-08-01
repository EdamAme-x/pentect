use pentect_plugin::{Finding, Inspect, PluginResult};

fn inspect(context: &mut Inspect) -> PluginResult {
    if let Some(start) = context.input.text.find("ACME-") {
        context.add_finding(Finding::new(start, start + 5, "ACME_ID"));
    }
    Ok(())
}

pentect_plugin::export!(inspect);

fn main() {}

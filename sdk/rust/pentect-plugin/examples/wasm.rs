use pentect_plugin::{Request, Response};

fn handle(request: Request) -> Result<Response, Box<dyn std::error::Error>> {
    Ok(Response::next(request.id))
}

pentect_plugin::export_wasm_plugin!(handle);

fn main() {}

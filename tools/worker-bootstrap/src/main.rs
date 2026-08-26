#[cfg(any(target_os = "linux", test))]
mod frame;

#[cfg(target_os = "linux")]
mod fault;
#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "linux")]
mod sealed;
#[cfg(target_os = "linux")]
mod seccomp;
#[cfg(target_os = "linux")]
mod supervisor;
#[cfg(target_os = "linux")]
mod worker;

#[cfg(target_os = "linux")]
const CHILD_MARKER: &str = "__sealr_worker_bootstrap_child_v1";

#[cfg(target_os = "linux")]
fn semantic_retention_request() -> Result<sealr::__worker_lab::InspectRetentionRequest, String> {
    let mut request = sealr::__worker_lab::InspectRetentionRequest::new(64, 64);
    request.add_path("deflated.txt")?;
    request.add_path("stored.txt")?;
    Ok(request)
}

#[cfg(target_os = "linux")]
fn semantic_read_retention_request() -> Result<sealr::__worker_lab::InspectRetentionRequest, String>
{
    Ok(sealr::__worker_lab::InspectRetentionRequest::new(0, 0))
}

fn main() {
    let args: Vec<_> = std::env::args_os().skip(1).collect();

    #[cfg(target_os = "linux")]
    let result = if args.first().is_some_and(|arg| arg == CHILD_MARKER) {
        worker::entry(&args)
    } else if args.is_empty() || (args.len() == 1 && args[0] == "conformance") {
        supervisor::run_conformance()
    } else {
        Err("usage: sealr-worker-bootstrap-lab [conformance]".into())
    };

    #[cfg(not(target_os = "linux"))]
    let result: Result<(), Box<dyn std::error::Error>> =
        if args.is_empty() || (args.len() == 1 && args[0] == "conformance") {
            Err("the authority-bootstrap conformance lab requires Linux".into())
        } else {
            Err("usage: sealr-worker-bootstrap-lab [conformance]".into())
        };

    if let Err(error) = result {
        eprintln!("sealr-worker-bootstrap-lab: {error}");
        std::process::exit(1);
    }
}

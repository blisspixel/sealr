#[cfg(any(target_os = "linux", test))]
mod frame;

#[cfg(target_os = "linux")]
mod fault;
#[cfg(all(target_os = "linux", feature = "lab"))]
mod helper;
#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "linux")]
mod sealed;
#[cfg(target_os = "linux")]
mod seccomp;
#[cfg(all(target_os = "linux", feature = "lab"))]
mod supervisor;
#[cfg(target_os = "linux")]
mod worker;

#[cfg(all(target_os = "linux", feature = "lab"))]
const CHILD_MARKER: &str = "__sealr_worker_bootstrap_child_v1";

#[cfg(target_os = "linux")]
const HELPER_BOOTSTRAP_ABI: u64 = 1;
#[cfg(target_os = "linux")]
const HELPER_FEATURE_ID: u64 = 1;

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

#[doc(hidden)]
pub fn production_worker_main(
    args: impl Iterator<Item = std::ffi::OsString>,
) -> Result<(), Box<dyn std::error::Error>> {
    let args = args.collect::<Vec<_>>();

    #[cfg(target_os = "linux")]
    {
        worker::production_entry(&args)
    }

    #[cfg(not(target_os = "linux"))]
    {
        let _ = args;
        Err("the sealr worker requires Linux".into())
    }
}

#[cfg(feature = "lab")]
#[doc(hidden)]
pub fn lab_main(
    args: impl Iterator<Item = std::ffi::OsString>,
) -> Result<(), Box<dyn std::error::Error>> {
    let args = args.collect::<Vec<_>>();

    #[cfg(target_os = "linux")]
    {
        if args.first().is_some_and(|arg| arg == CHILD_MARKER) {
            worker::lab_entry(&args)
        } else {
            supervisor::dispatch(&args)
        }
    }

    #[cfg(not(target_os = "linux"))]
    {
        if args.is_empty() || args.first().is_some_and(|arg| arg == "conformance") {
            Err("the authority-bootstrap conformance lab requires Linux".into())
        } else {
            Err("usage: sealr-worker-bootstrap-lab conformance --worker <absolute-path> --bytes <length> --sha256 <digest>".into())
        }
    }
}

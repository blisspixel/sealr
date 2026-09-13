fn main() {
    if let Err(error) = sealr_worker_bootstrap_lab::lab_main(std::env::args_os().skip(1)) {
        eprintln!("sealr-worker-bootstrap-lab: {error}");
        std::process::exit(1);
    }
}

fn main() {
    if let Err(error) =
        sealr_worker_bootstrap_lab::production_worker_main(std::env::args_os().skip(1))
    {
        eprintln!("sealr-worker: {error}");
        std::process::exit(1);
    }
}

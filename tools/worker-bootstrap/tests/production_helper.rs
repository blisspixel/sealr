#![cfg(target_os = "linux")]

use std::process::{Command, Stdio};

fn run(args: &[&str]) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_sealr-worker"))
        .args(args)
        .stdin(Stdio::null())
        .output()
        .expect("production helper starts")
}

#[test]
fn production_helper_rejects_direct_invocation() {
    let output = run(&[]);
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("stdin is not a sequenced-packet socket"));
    assert!(!stderr.contains("worker-bootstrap-evidence"));
}

#[test]
fn production_helper_has_no_commands_or_fault_selector() {
    for args in [
        vec!["--help"],
        vec!["conformance"],
        vec!["insufficient-landlock-abi"],
        vec!["seccomp-installation-failure"],
        vec!["unknown-ancillary"],
        vec!["stall-before-bootstrap-receive"],
        vec!["exit-after-exec-entry"],
        vec![
            "__sealr_worker_bootstrap_child_v1",
            "1",
            "exit-after-exec-entry",
        ],
    ] {
        let output = run(&args);
        assert!(
            !output.status.success(),
            "arguments unexpectedly passed: {args:?}"
        );
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(stderr.contains("accepts no command-line arguments"));
        assert!(!stderr.contains("worker-bootstrap-evidence"));
    }
}

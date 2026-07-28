use std::process::Command;

fn main() {
    println!("cargo:rerun-if-changed=.git/HEAD");
    println!("cargo:rerun-if-changed=.git/index");
    if let Ok(head) = std::fs::read_to_string(".git/HEAD")
        && let Some(branch_ref) = head.trim().strip_prefix("ref: ")
    {
        println!("cargo:rerun-if-changed=.git/{branch_ref}");
    }

    let git_commit = Command::new("git")
        .args(["rev-parse", "--short=12", "HEAD"])
        .output()
        .ok()
        .filter(|output| output.status.success())
        .and_then(|output| String::from_utf8(output.stdout).ok())
        .map(|commit| commit.trim().to_string())
        .filter(|commit| !commit.is_empty())
        .unwrap_or_else(|| "unknown".to_string());

    println!("cargo:rustc-env=RPKV2_GIT_COMMIT={git_commit}");
}

use std::process::Command;

fn main() {
    let output = Command::new("git")
        .args(["describe", "--tags", "--always", "--dirty"])
        .output()
        .expect("failed to execute git");
    let version = String::from_utf8_lossy(&output.stdout).trim().to_owned();
    println!("cargo:rustc-env=APP_VERSION={version}");

    protobuf_codegen::Codegen::new()
        .pure()
        .includes(&["src/protos"])
        .input("src/protos/router.proto")
        .input("src/protos/vless-addons.proto")
        .out_dir("src/protos")
        .run_from_script();
}

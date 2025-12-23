fn main() {
    protobuf_codegen::Codegen::new()
        .pure()
        .includes(&["src/protos"])
        .input("src/protos/router.proto")
        .input("src/protos/vless-addons.proto")
        .out_dir("src/protos")
        .run_from_script();
}

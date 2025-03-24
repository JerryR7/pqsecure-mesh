fn main() -> Result<(), Box<dyn std::error::Error>> {
    // 如果有 proto 文件，將在這裡編譯它們
    // 例如：
    // tonic_build::compile_protos("proto/pqsecure.proto")?;

    // 目前我們沒有 proto 文件，所以只返回 Ok
    Ok(())
}
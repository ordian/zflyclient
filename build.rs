fn main() -> Result<(), Box<dyn std::error::Error>> {
    #[cfg(feature = "cli")]
    tonic_build::configure()
        .build_server(false)
        .compile_protos(
            &["lightwallet-protocol/walletrpc/service.proto"],
            &["lightwallet-protocol/walletrpc/"],
        )?;
    Ok(())
}

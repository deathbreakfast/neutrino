//! Build script.

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let out_dir = std::path::PathBuf::from(std::env::var("OUT_DIR")?);
    let schemas_dir = std::path::PathBuf::from("schemas");
    let manifest_dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let codegen_crud = manifest_dir.join("../valence-codegen/src/codegen/generators/crud");

    println!("cargo:rerun-if-changed=schemas/");
    println!(
        "cargo:rerun-if-changed={}",
        codegen_crud.join("mod.rs").display()
    );
    println!(
        "cargo:rerun-if-changed={}",
        codegen_crud.join("emit_ctx.rs").display()
    );
    println!(
        "cargo:rerun-if-changed={}",
        codegen_crud.join("emit_model_ops.rs").display()
    );

    valence_codegen::generate_models(&valence_codegen::CodegenConfig {
        schemas_dir,
        out_dir,
        file_suffix: "_valence_schema.rs",
        trait_file_suffix: "_valence_trait.rs",
    })?;

    Ok(())
}

//! Gate: neutrino domain crates + vault teaching host are workspace members.

use std::fs;
use std::path::PathBuf;

fn workspace_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("..")
}

#[test]
fn neutrino_domain_workspace_members_happy_path() {
    let root =
        fs::read_to_string(workspace_root().join("Cargo.toml")).expect("workspace Cargo.toml");
    for member in [
        "neutrino",
        "neutrino-spectra-telemetry",
        "examples/vault-host",
    ] {
        assert!(
            root.contains(&format!("\"{member}\"")),
            "workspace must list {member}"
        );
        assert!(
            workspace_root().join(member).join("Cargo.toml").is_file(),
            "missing crate dir {member}"
        );
    }
    assert!(
        !root.contains("\"neutrino-app\""),
        "neutrino-app must live in neutrino-uf-app composer repo"
    );
}

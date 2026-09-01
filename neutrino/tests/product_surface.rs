//! Product surface contracts for neutrino-app (composer repo).
//!
//! Lives under the **neutrino domain** crate so CI can gate route/testid/auth/
//! When `L4-composers/neutrino-uf-app` is absent (standalone uf-dev CI), each
//! test returns early — domain contract suites remain the merge gate.

use std::fs;
use std::path::PathBuf;

fn workspace_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("..")
}

fn composer_app_src() -> Option<PathBuf> {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../..")
        .join("L4-composers/neutrino-uf-app/neutrino-app/src");
    path.is_dir().then_some(path)
}

fn read_app(rel: &str) -> Option<String> {
    let src = composer_app_src()?;
    let path = src.join(rel);
    fs::read_to_string(&path).ok()
}

/// Concatenate module sources after a file→directory split (e.g. `secrets_list/`).
fn read_app_module(dir: &str, files: &[&str]) -> Option<String> {
    Some(
        files
            .iter()
            .filter_map(|f| read_app(&format!("{dir}/{f}")))
            .collect::<Vec<_>>()
            .join("\n"),
    )
    .filter(|s| !s.is_empty())
}

#[test]
fn secrets_routes_mount_happy_path() {
    let Some(lib) = read_app("lib.rs") else {
        return;
    };
    for needle in [
        r#"path!("secrets")"#,
        r#"path!("")"#,
        r#"path!("acl")"#,
        "NeutrinoVerifiedGuardRouteView",
        "SecretsListRoute",
        "AclManageRoute",
        "id: \"secrets\"",
        "route_path: \"/secrets\"",
        "permission_manifest: permissions::NeutrinoPermission",
    ] {
        assert!(
            lib.contains(needle),
            "NeutrinoRoutes / uf_app missing `{needle}`"
        );
    }
}

#[test]
fn secrets_routes_drop_leaf_sad_path() {
    let Some(lib) = read_app("lib.rs") else {
        return;
    };
    for needle in [r#"path!("acl")"#, "AclManageRoute", "SecretsListRoute"] {
        assert!(
            lib.contains(needle),
            "removing `{needle}` drops a Secrets admin funnel entry"
        );
    }
    assert!(
        !lib.contains("unimplemented!"),
        "NeutrinoRoutes must not ship unimplemented placeholders"
    );
}

#[test]
fn uf_app_wrong_id_sad_path() {
    let Some(lib) = read_app("lib.rs") else {
        return;
    };
    assert!(
        lib.contains("id: \"secrets\""),
        "wrong uf_app id breaks Orbital host registration"
    );
    assert!(
        !lib.contains("id: \"neutrino\""),
        "uf_app id must stay `secrets` (product route id), not crate name neutrino"
    );
}

#[test]
fn layout_root_and_nav_happy_path() {
    let Some(layout) = read_app("layout.rs") else {
        return;
    };
    for needle in [
        "neutrino-app-root",
        "nav-secrets",
        "AppBarUserMenu",
        "UnifiedFieldShellLayout",
        "Outlet",
    ] {
        assert!(
            layout.contains(needle),
            "NeutrinoAppLayout missing contract `{needle}`"
        );
    }
}

#[test]
fn layout_missing_nav_sad_path() {
    let Some(layout) = read_app("layout.rs") else {
        return;
    };
    assert!(
        layout.contains("nav-secrets"),
        "dropping nav-secrets breaks operator left-nav contract"
    );
    assert!(
        layout.contains("data-testid=\"neutrino-app-root\""),
        "dropping neutrino-app-root breaks host / future Playwright parity"
    );
}

#[test]
fn verified_guard_auth_gate_happy_path() {
    let Some(lazy) = read_app("lazy_routes.rs") else {
        return;
    };
    for needle in [
        "RequireAuthenticated",
        "requires_email_verification=true",
        "NeutrinoAppLayout",
        "SecretsListPage",
        "AclManagePage",
    ] {
        assert!(
            lazy.contains(needle),
            "NeutrinoVerifiedGuardRouteView / lazy routes missing `{needle}`"
        );
    }
}

#[test]
fn verified_guard_drop_auth_sad_path() {
    let Some(lazy) = read_app("lazy_routes.rs") else {
        return;
    };
    assert!(
        lazy.contains("RequireAuthenticated") && lazy.contains("NeutrinoAppLayout"),
        "removing RequireAuthenticated opens /secrets pages to anonymous sessions"
    );
    assert!(
        lazy.contains("requires_email_verification=true"),
        "guard must keep email-verification gate on the secrets outlet"
    );
}

#[test]
fn vault_server_permissions_happy_path() {
    let Some(server) = read_app("server/mod.rs") else {
        return;
    };
    for pair in [
        ("neutrino_vault_ping", "SecretsRead"),
        ("list_vault_secrets", "SecretsRead"),
        ("create_vault_secret", "SecretsWrite"),
        ("reveal_vault_secret", "SecretsReveal"),
        ("delete_vault_secret", "SecretsWrite"),
        ("rotate_vault_secret", "SecretsRotate"),
    ] {
        let (fn_name, perm) = pair;
        assert!(server.contains(fn_name), "server missing `{fn_name}`");
        let start = server
            .find(&format!("pub async fn {fn_name}"))
            .unwrap_or_else(|| panic!("missing fn `{fn_name}`"));
        let window_start = start.saturating_sub(200);
        let window = &server[window_start..start];
        assert!(
            window.contains(&format!(r#"permission = "{perm}""#)),
            "`{fn_name}` must carry permission = \"{perm}\""
        );
    }
}

#[test]
fn vault_server_uses_session_valence_for_orm_happy_path() {
    let Some(server) = read_app("server/mod.rs") else {
        return;
    };
    assert!(
        server.contains("session_valence_from_ctx"),
        "vault server fns must use session Valence for Neutrino ORM privacy"
    );
    assert!(
        !server.contains("unsafe_system_valence"),
        "interactive vault server fns must not elevate to System"
    );
    assert!(
        !server.contains("system_valence_from_ctx"),
        "system Valence helper must not wire interactive ORM"
    );
}

#[test]
fn vault_server_wrong_permission_sad_path() {
    let Some(server) = read_app("server/mod.rs") else {
        return;
    };
    let reveal_start = server
        .find("pub async fn reveal_vault_secret")
        .expect("reveal_vault_secret");
    let window = &server[reveal_start.saturating_sub(200)..reveal_start];
    assert!(
        window.contains(r#"permission = "SecretsReveal""#),
        "reveal must stay SecretsReveal (not SecretsRead alone)"
    );
    assert!(
        !window.contains(r#"permission = "SecretsRead""#),
        "reveal must not be gated only by SecretsRead"
    );
}

#[test]
fn permission_manifest_secrets_domain_happy_path() {
    let Some(perms) = read_app("permissions.rs") else {
        return;
    };
    for needle in [
        "domain_key = \"secrets\"",
        "SecretsRead",
        "SecretsReveal",
        "SecretsWrite",
        "SecretsRotate",
        "SecretsGrantManage",
        "SecretsAuditView",
        "SecretsMasterKeyManage",
        "UfPermissionManifest",
    ] {
        assert!(
            perms.contains(needle),
            "NeutrinoPermission manifest missing `{needle}`"
        );
    }
}

#[test]
fn secrets_list_testid_and_bindings_happy_path() {
    let Some(page) = read_app_module("pages/secrets_list", &["mod.rs", "dialogs.rs", "table.rs"])
    else {
        return;
    };
    for needle in [
        "neutrino-secrets-list-page",
        "list_vault_secrets",
        "create_vault_secret",
        "reveal_vault_secret",
        "rotate_vault_secret",
        "delete_vault_secret",
    ] {
        assert!(page.contains(needle), "SecretsListPage missing `{needle}`");
    }
}

#[test]
fn secrets_list_drop_testid_sad_path() {
    let Some(page) = read_app_module("pages/secrets_list", &["mod.rs", "dialogs.rs", "table.rs"])
    else {
        return;
    };
    assert!(
        page.contains("data-testid=\"neutrino-secrets-list-page\""),
        "dropping neutrino-secrets-list-page breaks host / future Playwright parity"
    );
    assert!(
        !page.contains("unimplemented!"),
        "secrets list must not ship unimplemented placeholders"
    );
}

#[test]
fn acl_placeholder_page_happy_path() {
    let Some(page) = read_app("pages/acl_manage.rs") else {
        return;
    };
    for needle in ["AclManagePage", "Secret ACLs", "ACL matrix UI"] {
        assert!(page.contains(needle), "AclManagePage missing `{needle}`");
    }
}

#[test]
fn vault_host_matches_uf_app_happy_path() {
    let host = fs::read_to_string(workspace_root().join("examples/vault-host/src/main.rs"))
        .expect("vault-host main.rs");
    for needle in [
        "\"app_id\": \"secrets\"",
        "\"route_path\": \"/secrets\"",
        "\"read_permission\": \"SecretsRead\"",
        "\"reveal_permission\": \"SecretsReveal\"",
        "create_initial_neutrino_groups",
        "seed_bootstrap_secrets_with",
        "reveal_vault_secret",
        "rotate_vault_secret",
    ] {
        assert!(
            host.contains(needle),
            "vault-host missing contract `{needle}`"
        );
    }
    let Some(lib) = read_app("lib.rs") else {
        return;
    };
    assert!(
        lib.contains("id: \"secrets\"") && lib.contains("route_path: \"/secrets\""),
        "host inventory must stay aligned with uf_app!"
    );
    let Some(perms) = read_app("permissions.rs") else {
        return;
    };
    assert!(
        perms.contains("SecretsRead") && perms.contains("SecretsReveal"),
        "host read/reveal permissions must stay aligned with NeutrinoPermission"
    );
}

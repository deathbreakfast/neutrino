//! DB-scoped credential path helpers (Nucleus cell scoped_creds).

/// True when `scope_path` is a Nucleus cell scoped-creds path (not root).
///
/// Expected shape: `nucleus/cells/{cell}/scoped_creds/{runtime}/{logical}`
/// (leading `/` optional). Root scopes and non-nucleus paths return false.
#[must_use]
pub fn is_db_scoped_creds_path(scope_path: &str) -> bool {
    let p = scope_path.trim().trim_start_matches('/');
    if p.contains("/root/") || p.ends_with("/root") {
        return false;
    }
    let parts: Vec<&str> = p.split('/').filter(|s| !s.is_empty()).collect();
    parts.len() >= 5 && parts[0] == "nucleus" && parts[1] == "cells" && parts[3] == "scoped_creds"
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn db_scoped_happy() {
        assert!(is_db_scoped_creds_path(
            "/nucleus/cells/c1/scoped_creds/chronon/default"
        ));
        assert!(is_db_scoped_creds_path(
            "nucleus/cells/c1/scoped_creds/boson/default"
        ));
    }

    #[test]
    fn non_db_filtered() {
        assert!(!is_db_scoped_creds_path("nucleus/cells/c1/root/default"));
        assert!(!is_db_scoped_creds_path("/gluon/provider_account/x"));
        assert!(!is_db_scoped_creds_path("/product/oauth"));
        assert!(!is_db_scoped_creds_path(""));
    }
}

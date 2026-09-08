//! Path-segment-safe matching for vault list `scope_prefix` filters.

/// Returns whether `scope_path` falls under `prefix` using path-segment rules.
///
/// After trimming both sides:
/// - empty `prefix` is treated as "no filter" by callers (this helper returns `true`);
/// - exact equality matches;
/// - otherwise the path must start with `prefix` followed by `/` (or `prefix` already
///   ends with `/` and the path starts with that string).
///
/// This prevents `/finance/org/feed` from matching `/finance/org/feeds/...`.
#[must_use]
pub fn scope_path_matches_prefix(scope_path: &str, prefix: &str) -> bool {
    let scope_path = scope_path.trim();
    let prefix = prefix.trim();
    if prefix.is_empty() {
        return true;
    }
    if scope_path == prefix {
        return true;
    }
    if prefix.ends_with('/') {
        scope_path.starts_with(prefix)
    } else {
        scope_path.starts_with(&format!("{prefix}/"))
    }
}

#[cfg(test)]
mod tests {
    use super::scope_path_matches_prefix;

    #[test]
    fn exact_match_happy() {
        assert!(scope_path_matches_prefix(
            "/finance/org_abc/feeds",
            "/finance/org_abc/feeds"
        ));
    }

    #[test]
    fn child_path_matches_happy() {
        assert!(scope_path_matches_prefix(
            "/finance/org_abc/feeds/chase",
            "/finance/org_abc/feeds"
        ));
    }

    #[test]
    fn sibling_prefix_does_not_match_sad() {
        assert!(!scope_path_matches_prefix(
            "/finance/org_abc/feeds/chase",
            "/finance/org_abc/feed"
        ));
    }

    #[test]
    fn trailing_slash_prefix_matches_happy() {
        assert!(scope_path_matches_prefix(
            "/finance/org_abc/feeds/chase",
            "/finance/org_abc/feeds/"
        ));
        assert!(!scope_path_matches_prefix(
            "/finance/org_abc/feeds",
            "/finance/org_abc/feeds/"
        ));
    }

    #[test]
    fn empty_or_whitespace_prefix_matches_all_happy() {
        assert!(scope_path_matches_prefix("/gluon/smtp", ""));
        assert!(scope_path_matches_prefix("/gluon/smtp", "   "));
    }

    #[test]
    fn unrelated_path_does_not_match_sad() {
        assert!(!scope_path_matches_prefix(
            "/gluon/provider/aws",
            "/finance/org_abc/feeds"
        ));
    }
}

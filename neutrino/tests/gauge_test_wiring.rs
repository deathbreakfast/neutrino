//! Shared Gauge + Lepton wiring for Neutrino SSR integration tests.

#![allow(dead_code, missing_docs)]
#![allow(clippy::expect_used, clippy::unwrap_used)]

use chrono::Utc;
use gauge::touch_schema_inventory;
use neutrino::create_initial_neutrino_groups;
use valence::{Model, Valence};

pub async fn wire_neutrino_gauge_groups(v: &Valence) {
    touch_schema_inventory();
    create_initial_neutrino_groups(v)
        .await
        .expect("create_initial_neutrino_groups");
}

pub async fn seed_user(id: &str, email: &str, v: &Valence) {
    let _ = email; // email lives on AccountEmail upstream; label kept for call-site readability
    let now = Utc::now();
    let user = lepton::generated::User::new(
        Some(lepton::generated::UserUserType::Person),
        Some("test-password-hash".to_string()),
        Some(lepton::generated::UserStatus::Active),
        None,
        None,
        Some(now),
        None,
        None,
        now,
        now,
    )
    .expect("build user");
    lepton::generated::User::upsert(id, user, v)
        .await
        .expect("upsert user");
}

pub async fn add_user_to_group(user_id: &str, group_id: &str, v: &Valence) {
    let group = gauge::generated::PermissionGroup::get(group_id, v)
        .await
        .expect("get group")
        .unwrap_or_else(|| panic!("group {group_id} missing"));
    let user = lepton::generated::User::get(user_id, v)
        .await
        .expect("get user")
        .expect("user row");
    let principal = gauge::generated::PermissionUserPrincipal::upsert(
        &format!("user:{user_id}"),
        gauge::generated::PermissionUserPrincipal::new(
            user.id().expect("user id").clone(),
            user_id.to_string(),
        )
        .expect("principal"),
        v,
    )
    .await
    .expect("upsert principal");
    group
        .relate_to_member_record(principal.id().expect("principal id"), v)
        .await
        .expect("relate member");
}

pub async fn add_user_to_creators_group(user_id: &str, v: &Valence) {
    add_user_to_group(user_id, "neutrino.secret.creators", v).await;
}

/// Users referenced by vault contract tests (`actor`, `user:alice`, …).
pub async fn seed_default_vault_users(v: &Valence) {
    seed_user("actor", "actor@example.test", v).await;
    seed_user("test-actor", "test-actor@example.test", v).await;
    seed_user("alice", "alice@example.test", v).await;
    seed_user("bob", "bob@example.test", v).await;
    seed_user("ops", "ops@example.test", v).await;
    for id in ["actor", "test-actor", "alice", "bob", "ops"] {
        add_user_to_creators_group(id, v).await;
    }
}

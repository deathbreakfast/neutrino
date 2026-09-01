//! Valence privacy evaluators for Neutrino secret schemas.
//!
//! Uses [`gauge::actor_can_raw`] — never [`gauge::service::actor_can`] — so policy
//! checks do not re-enter typed ORM privacy or elevate to System.

use async_trait::async_trait;
use gauge::resource_permissions::{
    permission_name, ResourceAction, ResourceKind, CREATE_NEUTRINO_SECRETS,
};
use std::any::Any;
use valence::{
    Actor, ActorContext, Error, PolicyEvaluator, PrivacyOperation, PrivacyRule, Result, Valence,
};

pub use gauge::privacy_policies::SUPER_USER_GROUP_MEMBER as NEUTRINO_SUPER_USER;

/// Coarse create gate backed by raw Gauge walks.
pub const CREATE_NEUTRINO_SECRETS_GATE: StaticPermissionGateRaw = StaticPermissionGateRaw {
    rule_name: "neutrino::CREATE_NEUTRINO_SECRETS",
    permission_name: CREATE_NEUTRINO_SECRETS.permission_name,
};

/// Per-secret metadata mutate/delete gate (`View`/`Edit`/`Delete` on `id`).
pub const NEUTRINO_SECRET_ENTITY: ResourcePermissionPolicyRaw = ResourcePermissionPolicyRaw {
    rule_name: "neutrino::NEUTRINO_SECRET_ENTITY",
    kind: ResourceKind::NeutrinoSecret,
    id_field: "id",
};

/// Ciphertext table: Read→Reveal, Update→Edit, Delete→Delete on `secret_id`.
pub const NEUTRINO_SECRET_VERSION_ENTITY: SecretVersionPermissionPolicyRaw =
    SecretVersionPermissionPolicyRaw {
        rule_name: "neutrino::NEUTRINO_SECRET_VERSION_ENTITY",
        kind: ResourceKind::NeutrinoSecret,
        id_field: "secret_id",
    };

/// Sync field rule: `owner_subject_json.actor` matches the viewer user id.
pub const OWNER_SUBJECT_JSON: PrivacyRule = PrivacyRule {
    name: "neutrino_owner_subject_json",
    description: Some("Owner match via owner_subject_json.actor"),
    check: owner_subject_json_check,
};

fn actor_from_context(actor: &dyn ActorContext) -> Result<Actor> {
    serde_json::from_value(actor.actor_json().clone())
        .map_err(|e| Error::Internal(format!("invalid actor context: {e}")))
}

async fn actor_can_raw(v: &Valence, permission_name: &str) -> Result<bool> {
    gauge::actor_can_raw::actor_can_raw(v, permission_name)
        .await
        .map_err(|e| Error::Privacy(format!("Gauge raw permission check failed: {e}")))
}

fn resource_id_from_value(value: &serde_json::Value) -> Option<&str> {
    if let Some(s) = value.as_str() {
        let trimmed = s.trim();
        return (!trimmed.is_empty()).then_some(trimmed);
    }
    value
        .get("id")
        .and_then(|v| v.as_str())
        .map(str::trim)
        .filter(|s| !s.is_empty())
}

fn owner_subject_json_check(record: &serde_json::Value, viewer: &Actor) -> bool {
    if viewer.is_system() {
        return true;
    }
    let Some(viewer_id) = viewer.user_id() else {
        return false;
    };
    let normalized_viewer = viewer_id.strip_prefix("user:").unwrap_or(viewer_id);
    let field = record.get("owner_subject_json").unwrap_or(record);
    let actor_label = match field {
        serde_json::Value::String(s) => s.as_str(),
        serde_json::Value::Object(obj) => obj.get("actor").and_then(|v| v.as_str()).unwrap_or(""),
        _ => return false,
    };
    if actor_label.is_empty() {
        return false;
    }
    let owner_id = actor_label.strip_prefix("user:").unwrap_or(actor_label);
    normalized_viewer == owner_id
}

/// Static permission gate using raw Gauge walks (safe inside evaluators).
#[derive(Debug, Clone)]
pub struct StaticPermissionGateRaw {
    /// Valence privacy rule name.
    pub rule_name: &'static str,
    /// Gauge permission name checked via [`gauge::actor_can_raw`].
    pub permission_name: &'static str,
}

#[async_trait]
impl PolicyEvaluator for StaticPermissionGateRaw {
    fn name(&self) -> &'static str {
        self.rule_name
    }

    fn description(&self) -> Option<&'static str> {
        Some("Static Gauge permission gate (raw walks)")
    }

    async fn evaluate(
        &self,
        _op: PrivacyOperation,
        _record: &serde_json::Value,
        actor: &dyn ActorContext,
        v: &Valence,
    ) -> Result<bool> {
        let viewer = actor_from_context(actor)?;
        if viewer.is_system() {
            return Ok(true);
        }
        actor_can_raw(v, self.permission_name).await
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

/// Per-resource CRUD gate using raw Gauge walks.
#[derive(Debug, Clone)]
pub struct ResourcePermissionPolicyRaw {
    /// Valence privacy rule name.
    pub rule_name: &'static str,
    /// Resource kind for permission name construction.
    pub kind: ResourceKind,
    /// JSON field holding the resource id.
    pub id_field: &'static str,
}

impl ResourcePermissionPolicyRaw {
    const fn action_for_op(op: PrivacyOperation) -> Option<ResourceAction> {
        match op {
            PrivacyOperation::Read => Some(ResourceAction::View),
            PrivacyOperation::Update => Some(ResourceAction::Edit),
            PrivacyOperation::Delete => Some(ResourceAction::Delete),
            PrivacyOperation::Create => None,
        }
    }
}

#[async_trait]
impl PolicyEvaluator for ResourcePermissionPolicyRaw {
    fn name(&self) -> &'static str {
        self.rule_name
    }

    fn description(&self) -> Option<&'static str> {
        Some("Per-resource Gauge permission gate (raw walks)")
    }

    async fn evaluate(
        &self,
        op: PrivacyOperation,
        record: &serde_json::Value,
        actor: &dyn ActorContext,
        v: &Valence,
    ) -> Result<bool> {
        let viewer = actor_from_context(actor)?;
        if viewer.is_system() {
            return Ok(true);
        }
        let Some(action) = Self::action_for_op(op) else {
            return Ok(false);
        };
        let Some(resource_id) = record.get(self.id_field).and_then(resource_id_from_value) else {
            return Ok(false);
        };
        let name = permission_name(self.kind, resource_id, action);
        actor_can_raw(v, &name).await
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

/// Version-row gate: Read requires Reveal; Create/Update require Edit; Delete requires Delete.
#[derive(Debug, Clone)]
pub struct SecretVersionPermissionPolicyRaw {
    /// Valence privacy rule name.
    pub rule_name: &'static str,
    /// Parent secret kind.
    pub kind: ResourceKind,
    /// JSON field holding the parent secret id (`secret_id`).
    pub id_field: &'static str,
}

impl SecretVersionPermissionPolicyRaw {
    const fn action_for_op(op: PrivacyOperation) -> ResourceAction {
        match op {
            PrivacyOperation::Read => ResourceAction::Reveal,
            PrivacyOperation::Update | PrivacyOperation::Create => ResourceAction::Edit,
            PrivacyOperation::Delete => ResourceAction::Delete,
        }
    }
}

#[async_trait]
impl PolicyEvaluator for SecretVersionPermissionPolicyRaw {
    fn name(&self) -> &'static str {
        self.rule_name
    }

    fn description(&self) -> Option<&'static str> {
        Some("Neutrino secret version Gauge gate (Reveal for read)")
    }

    async fn evaluate(
        &self,
        op: PrivacyOperation,
        record: &serde_json::Value,
        actor: &dyn ActorContext,
        v: &Valence,
    ) -> Result<bool> {
        let viewer = actor_from_context(actor)?;
        if viewer.is_system() {
            return Ok(true);
        }
        let action = Self::action_for_op(op);
        let Some(resource_id) = record.get(self.id_field).and_then(resource_id_from_value) else {
            return Ok(false);
        };
        let name = permission_name(self.kind, resource_id, action);
        actor_can_raw(v, &name).await
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

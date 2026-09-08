//! One-shot revoke of NeutrinoSecret umbrella grant edges.
//!
//! [`crate::vault_gauge::NEUTRINO_SECRET`] uses
//! [`UmbrellaPolicy::None`](gauge::resource_permissions::UmbrellaPolicy::None), so new
//! bundles no longer grant `neutrino.secret.viewers` / `.operators`. Deployments seeded
//! before that flip still carry those edges. This script removes them without touching
//! creators, catalog Create*, other kinds, or per-user grants.

use anyhow::Context;
use gauge::resource_permissions::revoke_umbrella_grants;
use valence::Valence;

use crate::vault_gauge::NEUTRINO_SECRET;

/// Chronon script entry that revokes standing Neutrino secret umbrella grants.
#[chronon_coordinator_macros::script(
    name = "revoke_neutrino_secret_umbrella_grants",
    default_job(job = "revoke-neutrino-secret-umbrella-grants", run_once)
)]
pub async fn revoke_neutrino_secret_umbrella_grants_script(
    ctx: Box<dyn chronon_core::ScriptContext>,
) -> anyhow::Result<()> {
    let valence = chronon_valence_identity::valence_from_context(&*ctx)?;
    let groups = NEUTRINO_SECRET.groups;
    revoke_umbrella_grants(
        &valence,
        NEUTRINO_SECRET,
        &[groups.viewers, groups.operators],
    )
    .await
    .context("failed revoking NeutrinoSecret umbrella grants")?;
    Ok(())
}

/// Library helper for tests and one-off host wiring.
///
/// # Errors
///
/// Valence read / unrelate failures bubble as [`anyhow::Error`].
pub async fn revoke_neutrino_secret_umbrella_grants(v: &Valence) -> anyhow::Result<usize> {
    let groups = NEUTRINO_SECRET.groups;
    revoke_umbrella_grants(v, NEUTRINO_SECRET, &[groups.viewers, groups.operators]).await
}

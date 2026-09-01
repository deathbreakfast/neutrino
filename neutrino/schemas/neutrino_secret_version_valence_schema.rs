use crate::privacy_policies::{NEUTRINO_SECRET_VERSION_ENTITY, NEUTRINO_SUPER_USER};
use valence::prelude::*;
use valence::privacy_policies::common::SYSTEM_ONLY;

valence_schema! {
    NeutrinoSecretVersion {
        table: "neutrino_secret_version",
        version: "0.2.0",
        database: crate::embedded_surreal::DEFAULT_STORAGE,
        description: "Sealed secret payload (per-version ciphertext)",

        policies: {
            read: {
                always_allow: [NEUTRINO_SUPER_USER],
                allow: [NEUTRINO_SECRET_VERSION_ENTITY, SYSTEM_ONLY],
            },
            create: {
                always_allow: [NEUTRINO_SUPER_USER],
                allow: [NEUTRINO_SECRET_VERSION_ENTITY, SYSTEM_ONLY],
            },
            update: {
                always_allow: [NEUTRINO_SUPER_USER],
                allow: [NEUTRINO_SECRET_VERSION_ENTITY, SYSTEM_ONLY],
            },
            delete: {
                always_allow: [NEUTRINO_SUPER_USER],
                allow: [NEUTRINO_SECRET_VERSION_ENTITY, SYSTEM_ONLY],
            },
        },

        fields: [
            id: {
                r#type: FieldType::String,
                primary_key: true,
                required: true,
            },
            secret_id: {
                r#type: FieldType::Record("neutrino_secret"),
                required: true,
            },
            version_num: {
                r#type: FieldType::Integer,
                required: true,
            },
            sealed_payload_b64: {
                r#type: FieldType::String,
                required: true,
            },
            nonce_b64: {
                r#type: FieldType::String,
                required: true,
            },
            key_id: {
                r#type: FieldType::String,
                required: true,
            },
            status: {
                r#type: FieldType::Enum(&["active", "grace", "archived"]),
                required: true,
                default: "active",
            },
            created_at: {
                r#type: FieldType::DateTime,
                required: true,
            },
            created_by: {
                r#type: FieldType::String,
                required: true,
                default: "system",
            },
        ],

        connections: [
            secret_id: {
                table: "neutrino_secret",
                cardinality: HasOne,
                required: true,
                on_delete: Cascade,
            },
        ],
    }
}

use crate::privacy_policies::{
    CREATE_NEUTRINO_SECRETS_GATE, NEUTRINO_SECRET_ENTITY, NEUTRINO_SUPER_USER, OWNER_SUBJECT_JSON,
};
use valence::prelude::*;
use valence::privacy_policies::common::{AUTHENTICATED, SYSTEM_ONLY};

valence_schema! {
    NeutrinoSecret {
        table: "neutrino_secret",
        version: "0.2.0",
        database: crate::embedded_surreal::DEFAULT_STORAGE,
        description: "Neutrino secret metadata (plaintext name/scope only; versions hold ciphertext)",

        policies: {
            read: {
                always_allow: [NEUTRINO_SUPER_USER],
                allow: [AUTHENTICATED, SYSTEM_ONLY],
            },
            create: {
                always_allow: [NEUTRINO_SUPER_USER],
                allow: [CREATE_NEUTRINO_SECRETS_GATE, SYSTEM_ONLY],
            },
            update: {
                always_allow: [NEUTRINO_SUPER_USER],
                allow: [NEUTRINO_SECRET_ENTITY, SYSTEM_ONLY],
            },
            delete: {
                always_allow: [NEUTRINO_SUPER_USER],
                allow: [NEUTRINO_SECRET_ENTITY, SYSTEM_ONLY],
            },
        },

        fields: [
            id: {
                r#type: FieldType::String,
                primary_key: true,
                required: true,
            },
            name: {
                r#type: FieldType::String,
                required: true,
            },
            scope_path: {
                r#type: FieldType::String,
                required: true,
            },
            kind: {
                r#type: FieldType::String,
                required: true,
            },
            current_version: {
                r#type: FieldType::Integer,
                required: true,
            },
            owner_subject_json: {
                // Json (not String): SQLite SELECT helpers re-parse JSON-looking
                // TEXT into objects; a String field then fails deserialize.
                r#type: FieldType::Json,
                required: true,
                policies: {
                    read: {
                        always_allow: [SYSTEM_ONLY],
                        allow: [OWNER_SUBJECT_JSON],
                    },
                },
            },
            rotation_policy_json: {
                r#type: FieldType::Json,
            },
            created_at: {
                r#type: FieldType::DateTime,
                required: true,
            },
            updated_at: {
                r#type: FieldType::DateTime,
                required: true,
            },
        ]
    }
}

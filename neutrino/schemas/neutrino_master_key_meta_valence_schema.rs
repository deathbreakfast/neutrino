use valence::prelude::*;
use valence::privacy_policies::common::SYSTEM_ONLY;

valence_schema! {
    NeutrinoMasterKeyMeta {
        table: "neutrino_master_key_meta",
        version: "0.1.0",
        database: crate::embedded_surreal::DEFAULT_STORAGE,
        description: "Neutrino master key metadata (no key material)",

        policies: {
            read:   { allow: [SYSTEM_ONLY] },
            create: { allow: [SYSTEM_ONLY] },
            update: { allow: [SYSTEM_ONLY] },
            delete: { allow: [SYSTEM_ONLY] },
        },

        fields: [
            id: {
                r#type: FieldType::String,
                primary_key: true,
                required: true,
            },
            key_id: {
                r#type: FieldType::String,
                required: true,
            },
            source: {
                r#type: FieldType::Enum(&["env", "kms"]),
                required: true,
                default: "env",
            },
            kdf_params_json: {
                r#type: FieldType::Json,
            },
            created_at: {
                r#type: FieldType::DateTime,
                required: true,
            },
        ]
    }
}

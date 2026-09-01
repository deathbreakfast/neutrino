use valence::prelude::*;
use valence::privacy_policies::common::SYSTEM_ONLY;

valence_schema! {
    NeutrinoSecretAuditEvent {
        table: "neutrino_secret_audit_event",
        version: "0.2.0",
        database: crate::embedded_surreal::DEFAULT_STORAGE,
        description: "Append-only audit events for Neutrino (tamper-evident chain via prev_event_hash)",

        policies: {
            read: { defer_to_edge: "secret" },
            create: { defer_to_edge: "secret" },
            update: { allow: [SYSTEM_ONLY] },
            delete: { allow: [SYSTEM_ONLY] },
        },

        fields: [
            id: {
                r#type: FieldType::String,
                primary_key: true,
                required: true,
            },
            prev_event_hash: {
                r#type: FieldType::String,
                required: true,
            },
            actor: {
                r#type: FieldType::String,
                required: true,
            },
            action: {
                r#type: FieldType::String,
                required: true,
            },
            secret_id: {
                r#type: FieldType::String,
                required: true,
            },
            secret: {
                r#type: FieldType::Record("neutrino_secret"),
                required: true,
            },
            version_num: {
                r#type: FieldType::Integer,
                required: true,
            },
            outcome: {
                r#type: FieldType::Enum(&["ok", "denied", "error"]),
                required: true,
            },
            error_message: {
                r#type: FieldType::String,
            },
            ts: {
                r#type: FieldType::DateTime,
                required: true,
            },
        ],

        connections: [
            secret: {
                table: "neutrino_secret",
                cardinality: HasOne,
                required: true,
                on_delete: SetNull,
            },
        ],
    }
}

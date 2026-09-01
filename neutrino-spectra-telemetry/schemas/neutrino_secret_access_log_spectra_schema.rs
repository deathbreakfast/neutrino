use spectra::spectra_schema;

spectra_schema! {
    NeutrinoSecretAccessLog {
        store: "neutrino",
        table: "neutrino_secret_access_log",
        version: "0.1.0",
        description: "Secret store access attempts (never includes plaintext or ciphertext).",
        level: Warn,
        fields: [
            action: {
                r#type: String,
                classification: { pii: false, safe_for_console: true },
            },
            secret_id: {
                r#type: String,
                classification: { pii: true, safe_for_console: false },
            },
            version_num: {
                r#type: i64,
                classification: { pii: false, safe_for_console: true },
            },
            scope_path: {
                r#type: String,
                classification: { pii: true, safe_for_console: false },
            },
            secret_name: {
                r#type: String,
                classification: { pii: true, safe_for_console: false },
            },
            outcome: {
                r#type: String,
                classification: { pii: false, safe_for_console: true },
            },
            viewer_key: {
                r#type: String,
                classification: { pii: true, safe_for_console: false },
            },
            caller: {
                r#type: String,
                classification: { pii: true, safe_for_console: false },
            },
            error_message: {
                r#type: String,
                classification: { pii: false, safe_for_console: false },
            },
        ],
    }
}

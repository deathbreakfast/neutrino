#[cfg(feature = "ssr")]
mod neutrino_secret_schema {
    include!("../schemas/neutrino_secret_valence_schema.rs");
}

#[cfg(feature = "ssr")]
mod neutrino_secret_version_schema {
    include!("../schemas/neutrino_secret_version_valence_schema.rs");
}

#[cfg(feature = "ssr")]
mod neutrino_master_key_meta_schema {
    include!("../schemas/neutrino_master_key_meta_valence_schema.rs");
}

#[cfg(feature = "ssr")]
mod neutrino_secret_audit_event_schema {
    include!("../schemas/neutrino_secret_audit_event_valence_schema.rs");
}

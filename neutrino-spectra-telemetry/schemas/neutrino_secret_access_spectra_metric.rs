use spectra::spectra_metric;

spectra_metric! {
    NeutrinoSecretAccess {
        store: "neutrino",
        name: "neutrino_secret_access",
        version: "0.1.0",
        description: "Secret store access attempts. Labels: action, outcome.",
        level: Warn,
    }
}

use anyhow::Result;

use super::{attestation::TrustedKey, registry_client::RegistryClient, store::LocalStore, trust};

/// Registry connection plus the pinned key and local store every command
/// that installs or runs packages needs.
pub struct Session {
    pub client: RegistryClient,
    pub key: TrustedKey,
    pub store: LocalStore,
}

impl Session {
    pub fn open() -> Result<Self> {
        let client = RegistryClient::from_env()?;
        let store = LocalStore::open(client.base_url())?;
        store.ensure()?;
        let key = trust::trusted_key(&client)?;
        Ok(Self { client, key, store })
    }
}

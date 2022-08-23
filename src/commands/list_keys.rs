use crate::{
    error::Error,
    params::{keystore_params::KeystoreParams, CryptoScheme},
};
use clap::Parser;
use sc_keystore::LocalKeystore;
use sc_service::config::KeystoreConfig;
use sp_core::crypto::KeyTypeId;
use sp_keystore::{SyncCryptoStore, SyncCryptoStorePtr};
use std::{convert::TryFrom, env, sync::Arc};

/// The `list` command
#[derive(Debug, Clone, Parser)]
#[clap(
    name = "keys",
    about = "list keys compatible to the keystore of a node."
)]
pub struct ListKeysCmd {
    /// Key type, examples: "gran", or "imon"
    #[clap(long)]
    key_type: String,

    // #[allow(missing_docs)]
    // #[clap(flatten)]
    // pub shared_params: SharedParams,
    #[allow(missing_docs)]
    #[clap(flatten)]
    pub keystore_params: KeystoreParams,

    /// The cryptography scheme that should be used to generate the key out of the given URI.
    #[clap(long, value_name = "SCHEME", arg_enum, ignore_case = true)]
    pub scheme: CryptoScheme,
}

impl ListKeysCmd {
    /// Run the command
    pub fn run(&self) -> Result<(), Error> {
        let config_dir = env::current_dir()?;
        let keystore = match self.keystore_params.keystore_config(&config_dir)? {
            (_, KeystoreConfig::Path { path, password }) => {
                // let public = with_crypto_scheme!(self.scheme, to_vec(&suri, password.clone()))?;
                let keystore: SyncCryptoStorePtr = Arc::new(LocalKeystore::open(path, password)?);
                keystore
            }
            _ => unreachable!("keystore_config always returns path and password; qed"),
        };

        let key_type =
            KeyTypeId::try_from(self.key_type.as_str()).map_err(|_| Error::KeyTypeInvalid)?;

        match self.scheme {
            crate::params::CryptoScheme::Ecdsa => {
                let keys = SyncCryptoStore::ecdsa_public_keys(&*keystore, key_type);
                println!("{:?}", keys);
            }
            crate::params::CryptoScheme::Sr25519 => {
                let keys = SyncCryptoStore::sr25519_public_keys(&*keystore, key_type);
                println!("{:?}", keys);
            }
            crate::params::CryptoScheme::Ed25519 => {
                let keys = SyncCryptoStore::ed25519_public_keys(&*keystore, key_type);
                println!("{:?}", keys);
            }
        }

        Ok(())
    }
}

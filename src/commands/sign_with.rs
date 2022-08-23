//! Implementation of the `sign_with` subcommand
use crate::{
    commands::utils,
    error::{self, Error},
    params::{keystore_params::KeystoreParams, CryptoSchemeFlag},
};
use clap::Parser;
use sc_keystore::LocalKeystore;
use sc_service::config::KeystoreConfig;
use sp_core::crypto::Ss58Codec;
use sp_core::ByteArray;
use sp_core::Pair;
use sp_core::{crypto::KeyTypeId, Public};
use sp_keystore::{SyncCryptoStore, SyncCryptoStorePtr};
use std::{convert::TryFrom, env, sync::Arc};

/// The `sign` command
#[derive(Debug, Clone, Parser)]
#[clap(name = "signwith", about = "Sign a message, with a given (public) key")]
pub struct SignWithCmd {
    /// Key type, examples: "gran", or "imon"
    #[clap(long)]
    key_type: String,

    /// The public key.
    #[clap(long)]
    key: String,

    /// Message to sign, if not provided you will be prompted to
    /// pass the message via STDIN
    #[clap(long)]
    message: Option<String>,

    /// The message on STDIN is hex-encoded data
    #[clap(long)]
    hex: bool,

    #[allow(missing_docs)]
    #[clap(flatten)]
    pub keystore_params: KeystoreParams,

    #[allow(missing_docs)]
    #[clap(flatten)]
    pub crypto_scheme: CryptoSchemeFlag,
}

impl SignWithCmd {
    /// Run the command
    pub fn run(&self) -> error::Result<()> {
        let message = utils::read_message(self.message.as_ref(), self.hex)?;
        let key = self.key.as_ref();
        // let password = self.keystore_params.read_password()?;
        let key_type =
            KeyTypeId::try_from(self.key_type.as_str()).map_err(|_| Error::KeyTypeInvalid)?;

        let config_dir = env::current_dir()?;
        let keystore = match self.keystore_params.keystore_config(&config_dir)? {
            (_, KeystoreConfig::Path { path, password }) => {
                // let public = with_crypto_scheme!(self.scheme, to_vec(&suri, password.clone()))?;
                let keystore: SyncCryptoStorePtr = Arc::new(LocalKeystore::open(path, password)?);
                keystore
            }
            _ => unreachable!("keystore_config always returns path and password; qed"),
        };

        let signature = sign(
            keystore.clone(),
            key_type.clone(),
            &self.crypto_scheme,
            key,
            message,
        )?;

        println!("{}", signature);
        Ok(())
    }
}

fn sign(
    keystore: Arc<dyn SyncCryptoStore>,
    key_type: KeyTypeId,
    flag: &CryptoSchemeFlag,
    key: &str,
    message: Vec<u8>,
) -> error::Result<String> {
    let signature = match flag.scheme {
        crate::params::CryptoScheme::Ecdsa => {
            let pubkey = if let Ok(pubkey_vec) = hex::decode(key) {
                <sp_core::ecdsa::Pair as Pair>::Public::from_slice(pubkey_vec.as_slice())
                    .map_err(|_| error::Error::KeyFormatInvalid)?
            } else {
                <sp_core::ecdsa::Pair as Pair>::Public::from_string(key)?
            };

            let signature = SyncCryptoStore::sign_with(
                &*keystore,
                key_type,
                &pubkey.to_public_crypto_pair(),
                &message,
            )
            .unwrap()
            .unwrap();

            signature
        }
        crate::params::CryptoScheme::Sr25519 => {
            let pubkey = if let Ok(pubkey_vec) = hex::decode(key) {
                <sp_core::sr25519::Pair as Pair>::Public::from_slice(pubkey_vec.as_slice())
                    .map_err(|_| error::Error::KeyFormatInvalid)?
            } else {
                <sp_core::sr25519::Pair as Pair>::Public::from_string(key)?
            };

            let signature = SyncCryptoStore::sign_with(
                &*keystore,
                key_type,
                &pubkey.to_public_crypto_pair(),
                &message,
            )
            .unwrap()
            .unwrap();

            signature
        }
        crate::params::CryptoScheme::Ed25519 => {
            let pubkey = if let Ok(pubkey_vec) = hex::decode(key) {
                <sp_core::ed25519::Pair as Pair>::Public::from_slice(pubkey_vec.as_slice())
                    .map_err(|_| error::Error::KeyFormatInvalid)?
            } else {
                <sp_core::ed25519::Pair as Pair>::Public::from_string(key)?
            };

            let signature = SyncCryptoStore::sign_with(
                &*keystore,
                key_type,
                &pubkey.to_public_crypto_pair(),
                &message,
            )
            .unwrap()
            .unwrap();

            signature
        }
    };

    Ok(hex::encode(signature))
}

// #[cfg(test)]
// mod test {
// 	use super::*;

// 	#[test]
// 	fn sign() {
// 		let seed = "0xad1fb77243b536b90cfe5f0d351ab1b1ac40e3890b41dc64f766ee56340cfca5";

// 		let sign = SignCmd::parse_from(&[
// 			"sign",
// 			"--suri",
// 			seed,
// 			"--message",
// 			&seed[2..],
// 			"--password",
// 			"12345",
// 		]);
// 		assert!(sign.run().is_ok());
// 	}
// }

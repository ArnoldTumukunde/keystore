// This file is part of Substrate.

// Copyright (C) 2018-2022 Parity Technologies (UK) Ltd.
// SPDX-License-Identifier: GPL-3.0-or-later WITH Classpath-exception-2.0

// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU General Public License for more details.

// You should have received a copy of the GNU General Public License
// along with this program. If not, see <https://www.gnu.org/licenses/>.
pub mod generate;
mod insert_key;
mod inspect_key;
mod key;
mod list_keys;
mod sign;
mod sign_with;
pub mod utils;
mod verify;

use clap::ArgEnum;
use sp_core::{ecdsa, ed25519, sr25519};

pub use sp_core::{
    crypto::{key_types, AccountId32, CryptoType, CryptoTypeId, KeyTypeId},
    TypeId,
};

pub use self::{
    insert_key::InsertKeyCmd, inspect_key::InspectKeyCmd, key::KeySubcommand,
    list_keys::ListKeysCmd, sign::SignCmd, sign_with::SignWithCmd, verify::VerifyCmd,
};

/// Some type that is able to be collapsed into an account ID. It is not possible to recreate the
/// original value from the account ID.
pub trait IdentifyAccount {
    /// The account ID that this can be transformed into.
    type AccountId;
    /// Transform into an account.
    fn into_account(self) -> Self::AccountId;
}

#[derive(Debug, Copy, Clone, PartialEq, Eq, ArgEnum)]
#[clap(rename_all = "PascalCase")]
pub enum OutputType {
    Json,
    Text,
}

/// Public key for any known crypto algorithm.
#[derive(Eq, PartialEq, Ord, PartialOrd, Clone)]
#[cfg_attr(feature = "std", derive(Serialize, Deserialize))]
pub enum MultiSigner {
    /// An Ed25519 identity.
    Ed25519(ed25519::Public),
    /// An Sr25519 identity.
    Sr25519(sr25519::Public),
    /// An SECP256k1/ECDSA identity (actually, the Blake2 hash of the compressed pub key).
    Ecdsa(ecdsa::Public),
}

impl IdentifyAccount for MultiSigner {
    type AccountId = AccountId32;
    fn into_account(self) -> AccountId32 {
        match self {
            Self::Ed25519(who) => <[u8; 32]>::from(who).into(),
            Self::Sr25519(who) => <[u8; 32]>::from(who).into(),
            Self::Ecdsa(who) => sp_io::hashing::blake2_256(who.as_ref()).into(),
        }
    }
}

impl From<ed25519::Public> for MultiSigner {
    fn from(x: ed25519::Public) -> Self {
        Self::Ed25519(x)
    }
}

impl TryFrom<MultiSigner> for ed25519::Public {
    type Error = ();
    fn try_from(m: MultiSigner) -> Result<Self, Self::Error> {
        if let MultiSigner::Ed25519(x) = m {
            Ok(x)
        } else {
            Err(())
        }
    }
}

impl From<sr25519::Public> for MultiSigner {
    fn from(x: sr25519::Public) -> Self {
        Self::Sr25519(x)
    }
}

impl TryFrom<MultiSigner> for sr25519::Public {
    type Error = ();
    fn try_from(m: MultiSigner) -> Result<Self, Self::Error> {
        if let MultiSigner::Sr25519(x) = m {
            Ok(x)
        } else {
            Err(())
        }
    }
}

impl From<ecdsa::Public> for MultiSigner {
    fn from(x: ecdsa::Public) -> Self {
        Self::Ecdsa(x)
    }
}

impl TryFrom<MultiSigner> for ecdsa::Public {
    type Error = ();
    fn try_from(m: MultiSigner) -> Result<Self, Self::Error> {
        if let MultiSigner::Ecdsa(x) = m {
            Ok(x)
        } else {
            Err(())
        }
    }
}

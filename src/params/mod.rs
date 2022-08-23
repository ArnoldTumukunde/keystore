use clap::{ArgEnum, Args};
use sp_core::crypto::Ss58AddressFormat;

use crate::commands::OutputType;

pub mod keystore_params;

/// Optional flag for specifying output type
#[derive(Debug, Clone, Args)]
pub struct OutputTypeFlag {
    /// output format
    #[clap(
        long,
        value_name = "FORMAT",
        arg_enum,
        ignore_case = true,
        default_value = "Text"
    )]
    pub output_type: OutputType,
}

#[derive(Debug, Copy, Clone, PartialEq, Eq, ArgEnum)]
#[clap(rename_all = "PascalCase")]
pub enum CryptoScheme {
    Ed25519,
    Sr25519,
    Ecdsa,
}

/// Optional flag for specifying network scheme
#[derive(Debug, Clone, Args)]
pub struct NetworkSchemeFlag {
    /// network address format
    #[clap(
		short = 'n',
		long,
		value_name = "NETWORK",
		possible_values = &Ss58AddressFormat::all_names()[..],
		ignore_case = true,
		parse(try_from_str = Ss58AddressFormat::try_from),
	)]
    pub network: Option<Ss58AddressFormat>,
}

/// Optional flag for specifying crypto algorithm
#[derive(Debug, Clone, Args)]
pub struct CryptoSchemeFlag {
    /// cryptography scheme
    #[clap(
        long,
        value_name = "SCHEME",
        arg_enum,
        ignore_case = true,
        default_value = "Sr25519"
    )]
    pub scheme: CryptoScheme,
}

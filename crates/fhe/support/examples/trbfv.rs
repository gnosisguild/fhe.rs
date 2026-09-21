//! Shared share lifecycle for the TRBFV examples.

#![allow(dead_code, clippy::expect_used)]

use console::style;
use fhe::Error;
use fhe::trbfv::{
    AggregatedSecretKeyShare, AggregatedSmudgingShare, SecretKeyShare, ShareManager, SmudgingShare,
};
use ndarray::{Array2, ArrayView};

/// Print the common TRBFV example help and terminate the process.
pub fn print_notice_and_exit(error: Option<String>) -> ! {
    println!(
        "{} Threshold BFV example",
        style("  overview:").magenta().bold()
    );
    println!(
        "{} [-h] [--num_summed=N] [--num_parties=N] [--threshold=T] [--lambda=L]",
        style("     usage:").magenta().bold()
    );
    println!(
        "{} N >= 1, T <= (N-1)/2, and L >= 1",
        style("constraints:").magenta().bold()
    );
    if let Some(error) = error {
        println!("{} {}", style("     error:").red().bold(), error);
    }
    std::process::exit(0);
}

/// Common command-line values shared by all TRBFV examples.
#[derive(Clone, Copy)]
pub struct TrbfvCli {
    pub num_summed: Option<usize>,
    pub num_parties: usize,
    pub threshold: usize,
    pub lambda: usize,
}

/// Parse and validate the common TRBFV example arguments.
pub fn parse_cli(
    args: &[String],
    default_num_parties: usize,
    default_threshold: usize,
    default_lambda: usize,
    default_num_summed: Option<usize>,
) -> Result<TrbfvCli, String> {
    let mut values = TrbfvCli {
        num_summed: default_num_summed,
        num_parties: default_num_parties,
        threshold: default_threshold,
        lambda: default_lambda,
    };

    for argument in args {
        let (name, value) = argument
            .split_once('=')
            .ok_or_else(|| format!("Invalid argument `{argument}`"))?;
        let value = value
            .parse::<usize>()
            .map_err(|_| format!("Invalid `{name}` argument"))?;
        match name {
            "--num_summed" if values.num_summed.is_some() => values.num_summed = Some(value),
            "--num_parties" => values.num_parties = value,
            "--threshold" => values.threshold = value,
            "--lambda" => values.lambda = value,
            "--num_summed" => return Err("`--num_summed` is not supported here".into()),
            _ => return Err(format!("Unrecognized argument: {argument}")),
        }
    }

    if values.num_summed.is_some_and(|count| count == 0)
        || values.num_parties == 0
        || values.lambda == 0
    {
        return Err("Party, ciphertext, and lambda counts must be nonzero".into());
    }
    if values.threshold > (values.num_parties - 1) / 2 {
        return Err("Threshold must be at most (num_parties - 1) / 2".into());
    }
    Ok(values)
}

/// Share material carried by the examples through their simulated transport
/// and then through the protected in-memory ownership path.
pub struct TrbfvShares {
    /// Raw matrices exist only as the explicit transport representation.
    pub secret_key_shares_transport: Vec<Array2<u64>>,
    /// Raw matrices exist only as the explicit transport representation.
    pub smudging_shares_transport: Vec<Array2<u64>>,
    secret_key_shares_collected: Vec<SecretKeyShare>,
    smudging_shares_collected: Vec<SmudgingShare>,
    secret_key_aggregate: Option<AggregatedSecretKeyShare>,
    smudging_aggregate: Option<AggregatedSmudgingShare>,
}

impl TrbfvShares {
    #[must_use]
    pub fn new(
        secret_key_shares_transport: Vec<Array2<u64>>,
        smudging_shares_transport: Vec<Array2<u64>>,
    ) -> Self {
        Self {
            secret_key_shares_transport,
            smudging_shares_transport,
            secret_key_shares_collected: Vec::new(),
            smudging_shares_collected: Vec::new(),
            secret_key_aggregate: None,
            smudging_aggregate: None,
        }
    }

    /// Rehydrate one recipient's matrices at the simulated transport boundary.
    pub fn collect_transport(
        &mut self,
        secret_key_share: Array2<u64>,
        smudging_share: Array2<u64>,
    ) {
        self.secret_key_shares_collected
            .push(SecretKeyShare::from_transport(secret_key_share));
        self.smudging_shares_collected
            .push(SmudgingShare::from_transport(smudging_share));
    }

    /// Copy one recipient's rows from per-`q_i` dealt transport matrices.
    #[must_use]
    pub fn recipient_rows(
        secret_key_shares: &[Array2<u64>],
        smudging_shares: &[Array2<u64>],
        receiver_idx: usize,
        degree: usize,
        modulus_count: usize,
    ) -> (Array2<u64>, Array2<u64>) {
        let mut secret_key_rows = Array2::zeros((0, degree));
        let mut smudging_rows = Array2::zeros((0, degree));
        for (secret_key_qi, smudging_qi) in secret_key_shares
            .iter()
            .zip(smudging_shares)
            .take(modulus_count)
        {
            secret_key_rows
                .push_row(ArrayView::from(&secret_key_qi.row(receiver_idx).to_owned()))
                .expect("append secret-key share row");
            smudging_rows
                .push_row(ArrayView::from(&smudging_qi.row(receiver_idx).to_owned()))
                .expect("append smudging share row");
        }
        (secret_key_rows, smudging_rows)
    }

    /// Aggregate collected owners into the reusable key and one-time noise owners.
    pub fn aggregate(&mut self, manager: &ShareManager) -> Result<(), Error> {
        self.secret_key_aggregate =
            Some(manager.aggregate_secret_key_shares(std::mem::take(
                &mut self.secret_key_shares_collected,
            ))?);
        self.smudging_aggregate = Some(
            manager
                .aggregate_smudging_shares(std::mem::take(&mut self.smudging_shares_collected))?,
        );
        Ok(())
    }

    pub fn secret_key(&self) -> Result<&AggregatedSecretKeyShare, Error> {
        self.secret_key_aggregate
            .as_ref()
            .ok_or_else(|| Error::DefaultError("secret-key shares were not aggregated".into()))
    }

    pub fn take_smudging(&mut self) -> Result<AggregatedSmudgingShare, Error> {
        self.smudging_aggregate
            .take()
            .ok_or_else(|| Error::DefaultError("smudging shares were not aggregated".into()))
    }
}

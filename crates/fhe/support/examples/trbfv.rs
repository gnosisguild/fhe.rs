//! Shared share lifecycle for the TRBFV examples.

#![allow(dead_code, clippy::expect_used)]

use console::style;
use fhe::Error;
use fhe::trbfv::{
    AggregatedSecretKeyShare, AggregatedSmudgingShare, SecretKeyShare, ShareManager, SmudgingShare,
};
use ndarray::{Array2, ArrayView};

/// Usage line of the common TRBFV example help.
///
/// `--num_summed` is only advertised when the example supports it (the
/// addition examples); multiplication examples omit it from their usage.
#[must_use]
fn usage_line(supports_num_summed: bool) -> String {
    let summation_argument = if supports_num_summed {
        " [--num_summed=N]"
    } else {
        ""
    };
    format!("[-h|--help]{summation_argument} [--num_parties=N] [--threshold=T] [--lambda=L]")
}

/// Constraints line of the common TRBFV example help.
///
/// These mirror the `ShareManager::new` invariants: at least three parties
/// with the exact honest-majority threshold `T = (N-1)/2`.
const CONSTRAINTS_LINE: &str = "N >= 3, T = (N-1)/2, and L >= 1";

/// Print the common TRBFV example help and terminate the process.
pub fn print_notice_and_exit(error: Option<String>) -> ! {
    print_notice(error, true);
}

/// Print multiplication-example help and terminate the process.
pub fn print_notice_without_num_summed(error: Option<String>) -> ! {
    print_notice(error, false);
}

fn print_notice(error: Option<String>, supports_num_summed: bool) -> ! {
    let exit_code = i32::from(error.is_some());
    println!(
        "{} Threshold BFV example",
        style("  overview:").magenta().bold()
    );
    println!(
        "{} {}",
        style("     usage:").magenta().bold(),
        usage_line(supports_num_summed)
    );
    println!(
        "{} {}",
        style("constraints:").magenta().bold(),
        CONSTRAINTS_LINE
    );
    if let Some(error) = error.as_ref() {
        println!("{} {}", style("     error:").red().bold(), error);
    }
    std::process::exit(exit_code);
}

/// Common command-line values shared by all TRBFV examples.
#[derive(Clone, Copy, Debug)]
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
            "--num_summed" => {
                return Err(
                    "`--num_summed` is not supported by this example (see --help for the \
                     accepted arguments)"
                        .into(),
                );
            }
            _ => return Err(format!("Unrecognized argument: {argument}")),
        }
    }

    if values.num_summed.is_some_and(|count| count == 0)
        || values.num_parties == 0
        || values.lambda == 0
    {
        return Err("Party, ciphertext, and lambda counts must be nonzero".into());
    }
    // Mirror the `ShareManager::new` invariants so invalid settings are
    // rejected before any party setup can panic.
    if values.num_parties < 3 {
        return Err(format!(
            "Number of parties must be at least 3 (got {})",
            values.num_parties
        ));
    }
    let expected_threshold = (values.num_parties - 1) / 2;
    if values.threshold != expected_threshold {
        return Err(format!(
            "Threshold must be exactly (num_parties - 1) / 2 = {expected_threshold} \
             for {} parties (got {})",
            values.num_parties, values.threshold
        ));
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
        let collection_capacity = secret_key_shares_transport
            .first()
            .map_or(0, ndarray::ArrayBase::nrows);
        Self {
            secret_key_shares_transport,
            smudging_shares_transport,
            secret_key_shares_collected: Vec::with_capacity(collection_capacity),
            smudging_shares_collected: Vec::with_capacity(collection_capacity),
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
        assert!(secret_key_shares.len() >= modulus_count);
        assert!(smudging_shares.len() >= modulus_count);
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

#[cfg(test)]
mod tests {
    // Fully-qualified paths: bench targets compile this module with
    // `--cfg test` but strip `#[test]` bodies, which would leave imports
    // flagged as unused under `-D warnings`.

    fn args(arguments: &[&str]) -> Vec<String> {
        arguments
            .iter()
            .map(|argument| (*argument).into())
            .collect()
    }

    #[test]
    fn addition_mode_accepts_valid_arguments() {
        let cli = super::parse_cli(
            &args(&[
                "--num_summed=10",
                "--num_parties=5",
                "--threshold=2",
                "--lambda=40",
            ]),
            20,
            9,
            31,
            Some(50),
        )
        .expect("valid addition arguments must parse");
        assert_eq!(cli.num_summed, Some(10));
        assert_eq!(cli.num_parties, 5);
        assert_eq!(cli.threshold, 2);
        assert_eq!(cli.lambda, 40);
    }

    #[test]
    fn multiplication_mode_accepts_valid_arguments() {
        let cli = super::parse_cli(
            &args(&["--num_parties=3", "--threshold=1", "--lambda=31"]),
            3,
            1,
            31,
            None,
        )
        .expect("valid multiplication arguments must parse");
        assert_eq!(cli.num_summed, None);
        assert_eq!(cli.num_parties, 3);
        assert_eq!(cli.threshold, 1);
        assert_eq!(cli.lambda, 31);

        // Defaults alone must also be valid (no arguments given).
        let cli = super::parse_cli(&args(&[]), 20, 9, 31, None)
            .expect("multiplication defaults must parse");
        assert_eq!(cli.num_parties, 20);
        assert_eq!(cli.threshold, 9);
        assert_eq!(cli.num_summed, None);
    }

    #[test]
    fn multiplication_mode_rejects_previously_accepted_invalid_configs() {
        // Regression for the shared parser in multiplication mode
        // (`default_num_summed = None`): these inputs passed the old
        // `N >= 1, T <= (N-1)/2` validation but made `ShareManager::new`
        // reject the configuration (or panic in older versions) after the
        // CLI had accepted them.
        let error = super::parse_cli(&args(&["--num_parties=5", "--threshold=1"]), 5, 2, 31, None)
            .expect_err("non-exact threshold must be rejected in multiplication mode");
        assert!(
            error.contains("exactly (num_parties - 1) / 2 = 2"),
            "{error}"
        );

        let error = super::parse_cli(&args(&["--num_parties=2", "--threshold=0"]), 2, 0, 31, None)
            .expect_err("two parties must be rejected in multiplication mode");
        assert!(error.contains("at least 3"), "{error}");

        // Valid control in the same mode: exact threshold for five parties.
        let cli = super::parse_cli(&args(&["--num_parties=5", "--threshold=2"]), 5, 2, 31, None)
            .expect("exact threshold must parse in multiplication mode");
        assert_eq!(cli.num_parties, 5);
        assert_eq!(cli.threshold, 2);
        assert_eq!(cli.num_summed, None);
    }

    #[test]
    fn addition_mode_rejects_zero_num_summed() {
        let error = super::parse_cli(&args(&["--num_summed=0"]), 20, 9, 31, Some(50))
            .expect_err("zero num_summed must be rejected");
        assert!(error.contains("nonzero"), "{error}");
    }

    #[test]
    fn rejects_zero_lambda() {
        let error = super::parse_cli(&args(&["--lambda=0"]), 20, 9, 31, Some(50))
            .expect_err("zero lambda must be rejected");
        assert!(error.contains("nonzero"), "{error}");
    }

    #[test]
    fn rejects_previously_accepted_invalid_party_counts() {
        // n = 1 and n = 2 satisfied the old `N >= 1, T <= (N-1)/2` help text
        // but made `ShareManager::new` reject the configuration later.
        for num_parties in [1_usize, 2] {
            let threshold = (num_parties - 1) / 2;
            let error = super::parse_cli(&args(&[]), num_parties, threshold, 31, Some(50))
                .expect_err("fewer than three parties must be rejected");
            assert!(error.contains("at least 3"), "{error}");
        }
    }

    #[test]
    fn rejects_previously_accepted_lower_threshold() {
        // `T = 1 <= (5-1)/2` passed the old `T <= (N-1)/2` check but
        // `ShareManager::new` requires exactly `(n-1)/2`.
        let error = super::parse_cli(
            &args(&["--num_parties=5", "--threshold=1"]),
            5,
            2,
            31,
            Some(50),
        )
        .expect_err("non-exact threshold must be rejected");
        assert!(
            error.contains("exactly (num_parties - 1) / 2 = 2"),
            "{error}"
        );
    }

    #[test]
    fn rejects_mismatched_threshold_for_party_count() {
        for (num_parties, threshold) in [(7_usize, 2_usize), (10, 3), (20, 10)] {
            let error = super::parse_cli(
                &args(&[
                    &format!("--num_parties={num_parties}"),
                    &format!("--threshold={threshold}"),
                ]),
                num_parties,
                (num_parties - 1) / 2,
                31,
                Some(50),
            )
            .expect_err("mismatched threshold must be rejected");
            assert!(
                error.contains(&((num_parties - 1) / 2).to_string()),
                "{error}"
            );
        }
    }

    #[test]
    fn multiplication_mode_rejects_num_summed_early() {
        let error = super::parse_cli(&args(&["--num_summed=4"]), 3, 1, 31, None)
            .expect_err("num_summed must be rejected in multiplication mode");
        assert!(error.contains("--num_summed"), "{error}");
        assert!(error.contains("--help"), "{error}");
    }

    #[test]
    fn rejects_unrecognized_and_malformed_arguments() {
        let error = super::parse_cli(&args(&["--parties=5"]), 5, 2, 31, Some(50))
            .expect_err("unknown flags must be rejected");
        assert!(error.contains("Unrecognized argument"), "{error}");

        let error = super::parse_cli(&args(&["--num_parties"]), 5, 2, 31, Some(50))
            .expect_err("flags without values must be rejected");
        assert!(error.contains("Invalid argument"), "{error}");

        let error = super::parse_cli(&args(&["--num_parties=abc"]), 5, 2, 31, Some(50))
            .expect_err("non-numeric values must be rejected");
        assert!(
            error.contains("Invalid `--num_parties` argument"),
            "{error}"
        );
    }

    #[test]
    fn help_text_matches_mode_and_constraints() {
        let addition_usage = super::usage_line(true);
        let multiplication_usage = super::usage_line(false);
        assert!(addition_usage.starts_with("[-h|--help]"));
        assert!(addition_usage.contains("[--num_summed=N]"));
        assert!(!multiplication_usage.contains("--num_summed"));
        // The shared lines carry the exact ShareManager invariants.
        for usage in [&addition_usage, &multiplication_usage] {
            assert!(usage.contains("[--num_parties=N]"));
            assert!(usage.contains("[--threshold=T]"));
            assert!(usage.contains("[--lambda=L]"));
        }
        assert!(super::CONSTRAINTS_LINE.contains("N >= 3"));
        assert!(super::CONSTRAINTS_LINE.contains("T = (N-1)/2"));
        assert!(super::CONSTRAINTS_LINE.contains("L >= 1"));
    }
}

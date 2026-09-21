//! Shared share lifecycle for the TRBFV examples.

#![allow(dead_code, clippy::expect_used)]

use fhe::Error;
use fhe::trbfv::{
    AggregatedSecretKeyShare, AggregatedSmudgingShare, SecretKeyShare, ShareManager, SmudgingShare,
};
use ndarray::{Array2, ArrayView};

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

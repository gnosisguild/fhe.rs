/*!
 * Canonical participant/session binding types for l-BFV distributed key generation.
 *
 * Metadata binding is **consistency binding, not authentication**. The types
 * in this module record *who contributed what* and *to which session*, so
 * that aggregation can enforce exact participant-set equality and reject
 * duplicate or missing contributions. No signatures, broadcast protocol, or
 * full DKG orchestration is provided here.
 *
 * For the robust-DKG adversarial model and protocol-level guarantees, see
 * Urban–Rambaud (2024), §5: Robust Multiparty Computation from Threshold
 * Encryption Based on RLWE.
 */

use crate::{Error, Result};

/// A canonical, sorted set of participant IDs bound to a session.
///
/// Participant IDs must be nonzero `u32` values, unique, and the set must be
/// nonempty. The set is sorted at construction time so equality comparisons
/// are deterministic.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParticipantSet {
    session_id: [u8; 32],
    participant_ids: Box<[u32]>,
}

impl ParticipantSet {
    /// Create a new participant set for the given session.
    ///
    /// The `participant_ids` vector is sorted and deduplication-checked.
    /// Returns an error if the vector is empty, contains a zero ID, or
    /// contains duplicate IDs.
    ///
    /// # Noise budget (caller responsibility)
    ///
    /// This constructor does **not** bound the participant count against any
    /// BFV noise budget. Aggregated l-BFV keys accumulate `Σ e_i` error, whose
    /// variance grows linearly in `|S|` (see [`super::RelinKeyShare`] noise-growth
    /// notes). A set large enough that the aggregated relinearization key's
    /// noise exceeds the configured parameters' budget will still construct and
    /// aggregate successfully, but multiplication correctness is no longer
    /// guaranteed. Callers must validate `|S|` against their parameter set's
    /// noise budget before accepting a participant set for key generation.
    ///
    /// [`super::RelinKeyShare`]: super::RelinKeyShare
    pub fn new(session_id: [u8; 32], mut participant_ids: Vec<u32>) -> Result<Self> {
        if participant_ids.is_empty() {
            return Err(Error::DefaultError(
                "LBFV participant set must not be empty".to_string(),
            ));
        }
        if participant_ids.contains(&0) {
            return Err(Error::DefaultError(
                "LBFV participant IDs must be nonzero".to_string(),
            ));
        }

        participant_ids.sort_unstable();
        if participant_ids.windows(2).any(|pair| match pair {
            [left, right] => left == right,
            _ => false,
        }) {
            return Err(Error::DefaultError(
                "LBFV participant IDs must be unique".to_string(),
            ));
        }

        Ok(Self {
            session_id,
            participant_ids: participant_ids.into_boxed_slice(),
        })
    }

    /// The 32-byte session identifier.
    #[must_use]
    pub fn session_id(&self) -> &[u8; 32] {
        &self.session_id
    }

    /// The sorted, unique participant IDs in this set.
    #[must_use]
    pub fn participant_ids(&self) -> &[u32] {
        &self.participant_ids
    }

    /// Validate that the given contributions contain exactly one binding for
    /// every participant ID in this set, that all bindings reference the same
    /// participant set, and that no participant contributed more than once.
    pub(crate) fn validate_contributions<'a, I>(&self, bindings: I) -> Result<()>
    where
        I: IntoIterator<Item = &'a ContributionBinding>,
    {
        let mut ids = Vec::new();

        for binding in bindings {
            if &binding.participant_set != self {
                return Err(Error::DefaultError(
                    "LBFV contributions use different participant sets".to_string(),
                ));
            }
            if ids.contains(&binding.participant_id) {
                return Err(Error::DefaultError(
                    "LBFV participant contributed more than once".to_string(),
                ));
            }
            ids.push(binding.participant_id);
        }

        ids.sort_unstable();
        if ids.as_slice() != self.participant_ids.as_ref() {
            return Err(Error::DefaultError(
                "LBFV contributions do not contain the complete accepted participant set"
                    .to_string(),
            ));
        }

        Ok(())
    }
}

/// A binding that ties a single participant contribution to a specific
/// participant set and participant ID.
///
/// This is not cryptographic authentication — it is consistency metadata that
/// allows aggregation to verify that all contributions belong to the same
/// session and cover the complete participant set.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContributionBinding {
    pub(crate) participant_set: ParticipantSet,
    pub(crate) participant_id: u32,
}

impl ContributionBinding {
    /// Create a new contribution binding.
    ///
    /// The participant ID must be nonzero and must be present in the
    /// participant set.
    pub fn new(participant_set: ParticipantSet, participant_id: u32) -> Result<Self> {
        if participant_id == 0 {
            return Err(Error::DefaultError(
                "LBFV participant ID must be nonzero".to_string(),
            ));
        }
        if !participant_set.participant_ids().contains(&participant_id) {
            return Err(Error::DefaultError(
                "LBFV participant ID is not in the accepted participant set".to_string(),
            ));
        }

        Ok(Self {
            participant_set,
            participant_id,
        })
    }

    /// The participant set this contribution belongs to.
    #[must_use]
    pub fn participant_set(&self) -> &ParticipantSet {
        &self.participant_set
    }

    /// The participant ID of this contribution.
    #[must_use]
    pub fn participant_id(&self) -> u32 {
        self.participant_id
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn participant_binding_is_canonical_and_requires_exact_members() -> Result<()> {
        let set = ParticipantSet::new([7u8; 32], vec![3, 1, 2])?;
        assert_eq!(set.participant_ids(), &[1, 2, 3]);

        let first = ContributionBinding::new(set.clone(), 1)?;
        let second = ContributionBinding::new(set.clone(), 2)?;
        let third = ContributionBinding::new(set.clone(), 3)?;

        set.validate_contributions([&third, &first, &second])?;
        assert!(
            set.validate_contributions([&first, &first, &third])
                .is_err()
        );
        assert!(set.validate_contributions([&first, &second]).is_err());

        assert!(ParticipantSet::new([0u8; 32], vec![1, 1]).is_err());
        assert!(ContributionBinding::new(set, 0).is_err());

        Ok(())
    }
}

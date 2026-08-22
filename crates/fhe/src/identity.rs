//! Shared participant and session metadata for distributed BFV APIs.

use crate::{Error, Result};

/// An opaque caller-supplied identifier for a key epoch or one decryption use.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SessionId([u8; 32]);

impl SessionId {
    /// Construct an identifier from caller-supplied bytes.
    #[must_use]
    pub const fn new(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Borrow the opaque identifier bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl From<[u8; 32]> for SessionId {
    fn from(bytes: [u8; 32]) -> Self {
        Self::new(bytes)
    }
}

/// A sorted, non-empty set of 1-based participant identifiers for one epoch.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParticipantSet {
    session_id: SessionId,
    participant_ids: Box<[u32]>,
}

impl ParticipantSet {
    /// Create a canonical participant set, rejecting zero and duplicate IDs.
    pub fn new<S: Into<SessionId>>(session_id: S, mut participant_ids: Vec<u32>) -> Result<Self> {
        if participant_ids.is_empty() {
            return Err(Error::Threshold(crate::ThresholdError::EmptyParticipantSet));
        }
        if participant_ids.contains(&0) {
            return Err(Error::Threshold(
                crate::ThresholdError::InvalidParticipantId {
                    participant_id: 0,
                    n: usize::MAX,
                },
            ));
        }
        participant_ids.sort_unstable();
        if let Some(participant_id) = participant_ids.windows(2).find_map(|pair| {
            let left = pair.first().copied()?;
            let right = pair.get(1).copied()?;
            (left == right).then_some(right)
        }) {
            return Err(Error::Threshold(
                crate::ThresholdError::DuplicateContribution { participant_id },
            ));
        }
        Ok(Self {
            session_id: session_id.into(),
            participant_ids: participant_ids.into_boxed_slice(),
        })
    }

    /// The key-epoch identifier.
    #[must_use]
    pub fn session_id(&self) -> SessionId {
        self.session_id
    }

    /// Borrow the sorted participant IDs.
    #[must_use]
    pub fn participant_ids(&self) -> &[u32] {
        &self.participant_ids
    }

    /// Return whether an ID belongs to this set.
    #[must_use]
    pub fn contains(&self, participant_id: u32) -> bool {
        self.participant_ids.binary_search(&participant_id).is_ok()
    }

    /// Validate exact, one-per-member contribution coverage.
    pub(crate) fn validate_contributions<'a, I>(&self, bindings: I) -> Result<()>
    where
        I: IntoIterator<Item = &'a ContributionBinding>,
    {
        let mut ids = Vec::new();
        for binding in bindings {
            if binding.participant_set != *self {
                return Err(Error::Threshold(
                    crate::ThresholdError::ContributionSetMismatch,
                ));
            }
            if ids.contains(&binding.participant_id) {
                return Err(Error::Threshold(
                    crate::ThresholdError::DuplicateContribution {
                        participant_id: binding.participant_id,
                    },
                ));
            }
            if !self.contains(binding.participant_id) {
                return Err(Error::Threshold(
                    crate::ThresholdError::UnexpectedContribution {
                        participant_id: binding.participant_id,
                    },
                ));
            }
            ids.push(binding.participant_id);
        }
        ids.sort_unstable();
        if ids.as_slice() != self.participant_ids.as_ref() {
            return Err(Error::Threshold(crate::ThresholdError::MissingContribution));
        }
        Ok(())
    }
}

/// Metadata binding for one participant's contribution.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContributionBinding {
    participant_set: ParticipantSet,
    participant_id: u32,
}

impl ContributionBinding {
    /// Create a binding for a member of `participant_set`.
    pub fn new(participant_set: ParticipantSet, participant_id: u32) -> Result<Self> {
        if participant_id == 0 || !participant_set.contains(participant_id) {
            return Err(Error::Threshold(
                crate::ThresholdError::InvalidParticipantId {
                    participant_id,
                    n: participant_set.participant_ids().len(),
                },
            ));
        }
        Ok(Self {
            participant_set,
            participant_id,
        })
    }

    /// Borrow the participant set for this contribution.
    #[must_use]
    pub fn participant_set(&self) -> &ParticipantSet {
        &self.participant_set
    }

    /// The participant ID attached to this contribution.
    #[must_use]
    pub fn participant_id(&self) -> u32 {
        self.participant_id
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonical_set_and_exact_bindings() -> Result<()> {
        let set = ParticipantSet::new(SessionId::new([7; 32]), vec![3, 1, 2])?;
        assert_eq!(set.participant_ids(), &[1, 2, 3]);
        assert!(matches!(
            ParticipantSet::new(SessionId::new([7; 32]), vec![1, 2, 2]),
            Err(Error::Threshold(
                crate::ThresholdError::DuplicateContribution { participant_id: 2 }
            ))
        ));
        let one = ContributionBinding::new(set.clone(), 1)?;
        let two = ContributionBinding::new(set.clone(), 2)?;
        let three = ContributionBinding::new(set.clone(), 3)?;
        set.validate_contributions([&three, &one, &two])?;
        assert!(set.validate_contributions([&one, &one, &three]).is_err());
        assert!(set.validate_contributions([&one, &two]).is_err());
        Ok(())
    }
}

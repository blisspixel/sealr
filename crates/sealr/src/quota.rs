//! Pure monotone quota transitions.

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct QuotaState {
    used: u64,
    limit: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum QuotaError {
    Overflow,
    Exceeded { attempted: u64, limit: u64 },
}

impl QuotaState {
    pub(crate) fn new(limit: u64) -> Self {
        Self { used: 0, limit }
    }

    /// Apply one atomic transition. A failed transition leaves the state
    /// unchanged, so callers cannot accidentally account a rejected chunk.
    pub(crate) fn consume(&mut self, amount: u64) -> Result<u64, QuotaError> {
        let next = self.used.checked_add(amount).ok_or(QuotaError::Overflow)?;
        if next > self.limit {
            return Err(QuotaError::Exceeded {
                attempted: next,
                limit: self.limit,
            });
        }
        self.used = next;
        Ok(next)
    }

    pub(crate) fn used(self) -> u64 {
        self.used
    }

    pub(crate) fn remaining(self) -> u64 {
        self.limit - self.used
    }
}

#[cfg(kani)]
mod kani_proofs {
    use super::*;

    #[kani::proof]
    fn quota_consume_matches_wide_oracle_and_is_atomic() {
        let used: u64 = kani::any();
        let limit: u64 = kani::any();
        let amount: u64 = kani::any();
        kani::assume(used <= limit);

        let mut state = QuotaState { used, limit };
        let before = state;
        let actual = state.consume(amount);
        let wide_next = u128::from(used) + u128::from(amount);
        let expected = if wide_next > u128::from(u64::MAX) {
            Err(QuotaError::Overflow)
        } else {
            let next = wide_next as u64;
            if next > limit {
                Err(QuotaError::Exceeded {
                    attempted: next,
                    limit,
                })
            } else {
                Ok(next)
            }
        };

        assert_eq!(actual, expected);
        match expected {
            Ok(next) => {
                assert_eq!(state.used(), next);
                assert_eq!(state.remaining(), limit - next);
            }
            Err(_) => assert_eq!(state, before),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn quota_transitions_match_wide_integer_oracle() {
        let mut values: Vec<u64> = (0..=64).collect();
        values.extend([u64::MAX - 2, u64::MAX - 1, u64::MAX]);

        let mut checked_transitions = 0_u64;
        for &limit in &values {
            for &used in values.iter().filter(|&&value| value <= limit) {
                let mut state = QuotaState::new(limit);
                assert_eq!(state.consume(used), Ok(used));
                for &amount in &values {
                    let mut candidate = state;
                    let before = candidate;
                    let wide_next = u128::from(used) + u128::from(amount);
                    let expected = if wide_next > u128::from(u64::MAX) {
                        Err(QuotaError::Overflow)
                    } else {
                        let next = wide_next as u64;
                        if next > limit {
                            Err(QuotaError::Exceeded {
                                attempted: next,
                                limit,
                            })
                        } else {
                            Ok(next)
                        }
                    };

                    assert_eq!(
                        candidate.consume(amount),
                        expected,
                        "used={used}, amount={amount}, limit={limit}"
                    );
                    match expected {
                        Ok(next) => {
                            assert_eq!(candidate.used(), next);
                            assert_eq!(candidate.remaining(), limit - next);
                        }
                        Err(_) => assert_eq!(candidate, before, "failed transition mutated state"),
                    }
                    checked_transitions += 1;
                }
            }
        }
        assert_eq!(checked_transitions, 159_528);
    }
}

//! Pure compression-ratio comparison.

/// Strict greater-than comparison of uncompressed/compressed against `max_ratio`.
///
/// `uncomp == max_ratio * comp` passes. `comp == 0` is infinite when `uncomp > 0`
/// and passes only when both sides are zero. `max_ratio == 0` is not "off";
/// disable the check with `None`.
pub fn ratio_exceeds(uncomp: u64, comp: u64, max_ratio: u64) -> bool {
    if comp == 0 {
        return uncomp > 0;
    }
    // The product of two u64 values always fits in u128 exactly.
    let product = u128::from(max_ratio) * u128::from(comp);
    u128::from(uncomp) > product
}

#[cfg(kani)]
mod kani_proofs {
    use super::*;

    #[kani::proof]
    #[kani::solver(kissat)]
    fn ratio_exceeds_matches_checked_product_oracle() {
        let uncomp: u64 = kani::any();
        let comp: u64 = kani::any();
        let max_ratio: u64 = kani::any();
        let expected = max_ratio
            .checked_mul(comp)
            .is_some_and(|threshold| uncomp > threshold);

        assert_eq!(ratio_exceeds(uncomp, comp, max_ratio), expected);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ratio_exceeds_table() {
        assert!(!ratio_exceeds(1000, 10, 100));
        assert!(ratio_exceeds(1001, 10, 100));
        assert!(!ratio_exceeds(100, 1, 100));
        assert!(ratio_exceeds(101, 1, 100));
        assert!(!ratio_exceeds(50, 50, 100));
        assert!(ratio_exceeds(51, 50, 1));
        assert!(!ratio_exceeds(0, 0, 100));
        assert!(!ratio_exceeds(0, 1, 100));
        assert!(ratio_exceeds(1, 0, 100));
        assert!(!ratio_exceeds(1, 1, 1));
        assert!(ratio_exceeds(2, 1, 1));
        assert!(!ratio_exceeds(u64::MAX, u64::MAX, 100));
        assert!(ratio_exceeds(u64::MAX, 1, 100));
        let exact_comp = u64::MAX / 100;
        assert!(!ratio_exceeds(
            exact_comp.saturating_mul(100),
            exact_comp,
            100
        ));
        assert!(ratio_exceeds(
            exact_comp.saturating_mul(100).saturating_add(1),
            exact_comp,
            100
        ));
        let mantissa = (1_u64 << 53) + 1;
        assert!(ratio_exceeds(mantissa, 1, 1_u64 << 53));
    }

    #[test]
    fn ratio_exceeds_matches_an_independent_small_domain_oracle() {
        fn oracle(uncomp: u64, comp: u64, max_ratio: u64) -> bool {
            if comp == 0 {
                return uncomp > 0;
            }
            let quotient = uncomp / comp;
            let remainder = uncomp % comp;
            quotient > max_ratio || (quotient == max_ratio && remainder > 0)
        }

        for uncomp in 0..=255 {
            for comp in 0..=64 {
                for max_ratio in 0..=64 {
                    assert_eq!(
                        ratio_exceeds(uncomp, comp, max_ratio),
                        oracle(uncomp, comp, max_ratio),
                        "uncomp={uncomp}, comp={comp}, max_ratio={max_ratio}"
                    );
                }
            }
        }
    }
}

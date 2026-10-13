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

/// POSIX/GNU tar write records. GNU tar's default blocking factor is 20.
pub(crate) const TAR_RECORD_LEN: u64 = 10_240;
pub(crate) const TAR_TERMINATOR_LEN: u64 = 1_024;

/// Bytes charged to a derived TAR compression ratio.
///
/// The verified 1024-byte terminator and the verified all-zero bytes that
/// finish the single 10240-byte record containing that terminator are
/// mandatory framing, not payload expansion. Every other decoded byte stays
/// in the numerator, including member headers, member payloads, per-member
/// block padding, and trailing zeros past that one record. A terminator that
/// is not exactly 1024 bytes or is not adjacent to the trailing-zero range
/// charges the full decoded length.
pub(crate) fn derived_tar_ratio_numerator(
    decoded_len: u64,
    terminator_offset: u64,
    terminator_len: u64,
    trailing_offset: u64,
    trailing_len: u64,
) -> u64 {
    if terminator_len != TAR_TERMINATOR_LEN {
        return decoded_len;
    }
    let Some(terminator_end) = terminator_offset.checked_add(terminator_len) else {
        return decoded_len;
    };
    if trailing_offset != terminator_end || terminator_end > decoded_len {
        return decoded_len;
    }
    let records = terminator_end.div_ceil(TAR_RECORD_LEN);
    let Some(record_end) = records.checked_mul(TAR_RECORD_LEN) else {
        return decoded_len;
    };
    let mandatory_pad = record_end.saturating_sub(terminator_end);
    let excluded_pad = mandatory_pad.min(trailing_len);
    let Some(excluded) = TAR_TERMINATOR_LEN.checked_add(excluded_pad) else {
        return decoded_len;
    };
    decoded_len.saturating_sub(excluded.min(decoded_len))
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
    fn derived_tar_numerator_excludes_only_one_record_of_framing() {
        // One small ustar member: header and payload end at 1024, the
        // terminator occupies 1024..2048, and the rest of that record is pad.
        assert_eq!(
            derived_tar_ratio_numerator(10_240, 1_024, 1_024, 2_048, 8_192),
            1_024
        );
        // Empty member: the header ends at 512 and the terminator at 1536.
        assert_eq!(
            derived_tar_ratio_numerator(10_240, 512, 1_024, 1_536, 8_704),
            512
        );
        // Hand-built archives with no record padding still drop the terminator.
        assert_eq!(
            derived_tar_ratio_numerator(2_048, 1_024, 1_024, 2_048, 0),
            1_024
        );
        // A terminator that already ends on a record boundary has no mandatory
        // pad. Zeros in the following record stay charged.
        assert_eq!(
            derived_tar_ratio_numerator(20_480, 9_216, 1_024, 10_240, 10_240),
            19_456
        );
        // Zeros past the record that contains the terminator stay charged.
        assert_eq!(
            derived_tar_ratio_numerator(20_480, 1_024, 1_024, 2_048, 18_432),
            1_024 + 10_240
        );
        // A 2 MiB member is not framing.
        let decoded = 2 * 1024 * 1024;
        let numerator =
            derived_tar_ratio_numerator(decoded, decoded - 9_216, 1_024, decoded - 8_192, 8_192);
        assert!(numerator > 2 * 1024 * 1024 - 10_240);
        assert_eq!(derived_tar_ratio_numerator(10_240, 0, 512, 512, 0), 10_240);
        assert_eq!(
            derived_tar_ratio_numerator(10_240, 2_048, 1_024, 4_000, 8_192),
            10_240
        );
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

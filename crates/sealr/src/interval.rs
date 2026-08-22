//! Pure checked half-open intervals and exact partition validation.
//!
//! ZIP discovery and the codec-free covering audit share this arithmetic so
//! overflow, containment, gaps, and overlap have one production definition.

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct CheckedInterval {
    start: u64,
    end: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum IntervalError {
    EndOverflow,
    Reversed,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum PartitionError {
    EmptyPart { index: usize },
    PartOutside { index: usize },
    MissingParts,
    GapBeforeFirst { index: usize },
    Overlap { index: usize },
    Gap { index: usize },
    GapAfterLast { index: usize },
}

impl CheckedInterval {
    pub(crate) fn from_offset_len(offset: u64, len: u64) -> Result<Self, IntervalError> {
        let end = offset.checked_add(len).ok_or(IntervalError::EndOverflow)?;
        Ok(Self { start: offset, end })
    }

    pub(crate) fn from_bounds(start: u64, end: u64) -> Result<Self, IntervalError> {
        if end < start {
            return Err(IntervalError::Reversed);
        }
        Ok(Self { start, end })
    }

    pub(crate) fn start(self) -> u64 {
        self.start
    }

    pub(crate) fn end(self) -> u64 {
        self.end
    }

    pub(crate) fn is_empty(self) -> bool {
        self.start == self.end
    }

    pub(crate) fn contains(self, inner: Self) -> bool {
        inner.start >= self.start && inner.end <= self.end
    }
}

/// Validate that nonempty `parts`, in any input order, cover `outer` exactly
/// once. The returned index always refers to the original `parts` slice.
pub(crate) fn exact_partition(
    outer: CheckedInterval,
    parts: &[CheckedInterval],
) -> Result<(), PartitionError> {
    if parts.is_empty() {
        return if outer.is_empty() {
            Ok(())
        } else {
            Err(PartitionError::MissingParts)
        };
    }

    let mut ordered: Vec<(usize, CheckedInterval)> = parts.iter().copied().enumerate().collect();
    ordered.sort_by_key(|(_, interval)| interval.start);

    for (index, interval) in &ordered {
        if interval.is_empty() {
            return Err(PartitionError::EmptyPart { index: *index });
        }
        if !outer.contains(*interval) {
            return Err(PartitionError::PartOutside { index: *index });
        }
    }

    let (first_index, first) = ordered[0];
    if first.start != outer.start {
        return Err(PartitionError::GapBeforeFirst { index: first_index });
    }

    for window in ordered.windows(2) {
        let previous = window[0].1;
        let (index, next) = window[1];
        if previous.end > next.start {
            return Err(PartitionError::Overlap { index });
        }
        if previous.end < next.start {
            return Err(PartitionError::Gap { index });
        }
    }

    let (last_index, last) = ordered[ordered.len() - 1];
    if last.end != outer.end {
        return Err(PartitionError::GapAfterLast { index: last_index });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn checked_offset_length_matches_wide_integer_oracle() {
        let mut values: Vec<u64> = (0..=64).collect();
        values.extend([u64::MAX - 2, u64::MAX - 1, u64::MAX]);

        for &offset in &values {
            for &len in &values {
                let wide_end = u128::from(offset) + u128::from(len);
                let expected = (wide_end <= u128::from(u64::MAX)).then_some(wide_end as u64);
                let actual = CheckedInterval::from_offset_len(offset, len).map(|range| range.end());
                match expected {
                    Some(end) => assert_eq!(actual, Ok(end), "offset={offset}, len={len}"),
                    None => assert_eq!(
                        actual,
                        Err(IntervalError::EndOverflow),
                        "offset={offset}, len={len}"
                    ),
                }
            }
        }
    }

    #[test]
    fn exact_partition_matches_bounded_bitmap_oracle() {
        let candidates: Vec<CheckedInterval> = (0..=7)
            .flat_map(|start| {
                (start..=7).map(move |end| CheckedInterval::from_bounds(start, end).unwrap())
            })
            .collect();

        for outer_start in 0..=3 {
            for outer_end in outer_start..=6 {
                let outer = CheckedInterval::from_bounds(outer_start, outer_end).unwrap();
                let mut parts = Vec::new();
                compare_all_part_lists(outer, &candidates, &mut parts, 0);
                compare_all_part_lists(outer, &candidates, &mut parts, 1);
                compare_all_part_lists(outer, &candidates, &mut parts, 2);
                compare_all_part_lists(outer, &candidates, &mut parts, 3);
            }
        }
    }

    fn compare_all_part_lists(
        outer: CheckedInterval,
        candidates: &[CheckedInterval],
        parts: &mut Vec<CheckedInterval>,
        remaining: usize,
    ) {
        if remaining == 0 {
            let expected = bitmap_partition_oracle(outer, parts);
            assert_eq!(
                exact_partition(outer, parts).is_ok(),
                expected,
                "outer={outer:?}, parts={parts:?}"
            );
            return;
        }

        for &candidate in candidates {
            parts.push(candidate);
            compare_all_part_lists(outer, candidates, parts, remaining - 1);
            parts.pop();
        }
    }

    fn bitmap_partition_oracle(outer: CheckedInterval, parts: &[CheckedInterval]) -> bool {
        if outer.is_empty() {
            return parts.is_empty();
        }
        if parts.is_empty() || parts.iter().any(|part| part.is_empty()) {
            return false;
        }

        let mut counts = vec![0_u8; (outer.end() - outer.start()) as usize];
        for part in parts {
            if part.start() < outer.start() || part.end() > outer.end() {
                return false;
            }
            for position in part.start()..part.end() {
                let index = (position - outer.start()) as usize;
                counts[index] = counts[index].saturating_add(1);
            }
        }
        counts.into_iter().all(|count| count == 1)
    }
}

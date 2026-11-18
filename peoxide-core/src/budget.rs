//! A cap on the bytes one walk may copy out of a PE.
//!
//! Crafted tables can point many entries at the same bytes, so a small file would otherwise
//! have them copied once per entry, gigabytes in all. A walk that copies strings out of such
//! tables charges them to one `ByteBudget` and stops copying once it is spent.

use std::cell::Cell;

/// Bytes a walk may still copy. Once a charge does not fit, the budget stays spent.
pub(crate) struct ByteBudget(Cell<usize>);

impl ByteBudget {
    pub(crate) fn new(bytes: usize) -> Self {
        Self(Cell::new(bytes))
    }

    /// Charges `bytes`, or spends what is left and returns false when they do not fit.
    pub(crate) fn take(&self, bytes: usize) -> bool {
        let left = self.0.get().checked_sub(bytes);
        self.0.set(left.unwrap_or(0));
        left.is_some()
    }
}

#[cfg(test)]
mod tests {
    use super::ByteBudget;

    #[test]
    fn a_charge_that_does_not_fit_spends_the_rest() {
        let budget = ByteBudget::new(10);
        assert!(budget.take(6));
        assert!(!budget.take(5));
        assert!(!budget.take(1));
    }
}

// Copyright 2016 lazy-static.rs Developers; CKB adapter 2026 Tactus contributors.
// Licensed under MIT OR Apache-2.0, as the original crate.
// CKB executes each script VM on one thread without signal handlers. This
// backend must never be selected in a shared-memory multithreaded environment.
use core::cell::{Cell, UnsafeCell};
use core::mem::MaybeUninit;

pub struct Lazy<T: Sync> {
    state: Cell<u8>,
    value: UnsafeCell<MaybeUninit<T>>,
}

// SAFETY: the feature is restricted to the CKB single-thread target in lib.rs.
// No other VM shares this address space. Reentrant initialization is rejected
// before accessing uninitialized data; state 2 is published only after the write.
unsafe impl<T: Sync> Sync for Lazy<T> {}

impl<T: Sync> Lazy<T> {
    pub const INIT: Self = Self {
        state: Cell::new(0),
        value: UnsafeCell::new(MaybeUninit::uninit()),
    };

    #[inline(always)]
    pub fn get<F>(&'static self, builder: F) -> &'static T
    where
        F: FnOnce() -> T,
    {
        match self.state.get() {
            0 => {
                self.state.set(1);
                let value = builder();
                // SAFETY: state 1 excludes reentrant access, and no second
                // thread exists in this VM. This is the only initialization.
                unsafe { (*self.value.get()).write(value) };
                self.state.set(2);
            }
            2 => {}
            _ => panic!("recursive or poisoned CKB lazy initialization"),
        }
        // SAFETY: both paths reaching here have initialized value exactly once.
        unsafe { (&*self.value.get()).assume_init_ref() }
    }
}

#[macro_export]
#[doc(hidden)]
macro_rules! __lazy_static_create {
    ($NAME:ident, $T:ty) => {
        static $NAME: $crate::lazy::Lazy<$T> = $crate::lazy::Lazy::INIT;
    };
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn initializes_once_and_keeps_the_same_value() {
        static VALUE: Lazy<[u8; 4]> = Lazy::INIT;
        let first = VALUE.get(|| [1, 2, 3, 4]);
        let second = VALUE.get(|| panic!("builder must run once"));
        assert_eq!(first, &[1, 2, 3, 4]);
        assert!(core::ptr::eq(first, second));
    }
    #[test]
    fn recursion_and_poison_fail_before_uninitialized_access() {
        static VALUE: Lazy<u8> = Lazy::INIT;
        let first = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            VALUE.get(|| *VALUE.get(|| 42))
        }));
        assert!(first.is_err());
        let retry = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| VALUE.get(|| 42)));
        assert!(retry.is_err());
    }
}

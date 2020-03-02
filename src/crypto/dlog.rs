use crate::crypto::group::{generator, Element, Exponent};
use lazy_static::*;
use num::traits::One;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

/// Compute the discrete log, base `g` (from the common `generator`)
/// of an `element`. If the element is `gᵐ` then `m` is returned.
/// This uses a caching strategy, so O(m) work is necessary for
/// the first time, but afterwards the results are cached, making
/// this function run faster. This function is thread-safe.
pub fn discrete_log(element: &Element) -> Exponent {
    let cache = Arc::clone(&DLOG_CACHE);
    let mut cache = cache.lock().unwrap();
    let (ref mut max_elem, ref mut max_exp, ref mut map) = *cache;
    let g = generator();

    match map.get(element) {
        Some(exp) => Exponent::from(*exp),
        None => {
            while element != max_elem {
                *max_exp += 1;
                *max_elem = g * max_elem;
                map.insert(max_elem.clone(), *max_exp);
            }
            Exponent::from(*max_exp)
        }
    }
}

/// Tells you how many values are saved in the cache behind `discrete_log`.
pub fn discrete_log_cache_size() -> u32 {
    let cache = Arc::clone(&DLOG_CACHE);
    let mut cache = cache.lock().unwrap();
    let (_, ref mut max_exp, _) = *cache;

    *max_exp
}

lazy_static! {
    // TODO: find one of the memoizing/caching libraries that we
    // can use instead of this. Or, figure out a way to do the
    // computation in parallel.

    // TODO: write the cache out to a file so we can precompute this
    // even for really large elections.
    static ref DLOG_CACHE: Arc<Mutex<(Element, u32, HashMap<Element, u32>)>> = {
        let mut map: HashMap<Element, u32> = HashMap::new();
        map.insert(Element::one(), 0u32);
        Arc::new(Mutex::new((Element::one(), 0u32, map)))
    };
}

#[cfg(test)]
pub mod test {
    use super::*;
    use num::traits::{Pow, Zero};
    use num::BigUint;
    use proptest::prelude::*;

    pub fn discrete_log_uncached(element: &Element) -> Exponent {
        let g_inv = generator().inverse();

        let mut count = Exponent::zero();
        let mut cur = element.clone();
        while !cur.is_one() {
            cur = &cur * &g_inv;
            count = count + Exponent::one();
        }

        count
    }

    proptest! {
        #[test]
        fn test_dlog_uncached(exp in 0u32..100u32) {
            let exponent = Exponent::from(BigUint::from(exp));
            let ciphertext = generator().pow(&exponent);
            let plaintext = discrete_log_uncached(&ciphertext);
            assert_eq!(exponent, plaintext);
        }

        #[test]
        fn test_dlog(exp in 0u32..100u32) {
            let exponent = Exponent::from(BigUint::from(exp));
            let ciphertext = generator().pow(&exponent);
            let plaintext = discrete_log(&ciphertext);
            assert_eq!(exponent, plaintext);
        }

    }

    #[test]
    fn test_dlog_cache_size() {
        // Starting: might be 0, no more than 100 if the above unit tests
        // have run first.
        assert!(discrete_log_cache_size() <= 100);

        let exponent = Exponent::from(500);
        let ciphertext = generator().pow(&exponent);
        let plaintext = discrete_log(&ciphertext);
        assert_eq!(exponent, plaintext);

        let cache_size = discrete_log_cache_size();
        assert!(cache_size > 100 && cache_size <= 500);

        let exponent = Exponent::from(300);
        let ciphertext = generator().pow(&exponent);
        let plaintext = discrete_log(&ciphertext);
        assert_eq!(exponent, plaintext);

        // cache size shouldn't change this time.
        assert!(cache_size == discrete_log_cache_size());
    }
}

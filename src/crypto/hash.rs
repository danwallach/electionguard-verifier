use crate::crypto::elgamal;
use crate::crypto::group::Element;
use digest::Digest;
use num::BigUint;
use sha2::Sha256;

/// Specifies how the challenge should be computed by specifying which
/// inputs should be hashed, and in what order.
#[derive(Debug, Clone)]
pub struct Spec<'a, P>(pub &'a [Input<'a, P>]);

/// A single input to the hash function. It is parametrized over [P],
/// the type of information that can be provided by the proof, because
/// different proofs contain different pieces of information.
#[derive(Debug, Copy, Clone)]
pub enum Input<'a, P> {
    /// An input provided by the creator of the specification
    External(&'a BigUint),
    /// An input provided by the proof being checked
    Proof(P),
}

impl<'a, P: 'a + Copy> Spec<'a, P> {
    pub fn exec<R, D>(self, resolver: R) -> BigUint
    where
        R: 'a + Fn(P) -> &'a BigUint,
        D: Digest,
    {
        // TODO: pretty sure there should be some padding / length between elements?
        let hash = self
            .resolve(resolver)
            .map(BigUint::to_bytes_be)
            .fold(D::new(), D::chain)
            .result();

        BigUint::from_bytes_be(hash.as_slice())
    }

    fn resolve<R>(self, resolver: R) -> impl Iterator<Item = &'a BigUint> + 'a
    where
        R: 'a + Fn(P) -> &'a BigUint,
    {
        self.0.iter().copied().map(move |i| match i {
            Input::External(x) => x,
            Input::Proof(x) => resolver(x),
        })
    }
}

pub fn hash_uints(xs: &[&BigUint]) -> BigUint {
    let inputs = xs.iter().map(|i| Input::External(i)).collect::<Vec<_>>();
    Spec::<()>(&inputs).exec::<_, Sha256>(|_| unreachable!())
}

/// Hash together a BigUint, a message, and a commitment.
pub fn hash_umc(u: &BigUint, m: &elgamal::Message, c: &elgamal::Message) -> BigUint {
    hash_uints(&[
        u,
        m.public_key.as_uint(),
        m.ciphertext.as_uint(),
        c.public_key.as_uint(),
        c.ciphertext.as_uint(),
    ])
}

/// Hash together a BigUint, a message, and two commitments.
pub fn hash_umcc(
    u: &BigUint,
    m: &elgamal::Message,
    c1: &elgamal::Message,
    c2: &elgamal::Message,
) -> BigUint {
    hash_uints(&[
        u,
        m.public_key.as_uint(),
        m.ciphertext.as_uint(),
        c1.public_key.as_uint(),
        c1.ciphertext.as_uint(),
        c2.public_key.as_uint(),
        c2.ciphertext.as_uint(),
    ])
}

/// Hash together three BigUints.
pub fn hash_uuu(u1: &BigUint, u2: &BigUint, u3: &BigUint) -> BigUint {
    hash_uints(&[u1, u2, u3])
}

/// Hash together a BigUint and two group Elements.
pub fn hash_uee(u: &BigUint, e1: &Element, e2: &Element) -> BigUint {
    hash_uints(&[u, e1.as_uint(), e2.as_uint()])
}

#[cfg(test)]
pub mod test {
    use super::*;
    use crate::crypto::elgamal::test::*;
    use crate::crypto::group::test::*;
    use num::BigUint;
    use proptest::prelude::*;
    use std::fmt::Debug;

    /// General-purpose hash tester. If the hashes are different, the values must
    /// be different. If the values are equal, the hashes must be equal.
    fn hash_compare<V: Debug + PartialEq>(h1: &BigUint, h2: &BigUint, v1: &V, v2: &V) {
        if h1 != h2 {
            assert_ne!(v1, v2);
        }

        if v1 == v2 {
            assert_eq!(h1, h2);
        }
    }

    proptest! {
        #[test]
        fn test_hash_uints(x in arb_biguint_vec(), y in arb_biguint_vec()) {
            // Make copies to satisfy the types that the hash function wants.
            // https://stackoverflow.com/questions/37797242/how-to-get-a-slice-of-references-from-a-vector-in-rust
            let xary: &[&BigUint] = &(&x).iter().collect::<Vec<_>>();
            let yary: &[&BigUint] = &(&y).iter().collect::<Vec<_>>();

            let hx = hash_uints(xary);
            let hy = hash_uints(yary);

            hash_compare(&hx, &hx, &x, &x);
            hash_compare(&hx, &hy, &x, &y);
        }

        #[test]
        fn test_hash_umc(u1 in arb_biguint(), m1 in arb_elgamal_message(), c1 in arb_elgamal_message(), u2 in arb_biguint(), m2 in arb_elgamal_message(), c2 in arb_elgamal_message()) {
            let h0 = hash_umc(&u1, &m1, &c1);
            let h1 = hash_umc(&u1, &m1, &c2);
            let h2 = hash_umc(&u2, &m1, &c1);
            let h3 = hash_umc(&u1, &m2, &c1);
            let h4 = hash_umc(&u2, &m2, &c2);

            let t0 = (&u1, &m1, &c1);
            let t1 = (&u1, &m1, &c2);
            let t2 = (&u2, &m1, &c1);
            let t3 = (&u1, &m2, &c1);
            let t4 = (&u2, &m2, &c2);

            hash_compare(&h0, &h0, &t0, &t0);
            hash_compare(&h0, &h1, &t0, &t1);
            hash_compare(&h0, &h2, &t0, &t2);
            hash_compare(&h0, &h3, &t0, &t3);
            hash_compare(&h0, &h4, &t0, &t4);
        }

        #[test]
        fn test_hash_umcc(u1 in arb_biguint(), m1 in arb_elgamal_message(), c1 in arb_elgamal_message(), cc1 in arb_elgamal_message(), u2 in arb_biguint(), m2 in arb_elgamal_message(), c2 in arb_elgamal_message(), cc2 in arb_elgamal_message()) {
            let h0 = hash_umcc(&u1, &m1, &c1, &cc1);
            let h1 = hash_umcc(&u1, &m1, &c2, &cc1);
            let h2 = hash_umcc(&u2, &m1, &c1, &cc1);
            let h3 = hash_umcc(&u1, &m2, &c1, &cc1);
            let h4 = hash_umcc(&u1, &m1, &c1, &cc2);
            let h5 = hash_umcc(&u2, &m2, &c2, &cc2);

            let t0 = (&u1, &m1, &c1, &cc1);
            let t1 = (&u1, &m1, &c2, &cc1);
            let t2 = (&u2, &m1, &c1, &cc1);
            let t3 = (&u1, &m2, &c1, &cc1);
            let t4 = (&u1, &m1, &c1, &cc2);
            let t5 = (&u2, &m2, &c2, &cc2);

            hash_compare(&h0, &h0, &t0, &t0);
            hash_compare(&h0, &h1, &t0, &t1);
            hash_compare(&h0, &h2, &t0, &t2);
            hash_compare(&h0, &h3, &t0, &t3);
            hash_compare(&h0, &h4, &t0, &t4);
            hash_compare(&h0, &h5, &t0, &t5);
        }

        #[test]
        fn test_hash_uuu(u1 in arb_biguint(), u2 in arb_biguint(), u3 in arb_biguint(), v1 in arb_biguint(), v2 in arb_biguint(), v3 in arb_biguint()) {
            let h0 = hash_uuu(&u1, &u2, &u3);
            let h1 = hash_uuu(&v1, &u2, &u3);
            let h2 = hash_uuu(&u1, &v2, &u3);
            let h3 = hash_uuu(&u1, &u2, &v3);
            let h4 = hash_uuu(&v1, &v2, &v3);

            let t0 = (&u1, &u2, &u3);
            let t1 = (&v1, &u2, &u3);
            let t2 = (&u1, &v2, &u3);
            let t3 = (&u1, &u2, &v3);
            let t4 = (&v1, &v2, &v3);

            hash_compare(&h0, &h0, &t0, &t0);
            hash_compare(&h0, &h1, &t0, &t1);
            hash_compare(&h0, &h2, &t0, &t2);
            hash_compare(&h0, &h3, &t0, &t3);
            hash_compare(&h0, &h4, &t0, &t4);
        }

        #[test]
        fn test_hash_uee(u1 in arb_biguint(), e1 in arb_element(), ee1 in arb_element(), u2 in arb_biguint(), e2 in arb_element(), ee2 in arb_element()) {
            let h0 = hash_uee(&u1, &e1, &ee1);
            let h1 = hash_uee(&u2, &e1, &ee1);
            let h2 = hash_uee(&u1, &e2, &ee1);
            let h3 = hash_uee(&u1, &e1, &ee2);
            let h4 = hash_uee(&u2, &e2, &ee2);

            let t0 = (&u1, &e1, &ee1);
            let t1 = (&u2, &e1, &ee1);
            let t2 = (&u1, &e2, &ee1);
            let t3 = (&u1, &e1, &ee2);
            let t4 = (&u2, &e2, &ee2);

            hash_compare(&h0, &h0, &t0, &t0);
            hash_compare(&h0, &h1, &t0, &t1);
            hash_compare(&h0, &h2, &t0, &t2);
            hash_compare(&h0, &h3, &t0, &t3);
            hash_compare(&h0, &h4, &t0, &t4);
        }
    }
}

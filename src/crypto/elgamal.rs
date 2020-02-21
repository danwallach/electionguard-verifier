use crate::crypto::group::{generator, Element, Exponent};
use num::traits::Pow;
use num::BigUint;
use serde::{Deserialize, Serialize};

/// An ElGamal message `(c, d)` encoding zero. This is useful because
/// you can only combine two ciphertexts if they both encode zero, as
/// in the equation `hᵘ = hᵗ⁺ᶜʳ = hᵗ (hʳ)ᶜ = d bᶜ`. This acts as a
/// commitment to the one-time private key `t` used in this proof.
///
/// A message that has been encrypted using exponential ElGamal.
///
/// The encrypted message of the selection (the one or zero).
#[derive(PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct Message {
    /// The one-time public key `a = gʳ`, where `r` is the randomly
    /// generated one-time public key.
    pub public_key: Element,

    /// The encoding `b = gᵐ hʳ`, where `m` is the cleartext and `h`
    /// is the recipient public key being used for encryption.
    pub ciphertext: Element,
}

impl Message {
    /// Encrypt `m` using `public_key` and a `one_time_secret` key.
    pub fn encrypt(public_key: &Element, m: &BigUint, one_time_secret: &Exponent) -> Message {
        let g = generator();
        let h = public_key;
        let r = one_time_secret;
        let m: Exponent = m.clone().into();
        let m = &m;

        // Let k = g^r. You can think of this as your one-time public key.
        let k = g.pow(r);

        // Normal Elgamal encryption: "Publish (k, m ⋅ h^r). I'll refer to the first element of the
        // pair as the one-time public key, the second element as the ciphertext, and the whole
        // pair as the encrypted message."
        // But we are instead using exponential Elgamal, which replaces `m` with `g^m`: "we make
        // one small tweak: instead of forming the ciphertext as m ⋅ g^(rs) where g^(rs) is that
        // shared secret, we use g^m ⋅ g^(rs)."
        Message {
            public_key: k,
            ciphertext: g.pow(m) * h.pow(r),
        }
    }

    // Decrypts a Message, yields `gᵐ` for plaintext `m`, requires knowing the appropriate
    // `private_key`. No error checking!
    pub fn decrypt(&self, private_key: &Exponent) -> Element {
        // The message gives us g^r (self.public_key) and g^m * h^r (self.ciphertext)
        // where h = g ^ private_key. So, we can compute (g^r)^a = g^ra, then divide
        // and we'll get back g^m, which isn't exactly the plaintext, but it's no
        // longer encrypted.

        let g_ra = &self.public_key.pow(private_key);
        &self.ciphertext / g_ra
    }

    /// Homomorphic addition of encrypted messages.  Converts the encryptions of `a` and `b` into
    /// the encryption of `a + b`.
    pub fn h_add(&self, other: &Message) -> Message {
        Message {
            public_key: &self.public_key * &other.public_key,
            ciphertext: &self.ciphertext * &other.ciphertext,
        }
    }

    /// Homomorphic negation of encrypted messages.  Converts the encryption of `a` into the
    /// encryption of `-a`.
    pub fn h_neg(&self) -> Message {
        Message {
            public_key: self.public_key.inverse(),
            ciphertext: self.ciphertext.inverse(),
        }
    }

    /// Homomorphic subtraction of encrypted messages.  Converts the encryptions of `a` and `b`
    /// into the encryption of `a - b`.
    pub fn h_sub(&self, other: &Message) -> Message {
        self.h_add(&other.h_neg())
    }
}

#[cfg(test)]
pub mod test {
    use super::*;
    use crate::crypto::group::test::*;
    use num::traits::Zero;
    use num::BigUint;
    use proptest::prelude::*;

    prop_compose! {
        pub fn arb_elgamal_keypair()(private_key in arb_exponent()
                .prop_filter("non-zero private key needed so ElGamal isn't a no-op",
                    |k| !k.is_zero())) -> (Exponent, Element) {
            let public_key = generator().pow(&private_key);
            (private_key, public_key)
        }
    }

    proptest! {
        #[test]
        fn test_elgamal_decryption(
            keypair in arb_elgamal_keypair(),
            m in arb_exponent(),
            r in arb_exponent()) {

            let encryption = Message::encrypt(&(keypair.1), m.as_uint(), &r);
            let decryption = encryption.decrypt(&(keypair.0));

            assert_eq!(generator().pow(&m), decryption);
        }

        #[test]
        fn test_elgamal_homomorphism(
            keypair in arb_elgamal_keypair(),
            m1 in arb_exponent(),
            m2 in arb_exponent(),
            r1 in arb_exponent(),
            r2 in arb_exponent()) {

            let encryption1 = Message::encrypt(&(keypair.1), m1.as_uint(), &r1);
            let encryption2 = Message::encrypt(&(keypair.1), m2.as_uint(), &r2);

            let encrypted_sum = encryption1.h_add(&encryption2);
            let decryption = encrypted_sum.decrypt(&(keypair.0));
            let m_sum = m1 + m2;

            assert_eq!(generator().pow(&m_sum), decryption);
        }

        #[test]
        fn test_elgamal_inversion(
            keypair in arb_elgamal_keypair(),
            m1 in arb_exponent(),
            m2 in arb_exponent(),
            r1 in arb_exponent(),
            r2 in arb_exponent()) {

            let encryption1 = Message::encrypt(&(keypair.1), m1.as_uint(), &r1);
            let encryption2 = Message::encrypt(&(keypair.1), m2.as_uint(), &r2);

            let encrypted_sum = encryption1.h_add(&encryption2).h_sub(&encryption2);
            let decryption = encrypted_sum.decrypt(&(keypair.0));

            assert_eq!(generator().pow(&m1), decryption);
        }

        #[test]
        fn test_elgamal_reencryption(
            keypair in arb_elgamal_keypair(),
            m in arb_exponent(),
            r1 in arb_exponent(),
            r2 in arb_exponent()
                .prop_filter("non-zero reencryption needed to change input", |r| !r.is_zero())) {

            let encryption = Message::encrypt(&(keypair.1), m.as_uint(), &r1);
            let encrypted_zero = Message::encrypt(&(keypair.1), &BigUint::from(0_u32), &r2);
            let reencryption = encryption.h_add(&encrypted_zero);
            let decryption = reencryption.decrypt(&(keypair.0));

            assert_eq!(generator().pow(&m), decryption);
            assert!(reencryption.ciphertext != encryption.ciphertext);
        }
    }

    pub fn private_key() -> Exponent {
        BigUint::from(2546_u32).into()
    }

    pub fn public_key() -> Element {
        generator().pow(&private_key())
    }

    pub fn extended_base_hash() -> BigUint {
        31268_u32.into()
    }
}

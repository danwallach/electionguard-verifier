use crate::crypto::group::{generator, prime_minus_one, Element, Exponent};
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
        // If m >= p-1, then that's bad because it will wrap around and
        // look as if m=0. We could have encrypt() return Option<Message>
        // and push the problem on to our caller, but really we should
        // just never see a message so big, thus we're going to panic
        // and crash, instead.
        if m >= prime_minus_one() {
            panic!("Message out of range: {}", m)
        }

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

    /// Decrypts a Message, yields `gᵐ` for plaintext `m`, requires knowing the appropriate
    /// `secret_key`. If the secret_key is not correct, the results will be an
    /// unknown element. You need your own error checking. Similarly, you'll need your
    /// own logic to map from `gᵐ` back to `m` (e.g., a pre-computed lookup table).
    pub fn decrypt(&self, secret_key: &Exponent) -> Element {
        // The message gives us g^r (self.public_key) and g^m * h^r (self.ciphertext)
        // where h = g ^ secret_key. So, we can compute (g^r)^a = g^ra, which we can
        // use to get back g^m, which isn't the plaintext, but it's no longer encrypted.

        let g_ra = &self.public_key.pow(secret_key);
        &self.ciphertext / g_ra
    }

    /// Decrypts a Message, yields `gᵐ` for plaintext `m`, but using the public-key
    /// and one-time-secret rather than the secret_key. If the arguments to this
    /// function are incorrect, the results will be an unknown element. You need
    ///  your own error checking. Similarly, you'll need your own logic to map from
    /// `gᵐ` back to `m` (e.g., a pre-computed lookup table).
    pub fn decrypt_with_one_time_secret(
        &self,
        public_key: &Element,
        one_time_secret: &Exponent,
    ) -> Element {
        // The message gives us g^r (self.public_key) and g^m * h^r (self.ciphertext)
        // where h = g ^ secret_key. With the public key (g^a, not to be confused
        // with self.public_key), we can raise that to the rth power, yielding g^ra.

        // This decryption function is something that might be used when a voting
        // machine is being challenged to prove that it created an encryption
        // correctly. It also demonstrates the importance of throwing away the
        // random numbers after computing a ciphertext.

        let g_ra = &public_key.pow(one_time_secret);
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
    use num::BigUint;
    use proptest::prelude::*;

    prop_compose! {
        /// Returns a tuple containing an arbitrary ElGamal keypair (secret, public).
         pub fn arb_elgamal_keypair()(secret_key in arb_nonzero_exponent()) -> (Exponent, Element) {
            let public_key = generator().pow(&secret_key);
            (secret_key, public_key)
        }
    }

    prop_compose! {
        /// Returns an arbitrary ElGamal message. No two messages will be encrypted
        /// with the same keys, so only really useful if you don't care about decryption.
        pub fn arb_elgamal_message()(keypair in arb_elgamal_keypair(), m in arb_exponent(), r in arb_exponent()) -> Message {
            Message::encrypt(&(keypair.1), m.as_uint(), &r)
        }
    }

    proptest! {
        #[test]
        #[should_panic]
        fn test_elgamal_encryption_out_of_range(
            keypair in arb_elgamal_keypair(),
            m in arb_exponent(),
            r in arb_exponent()
        ) {
            let huge_number = prime_minus_one() + m.as_uint();
            let (secret_key, public_key) = keypair;

            // this line should panic
            let encryption = Message::encrypt(&public_key, &huge_number, &r);

            // we shouldn't get here
            let _decryption = encryption.decrypt(&secret_key);
            assert!(false);
        }

        #[test]
        fn test_elgamal_normal_decryption(
            keypair in arb_elgamal_keypair(),
            m in arb_exponent(),
            r in arb_exponent()) {

            let (secret_key, public_key) = keypair;
            let encryption = Message::encrypt(&public_key, m.as_uint(), &r);
            let decryption = encryption.decrypt(&secret_key);

            assert_eq!(generator().pow(&m), decryption);
        }

        #[test]
        fn test_elgamal_decryption_with_randomness(
            keypair in arb_elgamal_keypair(),
            m in arb_exponent(),
            r in arb_exponent()) {

            let public_key = keypair.1;
            let encryption = Message::encrypt(&public_key, m.as_uint(), &r);
            let decryption = encryption.decrypt_with_one_time_secret(&public_key, &r);

            assert_eq!(generator().pow(&m), decryption);
        }


        #[test]
        fn test_elgamal_homomorphism(
            keypair in arb_elgamal_keypair(),
            m1 in arb_exponent(),
            m2 in arb_exponent(),
            r1 in arb_exponent(),
            r2 in arb_exponent()) {

            let (secret_key, public_key) = keypair;
            let encryption1 = Message::encrypt(&public_key, m1.as_uint(), &r1);
            let encryption2 = Message::encrypt(&public_key, m2.as_uint(), &r2);

            let encrypted_sum = encryption1.h_add(&encryption2);
            let decryption = encrypted_sum.decrypt(&secret_key);
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

            let (secret_key, public_key) = keypair;
            let encryption1 = Message::encrypt(&public_key, m1.as_uint(), &r1);
            let encryption2 = Message::encrypt(&public_key, m2.as_uint(), &r2);

            let encrypted_sum = encryption1.h_add(&encryption2).h_sub(&encryption2);
            let decryption = encrypted_sum.decrypt(&secret_key);

            assert_eq!(generator().pow(&m1), decryption);
        }

        #[test]
        fn test_elgamal_reencryption(
            keypair in arb_elgamal_keypair(),
            m in arb_exponent(),
            r1 in arb_nonzero_exponent(),
            r2 in arb_nonzero_exponent()) {

            let (secret_key, public_key) = keypair;
            let encryption = Message::encrypt(&public_key, m.as_uint(), &r1);
            let encrypted_zero = Message::encrypt(&public_key, &BigUint::from(0_u32), &r2);
            let reencryption = encryption.h_add(&encrypted_zero);
            let decryption = reencryption.decrypt(&secret_key);

            assert_eq!(generator().pow(&m), decryption);
            assert!(reencryption.ciphertext != encryption.ciphertext);
        }
    }
}

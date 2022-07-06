/// elgamal mod
/// this is a utils for elgamal security algorithm
/// use for generating public_key
/// ```rust
/// # use elgamal_trex::elgamal;
/// # use rug::Integer;
/// # use rug::rand::RandState;
/// let big_num = Integer::from(2929);
/// let mut rand = RandState::new_mersenne_twister();
/// let seed = Integer::from_str_radix("833050814021254693158343911234888353695402778102174580258852673738983005", 10).unwrap();
/// rand.seed(&seed);
/// let pubkey = elgamal::generate_pub_key(&mut rand, 20, Integer::from(1));
/// assert_eq!(pubkey.g.to_u32().unwrap(), 913616, "Public key g part {} is not correct!", &pubkey.g);
/// assert_eq!(pubkey.h.to_u32().unwrap(), 55251, "Public key h part {} is not correct!", &pubkey.g);
/// assert_eq!(pubkey.p.to_u32().unwrap(), 1012679, "Public key p part {} is not correct!", &pubkey.g);
/// ```
pub mod elgamal;
pub use crate::elgamal::*;
pub mod utils;
use crate::elgamal::PublicKey;
use rug::{rand::RandState, Integer};
use std::fmt;

impl fmt::Display for PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "({}, {}, {})", self.p, self.g, self.h)
    }
}

/// trait for printing some struct
pub trait KeyFormat {
    fn from_hex_str(key_str: &str) -> Self;
}

/// Rust generator is not yet stable, use self-defined generator trait.
pub trait KeyGenerator {
    const CONFIDENCE: u32;
    /// Use current data slices as seed and generate a new public key.
    fn yield_pubkey(&self, rand: &mut RandState, bit_length: u32) -> Self;
}

impl KeyFormat for PublicKey {
    ///Generate a public key from string.
    fn from_hex_str(key_str: &str) -> PublicKey {
        let keys: Vec<_> = key_str.split(", ").collect();
        println!("keys~~~~~~~~~~~~~~~~{:?}", keys);
        if keys.len() < 3 {
            println!("The input string is not valid")
        }
        let p = Integer::from_str_radix(keys[0].replace("0x", "").as_str(), 16)
            .ok()
            .unwrap_or(Integer::from(0));
        let g = Integer::from_str_radix(keys[1].replace("0x", "").as_str(), 16)
            .ok()
            .unwrap_or(Integer::from(0));
        let h = Integer::from_str_radix(keys[2].replace("0x", "").as_str(), 16)
            .ok()
            .unwrap_or(Integer::from(0));
        let bit_length = keys[3].parse::<u32>().unwrap();
        let pubkey = PublicKey {
            p,
            g,
            h,
            bit_length,
        };
        pubkey
    }
}

impl KeyGenerator for RawPublicKey {
    const CONFIDENCE: u32 = 16;
    fn yield_pubkey(&self, rand: &mut RandState, bit_length: u32) -> Self {
        let pubkey_int = PublicKey::from_raw(self.clone());
        let seed = pubkey_int.yield_seed();
        let new_key = generate_pub_key(rand, bit_length, seed);
        new_key.to_raw()
    }
}

impl KeyGenerator for PublicKey {
    const CONFIDENCE: u32 = 16;
    fn yield_pubkey(&self, rand: &mut RandState, bit_length: u32) -> Self {
        let seed = self.clone().yield_seed();
        generate_pub_key(rand, bit_length, seed)
    }
}

#[cfg(test)]
mod tests {
    use crate::elgamal::*;
    use crate::elgamal::{Encryption, PrivateKey, PublicKey};
    use crate::KeyGenerator;
    use rug::rand::RandState;
    use rug::Integer;
    use az::OverflowingAs;

    fn brute_search(pubkey: &PublicKey) -> Option<PrivateKey> {
        let range = &pubkey.p.to_u32()?;
        for i in 1..*range {
            let index = Integer::from(i);
            let g_pow_mod = pubkey.g.pow_mod_ref(&index, &pubkey.p).unwrap();
            let mod_exp = Integer::from(g_pow_mod);
            if &pubkey.h == &mod_exp {
                return Some(PrivateKey {
                    p: pubkey.p.clone(),
                    g: pubkey.g.clone(),
                    x: index,
                    bit_length: pubkey.bit_length,
                });
            }
        }
        None
    }

    #[test]
    fn test_encryption() {
        let mut rand = RandState::new_mersenne_twister();
        let seed = Integer::from(2929);
        let pubkey = generate_pub_key(&mut rand, 16, seed);
        if let Some(private) = brute_search(&pubkey) {
            let msg = "Private key is found and here is a test of the elgamal crypto system.";
            let cipher = msg.to_string().encrypt(&mut rand, &pubkey);
            let plain = cipher.decrypt(&private).unwrap();
            assert_eq!(msg, plain, "Private key is not valid!");
        }
    }

    #[test]
    fn test_yield_pubkey() {
        let mut rand = RandState::new_mersenne_twister();
        let seed = Integer::from(3);
        // rand.seed(&seed);
        let pubkey = generate_pub_key(&mut rand, 255, seed);
        let mut new_pubkey = pubkey.yield_pubkey(&mut rand, 255);
        for _ in 0..10 {
            new_pubkey = new_pubkey.yield_pubkey(&mut rand, 255);
        }
    }

    #[test]
    fn test_seed_overflow() {
        let mut rand = RandState::new_mersenne_twister();
        let seed = Integer::from(2929);
        let pubkey = generate_pub_key(&mut rand, 16, seed);
        let new_seed = pubkey.yield_seed();
        let (short_seed, overflow_flag) = new_seed.clone().overflowing_as::<u16>();
        assert_ne!(overflow_flag, true, "The yielded seed is overflowing the bit length.");
        let long_seed = Integer::from(short_seed);
        assert_eq!(long_seed, new_seed, "The seed is not correct!")
    }
}

/// elgamal mod
/// this is a utils for elgamal security algorithm
/// use for generating public_key
/// ```rust
/// # use elgamal_capsule::elgamal;
/// # use rug::Integer;
/// # use rug::rand::RandState;
/// let big_num = Integer::from(2929);
/// let mut rand = RandState::new_mersenne_twister();
/// let seed = Integer::from_str_radix("833050814021254693158343911234888353695402778102174580258852673738983005", 10).unwrap();
/// rand.seed(&seed);
/// let pubkey = elgamal::generate_pub_key(&mut rand, 20);
/// assert_eq!(pubkey.g.to_u32().unwrap(), 96660, "Public key g part {} is not correct!", &pubkey.g);
/// assert_eq!(pubkey.h.to_u32().unwrap(), 25155, "Public key h part {} is not correct!", &pubkey.g);
/// assert_eq!(pubkey.p.to_u32().unwrap(), 1587683, "Public key p part {} is not correct!", &pubkey.g);
/// ```
mod elgamal;
pub use crate::elgamal::*;
pub mod generic;
pub mod utils;
use crate::generic::{PublicKey};
use std::fmt;
use rug::{rand::RandState, Integer};

impl fmt::Display for PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "({}, {}, {})", self.p, self.g, self.h)
    }
}

/// trait for printing some struct
pub trait KeyFormat {
    fn from_hex_str(key_str: &str) -> Self;
    fn print_parameter(&self);
}

/// Rust generator is not yet stable, use self-defined generator trait.
pub trait KeyGenerator {
    const CONFIDENCE: u32;
    /// Use current data slices as seed and generate a new public key.
    fn yield_pubkey(&self, bit_length: u32) -> Self;
}

impl KeyFormat for PublicKey {
    ///Generate a public key from string.
    fn from_hex_str(key_str: &str) -> PublicKey {
        let keys: Vec<_> = key_str.split(", ").collect();
        println!("keys~~~~~~~~~~~~~~~~{:?}", keys);
        if keys.len() < 3 {
            println!("The input string is not valid")
        }
        let p = Integer::from_str_radix(keys[0].replace("0x", "").as_str(), 16).ok().unwrap_or(Integer::from(0));
        let g = Integer::from_str_radix(keys[1].replace("0x", "").as_str(), 16).ok().unwrap_or(Integer::from(0));
        let h = Integer::from_str_radix(keys[2].replace("0x", "").as_str(), 16).ok().unwrap_or(Integer::from(0));
        let bit_length = keys[3].parse::<u32>().unwrap();
        let pubkey = PublicKey {
            p,
            g,
            h,
            bit_length,
        };
        pubkey
    }
    ///print public_key's p、g、h
    fn print_parameter(&self) {
        println!("_____________");
        println!("p:{}", self.p);
        println!("g:{}", self.g);
        println!("h:{}", self.h);
    }
}

impl KeyGenerator for RawPublicKey {
    const CONFIDENCE: u32 = 16;
    fn yield_pubkey(&self, bit_length: u32) -> Self {
        let pubkey_int = PublicKey::from_raw(self.clone());
        let seed = pubkey_int.yield_seed();
        let mut rand = RandState::new_mersenne_twister();
        rand.seed(&seed);
        let new_key = generate_pub_key(&mut rand, bit_length);
        new_key.to_raw()
    }
}

impl KeyGenerator for PublicKey {
    const CONFIDENCE: u32 = 16;
    fn yield_pubkey(&self, bit_length: u32) -> Self {
        let seed = self.clone().yield_seed();
        let mut rand = RandState::new_mersenne_twister();
        rand.seed(&seed);
        generate_pub_key(&mut rand, bit_length)
    }
}

#[cfg(test)]
mod tests {
    use crate::elgamal::*;
    use rug::rand::RandState;
    use rug::Integer;
    use crate::generic::{PublicKey,PrivateKey,Encryption};
    use crate::KeyGenerator;

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
        rand.seed(&seed);
        let pubkey = generate_pub_key(&mut rand, 16);
        if let Some(private) = brute_search(&pubkey) {
            let msg = "Private key is found and here is a test of the elgamal crypto system.";
            let cipher = msg.to_string().encrypt(&mut rand, &pubkey);
            let plain = cipher.decrypt(&private).unwrap();
            assert_eq!(msg, plain, "Private key is not valid!");
        }
    }

    #[test]
    fn test_yeild_pubkey(){
        let mut rand = RandState::new_mersenne_twister();
        let seed = Integer::from(3);
        rand.seed(&seed);
        let pubkey = generate_pub_key(&mut rand, 256);
        let new_pubkey = pubkey.yield_pubkey(256);
        println!("difficulty:256 pubkey:{:?}",new_pubkey.to_raw());
    }
}

use crate::utils;
use encoding::all::UTF_16LE;
use encoding::{DecoderTrap, EncoderTrap, Encoding};
use rug::ops::Pow;
use rug::{rand::RandState, Complete, Integer};
use codec::{Decode, Encode};

use sp_core::U256;
use crate::utils::{bigint_u256, u256_bigint};

const STR_RADIX: i32 = 10;
const SEARCH_LIMIT: u32 = 100;

///Init public key structure for elgamal encryption.
#[derive(Debug, Clone)]
pub struct PublicKey {
    pub p: Integer,
    pub g: Integer,
    pub h: Integer,
    pub bit_length: u32,
}

///init private key structure for elgamal encryption.
#[derive(Debug, Clone)]
pub struct PrivateKey {
    pub p: Integer,
    pub g: Integer,
    pub x: Integer,
    pub bit_length: u32,
}

/// A trait to use a RNG and elgamal key to encrypt plaintext to UTF_16LE string.
pub trait Encryption<I> {
    fn encrypt(&self,rand: &mut RandState, key: &PublicKey) -> String;
    fn decrypt(&self,key: &PrivateKey) -> Option<String>;
}

/// Generate a seed data slice from a key data.
pub trait Seed {
    fn yield_seed(self) -> Integer;
}

impl Seed for PublicKey{
    fn yield_seed(self) -> Integer {
        let sum = self.p + self.g + self.h;
        sum.to_owned()
    }
}

/// The raw public key type use bytes string.
#[derive(Clone, PartialEq, Eq, Encode, Decode, Debug)]
pub struct RawPublicKey {
    pub p: U256,
    pub g: U256,
    pub h: U256,
    pub bit_length: u32,
}

/// To and from raw bytes of a public key. Use little endian byte order by default.
pub trait RawKey {
    fn to_raw(self) -> RawPublicKey;
    fn from_raw(raw_key: RawPublicKey) -> Self;
}

impl RawKey for PublicKey {
    fn to_raw(self) -> RawPublicKey {
        RawPublicKey {
            p: bigint_u256(&self.p),
            g: bigint_u256(&self.g),
            h: bigint_u256(&self.h),
            bit_length: self.bit_length,
        }
    }

    fn from_raw(raw_key: RawPublicKey) -> Self {
        PublicKey{
            p:u256_bigint(&raw_key.p),
            g:u256_bigint(&raw_key.g),
            h:u256_bigint(&raw_key.h),
            bit_length: raw_key.bit_length,
        }
    }
}


///generate public_key with seed、bit_length、i_confidence
///Generates public key K1 (p, g, h) and private key K2 (p, g, x).
pub fn generate_pub_key(rand: &mut RandState, bit_length: u32, seed:Integer) -> PublicKey {
    rand.seed(&seed);
    let p = utils::random_prime_bigint(rand, bit_length.clone());
    // rand.seed(&seed);
    let g = match utils::find_primitive_root_bigint(rand, &p, SEARCH_LIMIT) {
        Some(value) => value,
        None => {
            Integer::from(0)
        }
    };
    // rand.seed(&seed);
    let h = utils::find_h_bigint(rand, &g);
    let pubkey: PublicKey = PublicKey {
        p,
        g,
        h,
        bit_length,
    };
    pubkey
}


impl Encryption<Integer> for String {
    ///Encrypts a string using the public key k.
    fn encrypt(&self,rand: &mut RandState, key: &PublicKey) -> String {
        let z = encode_utf16(self, key.bit_length.clone());
        // cipher_pairs list will hold pairs (c, d) corresponding to each integer in z
        let mut cipher_pairs = Vec::new();
        // i is an integer in z
        for i_code in z {
            // pick random y from (0, p-1) inclusive
            let y = utils::gen_bigint_range(rand, &Integer::ZERO, &key.p);
            // c = g^y mod p
            let c = Integer::from(key.g.pow_mod_ref(&y, &key.p).unwrap());
            // d = ih^y mod p
            let hy = Integer::from(key.h.pow_mod_ref(&y, &key.p).unwrap());
            let prod = Integer::from(&i_code * &hy);
            let d = prod.div_rem_euc_ref(&key.p).complete().1;
            // add the pair to the cipher pairs list
            let mut arr: Vec<Integer> = Vec::new();
            arr.push(c);
            arr.push(d);
            cipher_pairs.push(arr);
        }
        let mut encrypted_str = "".to_string();
        for pair in cipher_pairs {
            let pair_one = pair[0].to_string_radix(STR_RADIX).to_string();
            let pair_two = pair[1].to_string_radix(STR_RADIX).to_string();
            let space = " ".to_string();

            encrypted_str += &pair_one;
            encrypted_str += &space;
            encrypted_str += &pair_two;
            encrypted_str += &space;
        }
        encrypted_str
    }

    ///Performs decryption on the cipher pairs found in Cipher using
    ///private key K2 and writes the decrypted values to file Plaintext.
    fn decrypt(&self,key: &PrivateKey) -> Option<String> {
        // check if the last char is space
        let mut cipher_chars = self.chars();
        if let Some(last) = cipher_chars.clone().last() {
            if last.is_whitespace() {
                // if the last char is space, removed it from the string.
                cipher_chars.next_back();
            }
        } else {
            // if the cipher string is empty, return None.
            return None;
        }
        let reduced_str = cipher_chars.as_str();
        let ciphers = reduced_str.split(" ").collect::<Vec<&str>>();
        let count = ciphers.len();
        if count % 2 != 0 {
            return None;
        }
        let mut plain_text = Vec::new();
        for cd in ciphers.chunks(2) {
            // c = first number in pair
            let c = cd[0];
            let c_int = Integer::from_str_radix(c, STR_RADIX).unwrap();
            // d = second number in pair
            let d = cd[1];
            let d_int = Integer::from_str_radix(d, STR_RADIX).unwrap();
            // s = c^x mod p
            let s = c_int.pow_mod(&key.x, &key.p).unwrap();
            // plaintext integer = ds^-1 mod p
            let p_2 = Integer::from(&key.p - 2);
            let mod_exp_s = s.pow_mod(&p_2, &key.p).unwrap();
            let d_by_mod = Integer::from(d_int * mod_exp_s);
            let plain_i = Integer::from(d_by_mod.div_rem_euc_ref(&key.p).complete().1);
            // add plain to list of plaintext integers
            plain_text.push(plain_i);
            // count the length of the cipher strings
        }
        Some(decode_utf16(&plain_text, key.bit_length.clone()))
    }
}

///Encodes bytes to integers mod p.
///         Example
///         if n = 24, k = n / 8 = 3
///         z[0] = (summation from i = 0 to i = k)m[i]*(2^(8*i))
///         where m[i] is the ith message byte
pub fn encode_utf16(s_plaintext: &str, bit_length: u32) -> Vec<Integer> {
    let mut byte_array: Vec<u8> = UTF_16LE.encode(s_plaintext, EncoderTrap::Strict).unwrap();
    byte_array.insert(0, 254);
    byte_array.insert(0, 255);

    // z is the array of integers mod p
    let mut z: Vec<Integer> = Vec::new();
    // each encoded integer will be a linear combination of k message bytes
    // k must be the number of bits in the prime divided by 8 because each
    // message byte is 8 bits long
    let k: isize = (bit_length / 8) as isize;
    // j marks the jth encoded integer
    // j will start at 0 but make it -k because j will be incremented during first iteration
    let mut j: isize = -1 * k;
    // num is the summation of the message bytes
    // num = 0
    // i iterates through byte array
    for idx in 0..byte_array.len() {
        // if i is divisible by k, start a new encoded integer
        if idx as isize % k == 0 {
            j += k;
            // num = 0
            z.push(Integer::ZERO);
        }
        let index = (j / k) as usize;
        let base = Integer::from(2);
        let mi: u32 = (8 * (idx as isize % k)) as u32;
        // add the byte multiplied by 2 raised to a multiple of 8
        z[index] += Integer::from(byte_array[idx] as i64) * base.pow(mi);
    }
    z
}

///Decodes integers to the original message bytes.
/**
Example:
if "You" were encoded.
Letter        #ASCII
Y              89
o              111
u              117
if the encoded integer is 7696217 and k = 3
m[0] = 7696217 % 256 % 65536 / (2^(8*0)) = 89 = 'Y'
7696217 - (89 * (2^(8*0))) = 7696128
m[1] = 7696128 % 65536 / (2^(8*1)) = 111 = 'o'
7696128 - (111 * (2^(8*1))) = 7667712
m[2] = 7667712 / (2^(8*2)) = 117 = 'u'
 */
pub fn decode_utf16(encoded_ints: &Vec<Integer>, bit_length: u32) -> String {
    // bytes vector will hold the decoded original message bytes
    let mut byte_array: Vec<u8> = Vec::new();
    // each encoded integer is a linear combination of k message bytes
    // k must be the number of bits in the prime divided by 8 because each
    // message byte is 8 bits long
    let k = bit_length / 8;
    let two = Integer::from(2);
    for num in encoded_ints {
        let mut temp = num.clone();
        for i in 0..k {
            let idx_1 = i + 1;
            for j in idx_1..k {
                temp = temp.div_rem_euc(Integer::from(two.clone().pow(8 * j))).1;
            }
            let two_pow_i = two.clone().pow(8 * i);
            let letter = Integer::from(&temp / &two_pow_i).to_u8().unwrap();
            byte_array.push(letter);
            temp = Integer::from(num - (letter * two_pow_i));
        }
    }
    let raw_text = UTF_16LE.decode(&byte_array, DecoderTrap::Strict).unwrap();
    // remove the byte order mark (BOM)
    let stripped_text = raw_text.strip_prefix("\u{feff}").unwrap();
    stripped_text.to_string()
}
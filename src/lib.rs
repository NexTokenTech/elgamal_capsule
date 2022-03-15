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
pub mod elgamal {
    use crate::utils;
    use encoding::all::UTF_16LE;
    use encoding::{DecoderTrap, EncoderTrap, Encoding};
    use rug::ops::Pow;
    use rug::{rand::RandState, Complete, Integer};

    const STR_RADIX: i32 = 10;
    const SEARCH_LIMIT: u32 = 10;

    pub fn test_fn() {
        println!("test function suc");
    }

    ///Init public key structure for elgamal encryption.
    #[derive(Debug)]
    pub struct PublicKey {
        pub p: Integer,
        pub g: Integer,
        pub h: Integer,
        pub bit_length: u32,
    }

    ///init private key structure for elgamal encryption.
    #[derive(Debug)]
    pub struct PrivateKey {
        pub p: Integer,
        pub g: Integer,
        pub x: Integer,
        pub bit_length: u32,
    }

    impl PublicKey {
        ///print public_key's p、g、h
        pub fn print_parameter(&self) {
            println!("_____________");
            println!("p:{}", self.p);
            println!("g:{}", self.g);
            println!("h:{}", self.h);
        }
        ///Generate a public key from string.
        pub fn from_hex_str(key_str: &str) -> Option<PublicKey> {
            let keys: Vec<_> = key_str.split(", ").collect();
            println!("keys~~~~~~~~~~~~~~~~{:?}", keys);
            if keys.len() < 3 {
                println!("The input string is not valid")
            }
            let p = Integer::from_str_radix(keys[0].replace("0x", "").as_str(), 16).ok()?;
            let g = Integer::from_str_radix(keys[1].replace("0x", "").as_str(), 16).ok()?;
            let h = Integer::from_str_radix(keys[2].replace("0x", "").as_str(), 16).ok()?;
            let bit_length = keys[3].parse::<u32>().unwrap();
            let pubkey = PublicKey {
                p,
                g,
                h,
                bit_length,
            };
            Some(pubkey)
        }
    }

    ///generate public_key with seed、bit_length、i_confidence
    ///Generates public key K1 (p, g, h) and private key K2 (p, g, x).
    pub fn generate_pub_key(rand: &mut RandState, bit_length: u32) -> PublicKey {
        let p = utils::random_prime_bigint(rand, bit_length.clone());
        let g = utils::find_primitive_root_bigint(rand, &p, SEARCH_LIMIT).unwrap();
        let h = utils::find_h_bigint(rand, &g);
        let pubkey: PublicKey = PublicKey {
            p,
            g,
            h,
            bit_length,
        };
        pubkey
    }

    ///Encrypts a string using the public key k.
    pub fn encrypt(rand: &mut RandState, key: &PublicKey, s_plaintext: &str) -> String {
        let z = encode_utf16(s_plaintext, key.bit_length.clone());
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
    pub fn decrypt(key: &PrivateKey, cipher_str: &str) -> Option<String> {
        // check if the last char is space
        let mut cipher_chars = cipher_str.chars();
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
}

///elgamal_utils mod
/// use for supporting elgamal public_key generating
/// generate p: a big prime
/// generate g: a prime root
/// generate h: a random from seed
pub mod utils {
    use rug::{rand::RandState, Complete, Integer};
    use rug::integer::IsPrime;

    pub fn gen_bigint_range(rand: &mut RandState, start: &Integer, stop: &Integer) -> Integer {
        let range = Integer::from(stop - start);
        let below = range.random_below(rand);
        start + below
    }

    ///Find a SAFE prime number p for elgamal public key.
    #[allow(unused)]
    pub fn random_prime_bigint(rand: &mut RandState, bit_length: u32) -> Integer {
        // generate a random integer within bit length.
        let mut prime_i = Integer::from(Integer::random_bits(bit_length, rand));
        // find a prime number next to above random integer.
        let one = Integer::from(1);
        let two = Integer::from(2);
        loop {
            prime_i = prime_i.next_prime();
            let prime_j = Integer::from(&prime_i * &two + &one);
            let res = prime_j.is_probably_prime(16);
            if res == IsPrime::Yes || res == IsPrime::Probably {
                return prime_j;
            }
        }
    }

    ///Finds a primitive root for prime p.
    ///         This function was implemented from the algorithm described here:
    ///         http://modular.math.washington.edu/edu/2007/spring/ent/ent-html/node31.html
    ///
    /// # Arguments
    /// * `rand` - MT19937 RNG
    /// * `p` - A large prime number.
    /// * `limit` - A limit number of trails to find the primitive root.
    /// the prime divisors of p-1 are 2 and (p-1)/2 because
    /// p = 2x + 1 where x is a prime
    pub fn find_primitive_root_bigint(
        rand: &mut RandState,
        p: &Integer,
        limit: u32,
    ) -> Option<Integer> {
        let one = Integer::from(1);
        let two = Integer::from(2);
        if p == &two {
            return Some(one);
        }
        let p1 = two.clone();
        let p2 = Integer::from((p - &one).complete() / p1);
        let p3 = Integer::from((p - &one).complete() / &p2);
        let mut g;
        let mut count = 0;
        //test random g's until one is found that is a primitive root mod p
        loop {
            let range_num_low = two.clone();
            let range_num_high = Integer::from(p - &one);
            g = gen_bigint_range(rand, &range_num_low, &range_num_high);
            // g is a primitive root if for all prime factors of p-1, p[i]
            // g^((p-1)/p[i]) (mod p) is not congruent to 1
            let gp2 = Integer::from(g.pow_mod_ref(&p2, p).unwrap());
            if &gp2 != &one {
                let gp3 = Integer::from(g.pow_mod_ref(&p3, p).unwrap());
                if &gp3 != &one {
                    return Some(g);
                }
            }
            if count > limit {
                return None;
            }
            count += 1;
        }
    }

    pub fn find_h_bigint(rand: &mut RandState, p: &Integer) -> Integer {
        let one = Integer::from(1);
        let range_num_high = Integer::from(p - &one);
        gen_bigint_range(rand, &one, &range_num_high)
    }
}

#[cfg(test)]
mod tests {
    use crate::elgamal::*;
    use rug::rand::RandState;
    use rug::Integer;

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
        // let result = 2 + 2;
        // assert_eq!(result, 4);
        let mut rand = RandState::new_mersenne_twister();
        let seed = Integer::from(2929);
        rand.seed(&seed);
        let pubkey = generate_pub_key(&mut rand, 64);
        if let Some(private) = brute_search(&pubkey) {
            let msg = "Private key is found and here is a test of the elgamal crypto system.";
            let cipher = encrypt(&mut rand, &pubkey, &msg);
            let plain = decrypt(&private, cipher.as_str()).unwrap();
            assert_eq!(msg, plain, "Private key is not valid!");
        }
    }
}

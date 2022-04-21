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
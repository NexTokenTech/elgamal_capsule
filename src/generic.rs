use rug::{Integer,rand::RandState};
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
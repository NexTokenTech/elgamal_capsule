# ElGamal encryption system for the TREX network
This is a library for ElGamal encryption system on the TREX blockchain network. The data is encrpyted with the ElGamal system and appended to the TREX blockchain. Then, the data may be decrypted and released in the future.

This library is only compiled and teseted against x86 computer architectures and may not be supported on ARM computers or WASM run-time.

## Cargo usage
To use this library in your ,you should import elgamal_trex as a git dependence in Cargo.toml
```
[dependencies]
 elgamal_trex = { git = "https://github.com/NexTokenTech/elgamal_trex.git" }
```
See more examples in the unit test (src/lib.rs).

## Cargo doc
More details in this library is compiled as docstrings.
### This project support cargo doc, you should tap words in Terminal like below:
```
  cargo doc --open
```

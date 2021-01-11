# Winternitz-OTS

[![Crates.io](https://img.shields.io/crates/v/winternitz-ots)](https://crates.io/crates/winternitz-ots)
[![Build Status](https://travis-ci.org/0xAtropine/Winternitz-OTS.svg?branch=master)](https://travis-ci.org/0xAtropine/Winternitz-OTS)
![Crates.io](https://img.shields.io/crates/l/winternitz-ots)

A Rust Library/Crate For Dealing With The Post-Quantum Digital Signature Scheme **Winternitz One-Time Signature (W-OTS)** using the hash function **Blake2b**.

## Read About W-OTS

* [Hash-Based Signatures Part I: One-Time Signatures (OTS)](https://cryptoservices.github.io/quantum/2015/12/04/one-time-signatures.html)

* [Stackoverflow - Can someone explain very simplified how the Winternitz OTS/Lamport OTS works?](https://iota.stackexchange.com/questions/645/can-someone-explain-very-simplified-how-the-winternitz-ots-lamport-ots-works)

## How To Use

### Basic Usage

This will show you the basic usage of the library and how to generate a W-OTS Keypair and use it to sign a message digest, then verify the signature.

```rust
use winternitz_ots::wots;

// Generates a W-OTS Keypair using parameters using Winternitz Parameter of 16 and Blake2B
let keypair = wots::generate_wots();

// Have A Hexadecimal String You Would Like To Sign
let hex_digest = String::from("F7EE6090BA42BDDAB5899E8E25525922C3279D8563EEF37A597F13BCADA73DF7");

// Sign up to a 256bit (32 byte) hexadecimal digest using your W-OTS Keypair and a String
let signature = keypair.sign(hex_digest);

// Return a Boolean To Check Whether The Signature Is Valid
let verification: bool = signature.verify();

```

### Access Keypair Attributes

```rust
use winternitz_ots::wots;

// Generates a W-OTS Keypair using parameters using Winternitz Parameter of 16 and Blake2B
let keypair = wots::generate_wots();

// Sign Message
let sig = keypair.sign(message);

// Get From Keypair
let public_key: Vec<String> = keypair.pk;
let private_key: Vec<String> = keypair.sk;

// Get From Signature
let public_key = sig.pk;
let signatures = sig.signature;
let input: String = sig.input;
```

### More In-Depth Usage

```rust
extern crate winternitz_ots;
use winternitz_ots::wots;

fn main() {
    // Have A Hexadecimal String You Would Like To Sign
    let hex_string: String = String::from("ECC4C3134F80E54C08BAAE1A3F3BDC07BB3AD3906FF62D0D3DFC1EE87AE83194");

    // Generate W-OTS Keypair | Get The Hash Of The Public Key (For An Address For Example) using a digest from 1-64
    let keypair = wots::generate_wots();
    let public_key_hash = keypair.hash_public_key(8);

    // Export Public Key or Private Key; You may also wish to export metadata
    let pk = keypair.export_pk();
    let sk = keypair.export_sk();
    let (w, n) = keypair.export_metadata();

    // Use The Generate W-OTS Keypair
    let signature = keypair.sign(hex_string);

    // Check Whether The Signature Is Valid
    let is_signature_valid: bool = signature.verify();

    // Signature Attributes
        // A Vector of The Input Into Its Corresponding Value From 0-15 (for w=16)
    let input = &signature.input;
    let is_pk_hash_real = signature.verify_public_key_hash(public_key_hash.clone());

    println!();
    println!("PK[0]: {}",pk[0]);
    println!("PK[63]: {}",pk[63]);
    println!("SK[0]: {}",sk[0]);
    println!("SK[63]: {}",sk[63]);
    println!();
    println!("Public Key Address: 0x{}",public_key_hash);
    println!("Hash: Blake2b");
    println!("w: {}",w);
    println!("n: {}",n);
    println!();
    println!("Input: {}",input);
    println!();
    println!("Is Signature Valid: {}",is_signature_valid);
    println!("Is Public Key Address Valid For Given Public Key: {}",is_pk_hash_real);
    println!();
}
```

## To-Do

1. Add more tests / examples
2. Refactor Code A Lot and Reduce Memory Footprint
3. Attempt To Make Code Secure Against Side-Channel Attacks and Test For Security Vulnerabilties
4. Complete Benchmarks

---

A Winternitz-OTS+ (WOTS+) version in Rust is also currently in the works.

## License

Licensed under either of

* Apache License, Version 2.0

at your option.

## Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in the work by you, as defined in the Apache-2.0 license, shall be dual licensed as above, without any additional terms or conditions.

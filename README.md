# Winternitz-OTS

A Rust Library/Crate For Dealing With The Post-Quantum Digital Signature Scheme Winternitz One-Time Signature using the hash function Blake2b.

## Information

**Parameters Used By Default:**

* w: 16

* n: 32

* hash: Blake2b

## How To Use

```rust
use winternitz_ots::wots;

// Generates a W-OTS Keypair using parameters (w=16,n=32,hash=blake2b)
let keypair = wots::generate_wots();

// Have a Hexadecimal Digest String You Would Like To Sign 
let hex_digest: String = String::from("F7EE6090BA42BDDAB5899E8E25525922C3279D8563EEF37A597F13BCADA73DF7");

// Sign up to a 256bit (32 byte) hexadecimal digest using a W-OTS Keypair
let signature = keypair.sign(hex_digest);

// Return a Boolean To Check Whether The Signature Is Valid
let verification: bool = signature.verify();

```

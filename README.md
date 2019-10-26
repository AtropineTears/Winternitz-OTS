# Winternitz-OTS

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

## Dependecies

This library relies on the following crates:

* getrandom

> A Rust Crate that acts as a **CSPRNG** through the **Operating System** as opposed to in user-space. It supports a wide-variety of sources to get **cryptographic randomness** from.

* blake2-rfc

> A Rust Implementation of the **Blake2b Hashing Function**, a hashing algorithm based around **ChaCha20**. This function was chosen due to its **speed**, surpassing both MD5 and SHA1, while remaining as secure, if not more secure, than SHA256.

* hex

> A Rust Crate For Converting Between **Hexadecimal** and **Byte Vectors**

## License

* MIT License
* Apache License 2.0
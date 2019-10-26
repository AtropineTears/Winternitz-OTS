extern crate winternitz_ots;
use winternitz_ots::wots;

fn main() {
    // Have A Hexadecimal String You Would Like To Sign
    let hex_string: String = String::from("ECC4C3134F80E54C08BAAE1A3F3BDC07BB3AD3906FF62D0D3DFC1EE87AE83194");

    println!("Input String: {}", hex_string);
    
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
    let input = signature.input;
    let u4_bytes = signature.signature_cycles;

    println!("PK[0]: {}",pk[0]);
    println!("PK[63]: {}",pk[63]);
    println!("SK[0]: {}",sk[0]);
    println!("SK[63]: {}",sk[63]);
    println!();
    println!("Address: {}",public_key_hash);
    println!("w: {}",w);
    println!("n: {}",n);
    println!("Input: {}",input);
    println!("Cycles: {:?}",u4_bytes);
    println!();
    println!("Is Signature Valid: {}",is_signature_valid);
}
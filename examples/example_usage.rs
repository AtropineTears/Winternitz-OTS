extern crate winternitz_ots;
use winternitz_ots::wots;

fn main() {    
    // Generate W-OTS Keypair | Get A Hash Of The Public Key (For An Address For Example) using a digest from 1-64
    let keypair = wots::generate_wots();
    let public_key_hash = keypair.hash_public_key(8); // Length In Bytes of Public Address Derived From Public Key

    // Have A Hexadecimal String You Would Like To Sign
    let hex_string: String = String::from("ECC4C3134F80E54C08BAAE1A3F3BDC07BB3AD3906FF62D0D3DFC1EE87AE83194");
    
    // Export Public Key or Private Key; You may also wish to export metadata
    let pk = keypair.export_pk();
    let sk = keypair.export_sk();
    let (w, n) = keypair.export_metadata();

    // Use The Generated W-OTS Keypair To Sign The Provided Hexadecimal String
    let signature = keypair.sign(hex_string);
    
    // Check Whether The Signature Is Valid
    let is_signature_valid: bool = signature.verify();

    // Signature Attributes
    let input = &signature.input;
    let is_addr_hash_valid = signature.verify_public_key_hash(public_key_hash.clone());

    // Prints Out Information
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
    println!("Is Public Key Address Valid For Given Public Key: {}",is_addr_hash_valid);
    println!();
}
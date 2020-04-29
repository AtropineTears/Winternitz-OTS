use blake2_rfc::blake2b::{Blake2b, blake2b};
use hex;
use getrandom;


/// # W-OTS Keypair
/// This struct contains the W-OTS Keypair, including:
/// - w: The Wintertnitz Parameter, as a usize
/// - n: The Digest Length in Bytes, as a usize
/// - pk: The Public Key, as a Vector of Strings
/// - sk: The Private Key, as a Vector of Strings
#[derive(Debug, Clone, PartialEq, PartialOrd, Hash, Default)]
pub struct Wots {
    w: usize,
    n: usize,
    pub pk: Vec<String>,
    pub sk: Vec<String>,
}

/// # W-OTS Signature
/// This struct contains the signature, including
/// - public key: The Public Key as a vector of hexadecimal strings
/// - input string: A Hexadecimal String, with the default going up to 256bits if generated using the function
/// - signature: The Signature itself, as a vector of hexadecimal strings
#[derive(Debug, Clone, PartialEq, PartialOrd, Hash, Default)]
pub struct WotsSignature {
    pub pk: Vec<String>,
    pub input: String,
    pub signature: Vec<String>,
}

impl Wots {
    /// # Signature Function
    /// This function will let you sign an input hexadecimal string of up to 256bits.
    pub fn sign (&self, input: String) -> WotsSignature {
        // Create Empty Signature and Cycle Vector
        let mut signature: Vec<String> = vec![];
        let mut sig_cycles: Vec<usize> = vec![];
        
        // Input Formatting
        let input_uppercase = input.to_ascii_uppercase().clone();
        let input_vector = input_uppercase.clone().into_bytes();
        
        // Get Length of String and Assert It Is Not Longer Than PK
        let length: usize = input_vector.len();
        assert!(self.pk.len() >= length);
        
        // The Loop Itself
        for i in 0..length {
            
            // Turn Into Byte From Vector
            let byte = input_vector[i];
            
            // HEX: 0-9 (0-9)
            if byte >= 48 && byte <= 57 {
                let x: u8 = byte - 48u8;
                sig_cycles.push(x as usize);
            }
            // HEX: A-F (10-15)
            else if byte >= 65u8 && byte <= 70u8 {
                let x: u8 = byte - 55u8;
                sig_cycles.push(x as usize);
            }
            // HEX: a-f (10-15)
            else if byte >= 97 && byte <= 102 {
                let x: u8 = byte - 87u8;
                sig_cycles.push(x as usize);
            }
            else {
                panic!("The Input Is Not Supported Because Of Invalid Characters.")
            }
            // TODO: Remove Clone
            let sig: String = blake_hash(self.sk[i].clone(),sig_cycles[i]);
            signature.push(sig);
        }

        let output = WotsSignature {
            pk: self.pk.clone(),
            input: input,
            signature: signature,
            //signature_cycles: sig_cycles,
        };
        return output;
    }
    /// # Export Public Key
    pub fn export_pk(&self) -> Vec<String> {
        return self.pk.clone();
    }
    /// # Export Private Key
    pub fn export_sk(&self) -> Vec<String> {
        return self.sk.clone();
    }
    /// # Export Metadata
    pub fn export_metadata(&self) -> (usize, usize) {
        return (self.w, self.n);
    }
    /// # Hashing PK
    /// This function allows you to hash the public key which can be useful in certain situations.
    pub fn hash_public_key(&self, digest: usize) -> String {
        // Sanity Check For Digest Input
        if digest > 64usize || digest == 0usize {
            panic!("Digest Provided Is Either Too Small Or Too Large. It should be between 1 and 64 bytes.");
        }
        
        // Get Length Of Public Key
        let pk_length = self.pk.len();
        
        // Create Blake2B Hashing Context
        let mut pk_hash = Blake2b::new(digest);

        // Main Loop Where Hexadecimal Is Converted Into Bytes And Blake2B is updated
        for i in 0..pk_length {
            let s = self.pk[i].clone();
            pk_hash.update(&hex::decode(s).unwrap());
        }
        
        // Finalize Result As Blake2bResult and then convert into bytes which is encoded in hexadecimal
        let result = pk_hash.finalize();
        let output: String = hex::encode_upper(result.as_bytes());

        return output;
    }
}

impl WotsSignature {
    fn cycle(&self, input: String) -> Vec<usize> {
        let mut sig_cycles: Vec<usize> = vec![];

        // Input Formatting
        let input_uppercase = input.to_ascii_uppercase().clone();
        let input_vector = input_uppercase.clone().into_bytes();
        
        // Get Length of String and Assert It Is Not Longer Than PK
        let length: usize = input_vector.len();

        for i in 0..length { 
            // Turn Into Byte From Vector
            let byte = input_vector[i];
            
            // HEX: 0-9 (0-9)
            if byte >= 48 && byte <= 57 {
                let x: u8 = byte - 48u8;
                sig_cycles.push(x as usize);
            }
            // HEX: A-F (10-15)
            else if byte >= 65u8 && byte <= 70u8 {
                let x: u8 = byte - 55u8;
                sig_cycles.push(x as usize);
            }
            // HEX: a-f (10-15)
            else if byte >= 97 && byte <= 102 {
                let x: u8 = byte - 87u8;
                sig_cycles.push(x as usize);
            }
            else {
                panic!("The Input Is Not Supported Because Of Invalid Characters.")
            }
        }
        return sig_cycles;
    }
    /// # Verification of Signature
    /// This function allows you to verify the signature against the public key.
    pub fn verify (&self) -> bool {
        let signature_cycles: Vec<usize> = self.cycle(self.input.clone());
        let length: usize = signature_cycles.len();

        for i in 0..length {
            let cycle: usize = 16usize - signature_cycles[i];
            let blake: String = blake_hash(self.signature[i].clone(),cycle);
            assert_eq!(self.pk[i],blake)
        }
        return true;
    }
    /// # Verification of Public Key Hash
    /// This function allows you to verify the hash of the public key. Only useful in a small amount of situations.
    pub fn verify_public_key_hash (&self, mut input: String) -> bool {
        input = input.to_uppercase();
        
        // Get Digest By Dividing The Hexadecimal Representation By 2
        let digest = input.len() / 2usize;

        // Get Length Of Public Key
        let pk_length = self.pk.len();
        
        // Create Blake2B Hashing Context
        let mut pk_hash = Blake2b::new(digest);

        // Main Loop Where Hexadecimal Is Converted Into Bytes And Blake2B is updated
        for i in 0..pk_length {
            let s = self.pk[i].clone();
            pk_hash.update(&hex::decode(s).unwrap());
        }
        
        // Finalize Result As Blake2bResult and then convert into bytes which is encoded in hexadecimal
        let result = pk_hash.finalize();
        let output: String = hex::encode_upper(result.as_bytes());

        if input == output {
            return true
        }
        else {
            return false
        }
    }
}

// CSPRNG of 256bits (32 bytes) of Randomness
fn os_32() -> Result<[u8; 32], getrandom::Error> {
    let mut buf = [0u8; 32];
    getrandom::getrandom(&mut buf)?;
    Ok(buf)
}

// Used For Signing and Generation
// s: Hexadecimal String To Be Hashed
// w: Cycles of Hash Iterations To Be Performed
#[allow(dead_code)]
fn blake_hash(s: String, w:usize) -> String {
    let mut _is_generation: bool = false;
    let mut _is_signing: bool = false;
    
    
    if w == 0usize {
        return s;
    }
    else if w == 16usize {
        // Does Not Mean Anything As You Can Do This From The Secret Key Provided (0000)
        _is_generation = true;
    }
    else if w > 16usize {
        panic!("This Amount of Cycles is Not Supported")
    }
    else {
        _is_signing = true;
    }

    // Turn Hexadecimal Into A Vector of Bytes
    let bytes: Vec<u8> = hex::decode(s).unwrap().to_owned();
    // Turn Bytes Into An Array of Bytes
    let mut _blake = blake2b(32, &[], bytes.as_slice());
    let mut blake = _blake.as_bytes();
    
    // Cycles (w - 1) because the hex is decoded into a Vector and then hashed once before the loop
    let cycles = w - 1usize;

    // If A Single Hash is Performed and the cycles counter reaches 0, then return the value
    if cycles == 0usize {
        return hex::encode_upper(&blake);
    }
    
    // MAIN: The Loop Cycle
    for _i in 0..cycles {
        _blake = blake2b(32, &[], &blake);
        blake = _blake.as_bytes();
    }
    return hex::encode_upper(blake);
}

/// # Generate Default W-OTS Keypair
/// This function is the main function that allows you to generate a W-OTS Keypair used to sign up to 32bytes (256bits) and constructs the Wots struct.
/// - w: Winternitz Parameter (16)
/// - n: Digest Size in Bytes (32)
/// - sk: Secret Key as a vector of hexadecimal
/// - pk: Public Key as a vector of hexadecimal
pub fn generate_wots() -> Wots {
    let w: usize = 16; // Default Winternitz Parameter (signing 4 bits at a time)
    let n: usize = 32; // Default Digest Size in Bytes (256bits)
    
    // Create Secret Key and Public Key Pair
    let mut sk: Vec<String> = vec![];
    let mut pk: Vec<String> = vec![];

    
    for _i in 0..64 {
        // Generate Secret Key and Encode In Hexadecimal as a String
        let secret: [u8;32] = os_32().unwrap();
        let secret_hex: String = hex::encode_upper(secret);

        sk.push(secret_hex.clone());
        
        // Generate Public Key
        let public = blake_hash(secret_hex, w);

        pk.push(public)
    }
    let output = Wots {
        w: w, 
        n: n,
        pk: pk,
        sk: sk,
    };
    return output;
}
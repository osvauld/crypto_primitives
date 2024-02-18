use sequoia_openpgp as openpgp;
use openpgp::policy::StandardPolicy;
use std::time::Instant;
use rust_openpgp_wasm::{ generate, encrypt, decrypt};


fn main() -> openpgp::Result<()> {
    let p = StandardPolicy::new();

    // Key Generation Benchmark
    let start = Instant::now();
    let cert = generate()?;
    println!("Key generation took: {:?}", start.elapsed());

    // Prepare message and encryption
    let message = "This is a test message";
    let mut ciphertext = Vec::new();

    // Encryption Benchmark
    let start = Instant::now();
    encrypt(&p, &mut ciphertext, message, &cert)?;
    println!("Encryption took: {:?}", start.elapsed());

    // Decryption Benchmark
    let mut decrypted_msg = Vec::new();
    let start = Instant::now();
    decrypt(&p, &mut decrypted_msg, &ciphertext, &cert)?;
    println!("Decryption took: {:?}", start.elapsed());

    Ok(())
}
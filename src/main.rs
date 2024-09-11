use anyhow::Result;
use base64::{decode, encode};

mod crypto_utils;
use crypto_utils::{decrypt_and_load_certificate, generate_keys, sign_message_with_stored_cert};

fn main() -> Result<()> {
    // Generate keys
    let password = "my_secure_password";
    let username = "test_user";

    let keys = generate_keys(password, username).unwrap();

    // println!("Generated keys:");
    // println!("Encrypted Private Key: {}", keys.private_key);
    // println!("Public Key: {}", keys.public_key);
    // println!("Salt: {}", keys.salt);

    match decrypt_and_load_certificate(&keys.private_key, &keys.salt, password) {
        Ok(_) => println!("Successfully decrypted and loaded the certificate."),
        Err(e) => println!("Failed to decrypt and load the certificate: {:?}", e),
    }
    let message = "Hello, World!";
    match sign_message_with_stored_cert(message) {
        Ok(signed_message) => println!("Signed message: {}", signed_message),
        Err(e) => println!("Failed to sign message: {:?}", e),
    }

    Ok(())
}

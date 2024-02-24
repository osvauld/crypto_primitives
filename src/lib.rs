// lib.rs
mod crypto_utils;

use anyhow::Result;
use base64::{decode, encode};
use crypto_utils::*;
use lazy_static::lazy_static;
use openpgp::cert::prelude::*;
use openpgp::crypto::Password;
use openpgp::packet::key::SecretParts;
use openpgp::packet::key::UnspecifiedRole;
use openpgp::packet::Key;
use openpgp::parse::Parse;
use openpgp::policy::StandardPolicy;
use openpgp::serialize::stream::{Message, Signer};
use openpgp::serialize::Serialize;
use openpgp::types::KeyFlags;
use sequoia_openpgp as openpgp;

use serde_wasm_bindgen::to_value;
use std::io::Write;

use std::sync::Mutex;
use wasm_bindgen::prelude::*;

lazy_static! {
    static ref GLOBAL_CONTEXT: Mutex<
        Option<(
            Key<SecretParts, UnspecifiedRole>,
            Key<SecretParts, UnspecifiedRole>
        )>,
    > = Mutex::new(None);
}

#[wasm_bindgen]
pub fn generate_and_encrypt_keys(password: &str) -> Result<JsValue, JsValue> {
    // Example for generating an encryption certificate. Adjust as needed.
    let enc_cert = generate_cert_for_usage(KeyFlags::empty().set_storage_encryption(), password)
        .map_err(|e| JsValue::from_str(&e.to_string()))?;
    let sign_cert = generate_cert_for_usage(KeyFlags::empty().set_signing(), password)
        .map_err(|e| JsValue::from_str(&e.to_string()))?;

    // Serialize and encrypt the private keys using the password
    let mut enc_private_key = Vec::new();
    enc_cert
        .as_tsk()
        .serialize(&mut enc_private_key)
        .map_err(|err| JsValue::from_str(&err.to_string()))?;
    let mut sign_private_key = Vec::new();
    sign_cert
        .as_tsk()
        .serialize(&mut sign_private_key)
        .map_err(|err| JsValue::from_str(&err.to_string()))?;
    // Serialize the public keys

    // Serialize the public keys
    let mut enc_public_key = Vec::new();
    enc_cert
        .armored()
        .serialize(&mut enc_public_key)
        .map_err(|err| JsValue::from_str(&err.to_string()))?;
    let mut sign_public_key = Vec::new();
    sign_cert
        .armored()
        .serialize(&mut sign_public_key)
        .map_err(|err| JsValue::from_str(&err.to_string()))?;
    // Convert the keys into base64 strings
    let base64_enc_private_key = encode(&enc_private_key);
    let base64_sign_private_key = encode(&sign_private_key);
    let base64_enc_public_key = encode(&enc_public_key);
    let base64_sign_public_key = encode(&sign_public_key);

    // Return the base64-encoded private keys and public keys
    Ok(to_value(&serde_json::json!({
        "enc_private_key": base64_enc_private_key,
        "sign_private_key": base64_sign_private_key,
        "enc_public_key": base64_enc_public_key,
        "sign_public_key": base64_sign_public_key,
    }))
    .map_err(|err| JsValue::from_str(&err.to_string()))?)
}

#[wasm_bindgen]
pub fn encrypt_messages(public_key_b64: &str, plaintexts: Vec<String>) -> Result<JsValue, JsValue> {
    let public_key_bytes = decode(public_key_b64).map_err(|e| e.to_string())?;
    let cert = Cert::from_bytes(&public_key_bytes).map_err(|e| e.to_string())?;
    let policy = StandardPolicy::new();

    let mut encrypted_texts = Vec::new();

    for plaintext in plaintexts.iter() {
        let mut encrypted_data = Vec::new();
        encrypt(&policy, &mut encrypted_data, plaintext, &cert)
            .map_err(|e| JsValue::from_str(&e.to_string()))?;

        let encrypted_b64 = encode(&encrypted_data);
        encrypted_texts.push(encrypted_b64);
    }

    to_value(&encrypted_texts).map_err(|e| JsValue::from_str(&e.to_string()))
}

#[wasm_bindgen]
pub fn decrypt_messages(
    private_key_b64: &str,
    encrypted_texts: Vec<String>,
    password: &str,
) -> Result<JsValue, JsValue> {
    let private_key_bytes = decode(private_key_b64).map_err(|e| e.to_string())?;
    let cert = Cert::from_bytes(&private_key_bytes).map_err(|e| e.to_string())?;
    let p = &StandardPolicy::new();
    // Get the secret key from the certificate
    let keypair = cert
        .keys()
        .with_policy(p, None)
        .secret()
        .for_storage_encryption()
        .nth(0)
        .ok_or_else(|| JsValue::from_str("No suitable key found in Cert."))?
        .key()
        .clone();

    // Convert the password to a SessionKey
    let password = Password::from(password);

    // Decrypt the secret key with the password
    let sk = keypair
        .decrypt_secret(&password)
        .map_err(|_| JsValue::from_str("Failed to decrypt secret key with password."))?;
    let mut decrypted_texts = Vec::new();

    for encrypted_b64 in encrypted_texts.iter() {
        let encrypted_bytes = decode(encrypted_b64).map_err(|e| e.to_string())?;

        let plain_text = decrypt_message(p, &sk, &encrypted_bytes).map_err(|e| e.to_string())?;
        decrypted_texts.push(plain_text);
    }

    to_value(&decrypted_texts).map_err(|e| JsValue::from_str(&e.to_string()))
}

#[wasm_bindgen]
pub fn sign_message(encoded_key: &str, password: &str, message: &str) -> Result<JsValue, JsValue> {
    // Decoding the key
    let private_key_bytes = decode(encoded_key).map_err(|e| JsValue::from_str(&e.to_string()))?;
    let cert =
        Cert::from_bytes(&private_key_bytes).map_err(|e| JsValue::from_str(&e.to_string()))?;
    let policy = &StandardPolicy::new();

    // Finding a signing-capable key
    let key = cert
        .keys()
        .with_policy(policy, None)
        .secret()
        .for_signing()
        .nth(0)
        .ok_or_else(|| JsValue::from_str("No suitable key found in Cert."))?
        .key()
        .clone();

    // Decrypting the secret key with the provided password
    let password = Password::from(password);
    let decrypted_key = key
        .decrypt_secret(&password)
        .map_err(|_| JsValue::from_str("Failed to decrypt secret key with password."))?;

    // Preparing for the signing operation
    let mut signed_message = Vec::new();
    let message_writer = Message::new(&mut signed_message);

    // Initializing the signer
    let keypair = decrypted_key
        .into_keypair()
        .map_err(|_| JsValue::from_str("Failed to convert secret key into keypair."))?;
    let mut signer = Signer::new(message_writer, keypair)
        .detached() // This should correctly initialize a detached signer, if .detached() is a valid builder method
        .build()
        .map_err(|e| JsValue::from_str(&e.to_string()))?;

    // Signing the message
    signer
        .write_all(message.as_bytes())
        .map_err(|_| JsValue::from_str("Failed to write message to signer."))?;
    signer
        .finalize()
        .map_err(|_| JsValue::from_str("Failed to finalize signer."))?;

    // Armoring the signature
    let mut armored_signature = Vec::new();
    let mut armor_writer =
        openpgp::armor::Writer::new(&mut armored_signature, openpgp::armor::Kind::Signature)
            .map_err(|e| JsValue::from_str(&e.to_string()))?;
    armor_writer
        .write_all(&signed_message)
        .map_err(|_| JsValue::from_str("Failed to write signature."))?;
    armor_writer
        .finalize()
        .map_err(|_| JsValue::from_str("Failed to finalize armored writer."))?;

    // Encoding the armored signature in base64
    let base64_encoded_signature = base64::encode(armored_signature);

    Ok(JsValue::from_str(&base64_encoded_signature))
}

#[wasm_bindgen]
pub fn decrypt_and_store_keys(
    enc_private_key_b64: &str,
    sign_private_key_b64: &str,
    password: &str,
) -> Result<(), JsValue> {
    // Decrypt the encryption private key
    let enc_keypair = decrypt_private_key(enc_private_key_b64, password, false)
        .map_err(|_| JsValue::from_str("Failed to decrypt encryption private key."))?;

    // Decrypt the signing private key
    let sign_keypair = decrypt_private_key(sign_private_key_b64, password, true)
        .map_err(|_| JsValue::from_str("Failed to decrypt signing private key."))?;

    // Store the decrypted keys in the global context

    // Store the decrypted keys in the global context
    let mut context = GLOBAL_CONTEXT
        .lock()
        .map_err(|_| JsValue::from_str("Failed to lock global context."))?;
    *context = Some((enc_keypair.clone(), sign_keypair.clone()));
    Ok(())
}

#[wasm_bindgen]
pub fn sign_message_with_stored_key(message: &str) -> Result<JsValue, JsValue> {
    // Access the global context to retrieve the stored sign_keypair
    let context = GLOBAL_CONTEXT
        .lock()
        .map_err(|_| JsValue::from_str("Failed to lock global context."))?;
    let sign_keypair = context
        .as_ref()
        .ok_or_else(|| JsValue::from_str("No keys stored in context."))?
        .1
        .clone();

    // Convert the stored keypair into a form suitable for signing
    let keypair = sign_keypair
        .into_keypair()
        .map_err(|_| JsValue::from_str("Failed to convert secret key into keypair."))?;

    // Prepare for the signing operation
    let mut signed_message = Vec::new();
    let message_writer = Message::new(&mut signed_message);

    // Initialize the signer
    let mut signer = Signer::new(message_writer, keypair)
        .detached() // Assuming detached signature
        .build()
        .map_err(|e| JsValue::from_str(&e.to_string()))?;

    // Sign the message
    signer
        .write_all(message.as_bytes())
        .map_err(|_| JsValue::from_str("Failed to write message to signer."))?;
    signer
        .finalize()
        .map_err(|_| JsValue::from_str("Failed to finalize signer."))?;

    // Armoring the signature
    let mut armored_signature = Vec::new();
    let mut armor_writer =
        openpgp::armor::Writer::new(&mut armored_signature, openpgp::armor::Kind::Signature)
            .map_err(|e| JsValue::from_str(&e.to_string()))?;
    armor_writer
        .write_all(&signed_message)
        .map_err(|_| JsValue::from_str("Failed to write signature."))?;
    armor_writer
        .finalize()
        .map_err(|_| JsValue::from_str("Failed to finalize armored writer."))?;

    // Encoding the armored signature in base64
    let base64_encoded_signature = base64::encode(armored_signature);

    Ok(JsValue::from_str(&base64_encoded_signature))
}

#[wasm_bindgen]
pub fn is_global_context_set() -> bool {
    GLOBAL_CONTEXT.lock().unwrap().is_some()
}

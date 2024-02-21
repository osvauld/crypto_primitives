// lib.rs
mod crypto_utils;

use sequoia_openpgp as openpgp;
use crypto_utils::*;
use wasm_bindgen::prelude::*;
use serde_wasm_bindgen::to_value;
use base64::{encode, decode};
use std::io::Cursor;
use anyhow::Result ;
use openpgp::serialize::Serialize;
use openpgp::cert::prelude::*;
use openpgp::parse::Parse ;
use openpgp::policy::StandardPolicy;
use openpgp::types::KeyFlags;





#[wasm_bindgen]
pub fn generate_and_encrypt_keys(password: &str) -> Result<JsValue, JsValue> {
    // Example for generating an encryption certificate. Adjust as needed.
    let enc_cert = generate_cert_for_usage(KeyFlags::empty().set_storage_encryption(), password).map_err(|e| JsValue::from_str(&e.to_string()))?;
    let sign_cert = generate_cert_for_usage(KeyFlags::empty().set_signing(), password).map_err(|e| JsValue::from_str(&e.to_string()))?;

    // Serialize and encrypt the private keys using the password
    let mut enc_private_key = Vec::new();
    enc_cert.as_tsk().serialize(&mut enc_private_key).map_err(|err| JsValue::from_str(&err.to_string()))?;
    let mut sign_private_key = Vec::new();
    sign_cert.as_tsk().serialize(&mut sign_private_key).map_err(|err| JsValue::from_str(&err.to_string()))?;

    // Serialize the public keys
    let mut enc_public_key = Vec::new();
    enc_cert.serialize(&mut enc_public_key).map_err(|err| JsValue::from_str(&err.to_string()))?;
    let mut sign_public_key = Vec::new();
    sign_cert.serialize(&mut sign_public_key).map_err(|err| JsValue::from_str(&err.to_string()))?;

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
    })).map_err(|err| JsValue::from_str(&err.to_string()))?)
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
pub fn decrypt_messages(private_key_b64: &str, encrypted_texts: Vec<String>) -> Result<JsValue, JsValue> {
    let private_key_bytes = decode(private_key_b64).map_err(|e| e.to_string())?;
    let cert = Cert::from_bytes(&private_key_bytes).map_err(|e| e.to_string())?;
    let policy = StandardPolicy::new();

    let mut decrypted_texts = Vec::new();

    for encrypted_b64 in encrypted_texts.iter() {
        let encrypted_bytes = decode(encrypted_b64).map_err(|e| e.to_string())?;
        let mut decrypted_data = Cursor::new(Vec::new());
        decrypt(&policy, &mut decrypted_data, &encrypted_bytes, &cert).map_err(|e| e.to_string())?;

        let decrypted_data = decrypted_data.into_inner();
        let decrypted_text = String::from_utf8(decrypted_data).map_err(|e| e.to_string())?;
        decrypted_texts.push(decrypted_text);
    }

    to_value(&decrypted_texts).map_err(|e| JsValue::from_str(&e.to_string()))
}

/// Generates an encryption-capable key.
pub fn generate() -> openpgp::Result<openpgp::Cert> {
    let (cert, _revocation) = CertBuilder::new()
        .add_userid("someone@example.org")
        .add_transport_encryption_subkey()
        .generate()?;

    // Save the revocation certificate somewhere.

    Ok(cert)
}

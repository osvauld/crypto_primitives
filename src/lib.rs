// lib.rs
mod crypto_core;
mod crypto_utils;
mod errors;
mod types;

use crate::types::{
    BasicFields, Credential, CredentialFields, Field, PasswordChangeInput, PublicKey, UrlMap,
};
use anyhow::Result;
use crypto_utils::*;
use js_sys::Array;
use serde_wasm_bindgen::{from_value, to_value};
use wasm_bindgen::prelude::*;
use web_sys::console;

#[wasm_bindgen]
pub fn hello_wasm() -> JsValue {
    JsValue::from_str("Hello from WASM!")
}

#[wasm_bindgen]
pub fn generate_and_encrypt_keys(password: &str, username: &str) -> Result<JsValue, JsValue> {
    let keys = generate_keys(password, username).map_err(|e| JsValue::from_str(&e.to_string()))?;

    Ok(to_value(&serde_json::json!({
        "enc_private_key": keys.private_key,
        "sign_private_key": keys.private_key,
        "enc_public_key": keys.public_key,
        "sign_public_key": keys.public_key,
        "salt": keys.salt,
    }))
    .map_err(|err| JsValue::from_str(&err.to_string()))?)
}

#[wasm_bindgen]
pub fn generate_keys_without_password(username: &str) -> Result<JsValue, JsValue> {
    let keys =
        gen_keys_without_password(username).map_err(|e| JsValue::from_str(&e.to_string()))?;

    // Return the base64-encoded private keys and public keys
    Ok(to_value(&serde_json::json!({
        "enc_private_key": keys.private_key,
        "sign_private_key": keys.private_key,
        "enc_public_key": keys.public_key,
        "sign_public_key": keys.salt,
    }))
    .map_err(|err| JsValue::from_str(&err.to_string()))?)
}

#[wasm_bindgen]
pub fn decrypt_and_store_keys(
    encrypted_cert_b64: &str,
    salt_b64: &str,
    passphrase: &str,
) -> Result<(), JsValue> {
    crypto_utils::decrypt_and_load_certificate(encrypted_cert_b64, salt_b64, passphrase).map_err(
        |e| {
            let error_msg = format!("Failed to decrypt and load certificate: {}", e);
            console::error_1(&JsValue::from_str(&error_msg));
            JsValue::from_str(&error_msg)
        },
    )
}

#[wasm_bindgen]
pub fn sign_message_with_stored_key(message: &str) -> Result<JsValue, JsValue> {
    crypto_utils::sign_message_with_stored_cert(message)
        .map(|signature| JsValue::from_str(&signature))
        .map_err(|e| JsValue::from_str(&format!("Failed to sign message: {}", e)))
}

#[wasm_bindgen]
pub fn is_global_context_set() -> bool {
    crypto_utils::is_context_set()
}

#[wasm_bindgen]
pub fn clear_global_context() {
    crypto_utils::clear_context();
}

#[wasm_bindgen]
pub fn encrypt_new_credential(public_keys: Array, fields: Array) -> Result<JsValue, JsValue> {
    let public_keys: Vec<PublicKey> = public_keys
        .iter()
        .map(|key| {
            from_value(key).map_err(|_| JsValue::from_str("Failed to deserialize public key"))
        })
        .collect::<Result<Vec<_>, JsValue>>()?;

    let fields: Vec<Field> = fields
        .iter()
        .map(|field| {
            from_value(field).map_err(|_| JsValue::from_str("Failed to deserialize field"))
        })
        .collect::<Result<Vec<_>, JsValue>>()?;

    let encrypted_fields = encrypt_fields_for_multiple_keys(public_keys, fields)
        .map_err(|e| JsValue::from_str(&format!("Encryption failed: {}", e)))?;

    Ok(to_value(&encrypted_fields)?)
}

#[wasm_bindgen]
pub fn decrypt_credentials(credentials: JsValue) -> Result<JsValue, JsValue> {
    // Convert JsValue (which is expected to be an array) into Vec<Credential>
    let creds_vec: Vec<Credential> =
        from_value(credentials).map_err(|e| JsValue::from_str(&e.to_string()))?;

    // Call the function in crypto_utils
    match crypto_utils::decrypt_credentials(creds_vec) {
        Ok(decrypted) => {
            serde_wasm_bindgen::to_value(&decrypted).map_err(|e| JsValue::from_str(&e.to_string()))
        }
        Err(e) => Err(JsValue::from_str(&e.to_string())),
    }
}

#[wasm_bindgen]
pub fn decrypt_text(encrypted_text: JsValue) -> Result<JsValue, JsValue> {
    // Convert JsValue to String
    let encrypted_text_str: String = encrypted_text
        .as_string()
        .ok_or_else(|| JsValue::from_str("Invalid input: expected a string"))?;

    // Call the decrypt_text function in crypto_utils
    let decrypted_text = crypto_utils::decrypt_text(encrypted_text_str)
        .map_err(|e| JsValue::from_str(&e.to_string()))?;

    // Return the decrypted text as JsValue
    Ok(JsValue::from_str(&decrypted_text))
}

#[wasm_bindgen]
pub fn decrypt_fields(credentials: JsValue) -> Result<JsValue, JsValue> {
    // Convert JsValue to Vec<CredentialFields>
    let credentials: Vec<CredentialFields> =
        from_value(credentials).map_err(|e| JsValue::from_str(&e.to_string()))?;

    // Call the decrypt_fields function in crypto_utils
    let decrypted_credentials =
        crypto_utils::decrypt_fields(credentials).map_err(|e| JsValue::from_str(&e.to_string()))?;

    // Convert the result back to JsValue
    to_value(&decrypted_credentials).map_err(|e| JsValue::from_str(&e.to_string()))
}
#[wasm_bindgen]
pub fn encrypt_fields(fields: JsValue, public_key: JsValue) -> Result<JsValue, JsValue> {
    // Convert JsValue to Vec<BasicFields>
    let fields: Vec<BasicFields> =
        from_value(fields).map_err(|e| JsValue::from_str(&e.to_string()))?;

    // Convert public_key JsValue to String
    let public_key_str: String = public_key
        .as_string()
        .ok_or_else(|| JsValue::from_str("Invalid public key: expected a string"))?;

    // Call the encrypt_fields function in crypto_utils
    let encrypted_fields = crypto_utils::encrypt_fields(fields, &public_key_str)
        .map_err(|e| JsValue::from_str(&e.to_string()))?;

    // Convert the result back to JsValue
    to_value(&encrypted_fields).map_err(|e| JsValue::from_str(&e.to_string()))
}

#[wasm_bindgen]
pub fn sign_hash_message(text: &str) -> Result<JsValue, JsValue> {
    let signature =
        crypto_utils::sign_and_hash_message(text).map_err(|e| JsValue::from_str(&e.to_string()))?;
    Ok(JsValue::from_str(&signature))
}

#[wasm_bindgen]
pub fn encrypt_field_value(field_value: String, public_keys: Array) -> Result<JsValue, JsValue> {
    let public_keys: Vec<PublicKey> = public_keys
        .iter()
        .map(|key| {
            from_value(key).map_err(|_| JsValue::from_str("Failed to deserialize public key"))
        })
        .collect::<Result<Vec<_>, JsValue>>()?;

    let results = crypto_utils::encrypt_field_value(&field_value, public_keys)
        .map_err(|e| JsValue::from_str(&format!("Encryption failed: {}", e)))?;
    serde_wasm_bindgen::to_value(&results)
        .map_err(|e| JsValue::from_str(&format!("Serialization failed: {}", e)))
}

#[wasm_bindgen]
pub fn decrypt_urls(urls: JsValue) -> Result<JsValue, JsValue> {
    let urls: Vec<UrlMap> = from_value(urls).map_err(|e| JsValue::from_str(&e.to_string()))?;
    let decrypted_urls = crypto_utils::decrypt_urls(urls)
        .map_err(|e| JsValue::from_str(&format!("decryption failed: {}", e)))?;
    to_value(&decrypted_urls)
        .map_err(|e| JsValue::from_str(&format!("Serialization failed: {}", e)))
}
#[wasm_bindgen]
pub fn import_certificate(cert_string: JsValue, passphrase: JsValue) -> Result<JsValue, JsValue> {
    let cert_string: String = cert_string
        .as_string()
        .ok_or_else(|| JsValue::from_str("Invalid input: expected a string"))?;

    let passphrase: String = passphrase
        .as_string()
        .ok_or_else(|| JsValue::from_str("Invalid input: expected a string"))?;

    let keys = crypto_utils::import_certificate(cert_string, passphrase)
        .map_err(|e| JsValue::from_str(&e.to_string()))?;
    Ok(to_value(&serde_json::json!({
        "enc_private_key": keys.private_key,
        "sign_private_key": keys.private_key,
        "enc_public_key": keys.public_key,
        "sign_public_key": keys.salt,
    }))
    .map_err(|err| JsValue::from_str(&err.to_string()))?)
}

#[wasm_bindgen]
pub fn export_certificate(
    passphrase: &str,
    enc_pvt_key: &str,
    salt: &str,
) -> Result<JsValue, JsValue> {
    let key = crypto_utils::export_certificate(passphrase, enc_pvt_key, salt)
        .map_err(|e| JsValue::from_str(&e.to_string()))?;
    Ok(to_value(&key).unwrap_or(JsValue::NULL))
}

#[wasm_bindgen]
pub fn change_password(input: JsValue) -> Result<JsValue, JsValue> {
    let input: PasswordChangeInput = from_value(input)
        .map_err(|e| JsValue::from_str(&format!("Failed to deserialize input: {}", e)))?;

    let new_encrypted_cert = crypto_utils::change_certificate_password(
        &input.enc_pvt_key,
        &input.salt,
        &input.old_password,
        &input.new_password,
    )
    .map_err(|e| JsValue::from_str(&e.to_string()))?;

    Ok(JsValue::from_str(&new_encrypted_cert))
}

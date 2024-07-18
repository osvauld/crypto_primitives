// lib.rs
mod crypto_utils;

use anyhow::Result;
use base64::{decode, encode};
use crypto_utils::*;
use js_sys::Array;
use lazy_static::lazy_static;
use openpgp::cert::prelude::*;
use openpgp::crypto::KeyPair;
use openpgp::crypto::Password;
use openpgp::packet::key::SecretParts;
use openpgp::packet::key::UnspecifiedRole;
use openpgp::packet::Key;
use openpgp::parse::Parse;
use openpgp::policy::StandardPolicy;
use openpgp::serialize::stream::{Message, Signer};
use openpgp::serialize::Serialize as openpgp_Serialize;
use openpgp::types::KeyFlags;
use sequoia_openpgp as openpgp;
use serde::{Deserialize, Serialize};
use serde_wasm_bindgen::{from_value, to_value};
use std::collections::HashMap;
use std::io::Write;
use std::sync::Mutex;
use wasm_bindgen::prelude::*;
use web_sys::console;

lazy_static! {
    static ref GLOBAL_CONTEXT: Mutex<
        Option<(
            Key<SecretParts, UnspecifiedRole>,
            Key<SecretParts, UnspecifiedRole>
        )>,
    > = Mutex::new(None);
}

#[wasm_bindgen]

pub fn hello_wasm() -> JsValue {
    JsValue::from_str("Hello from WASM!")
}

#[wasm_bindgen]
pub fn generate_and_encrypt_keys(password: &str, username: &str) -> Result<JsValue, JsValue> {
    // Example for generating an encryption certificate. Adjust as needed.
    let enc_cert = generate_certificate(
        KeyFlags::empty().set_storage_encryption(),
        password,
        username,
    )
    .map_err(|e| JsValue::from_str(&e.to_string()))?;
    let sign_cert = generate_certificate(KeyFlags::empty().set_signing(), password, username)
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
pub fn generate_keys_without_password(username: &str) -> Result<JsValue, JsValue> {
    let enc_cert =
        generate_certificate_without_password(KeyFlags::empty().set_storage_encryption(), username)
            .map_err(|e| JsValue::from_str(&e.to_string()))?;
    let sign_cert =
        generate_certificate_without_password(KeyFlags::empty().set_signing(), username)
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
    let keypair = get_sign_keypair().map_err(|e| JsValue::from_str(&e))?;

    // Call `sign_message_with_keypair` and directly use its result
    let base64_encoded_signature =
        sign_message_with_keypair(message, keypair).map_err(|e| JsValue::from_str(&e))?; // Convert error to JsValue and propagate if any

    // Return the result wrapped in a JsValue
    Ok(JsValue::from_str(&base64_encoded_signature))
}

#[wasm_bindgen]
pub fn is_global_context_set() -> bool {
    GLOBAL_CONTEXT.lock().unwrap().is_some()
}
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PublicKey {
    id: String,
    public_key: String,
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Field {
    field_name: Option<String>,
    field_value: String,
    field_type: Option<String>,
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EncryptedField {
    user_id: String,
    fields: Vec<Field>,
}

#[wasm_bindgen]
pub fn encrypt_new_credential(public_keys: Array, fields: Array) -> Result<JsValue, JsValue> {
    let mut encrypted_fields = Vec::new();
    let policy = StandardPolicy::new();

    for public_key in public_keys.iter() {
        let public_key_struct: PublicKey = from_value(public_key.clone())
            .map_err(|_| JsValue::from_str("Failed to deserialize public key"))?;

        let public_key_decoded = base64::decode(&public_key_struct.public_key)
            .map_err(|_| JsValue::from_str("Failed to decode public key"))?;

        let public_key_openpgp = Cert::from_bytes(&public_key_decoded)
            .map_err(|_| JsValue::from_str("Failed to parse public key"))?;

        let mut fields_for_user = Vec::new();

        for field in fields.iter() {
            let mut sink = Vec::new();
            let field: Field = from_value(field.clone())
                .map_err(|_| JsValue::from_str("Failed to deserialize field"))?;

            // Encrypt the field value
            encrypt(&policy, &mut sink, &field.field_value, &public_key_openpgp)
                .map_err(|_| JsValue::from_str("Failed to encrypt field value"))?;

            fields_for_user.push(Field {
                field_name: field.field_name,
                field_value: encode(sink),
                field_type: field.field_type,
            });
        }

        encrypted_fields.push(EncryptedField {
            user_id: public_key_struct.id,
            fields: fields_for_user,
        });
    }

    Ok(serde_wasm_bindgen::to_value(&encrypted_fields)?)
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct MetaField {
    field_id: String,
    field_name: Option<String>,
    field_value: String,
    field_type: Option<String>,
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Credential {
    credential_id: String,
    fields: Vec<MetaField>,
    name: String,
    description: String,
    folder_id: String,
    credential_type: String,
    created_at: String,
    created_by: String,
    updated_at: String,
    access_type: String,
}
#[wasm_bindgen]
pub fn decrypt_credentials(credentials: Array) -> Result<JsValue, JsValue> {
    let context = GLOBAL_CONTEXT
        .lock()
        .map_err(|_| JsValue::from_str("Failed to lock global context."))?;

    let (enc_keypair, _) = context
        .as_ref()
        .ok_or(JsValue::from_str("Keys are not loaded in the context."))?;

    let policy = StandardPolicy::new();

    let mut decrypted_credentials = Vec::new();

    for credential in credentials.iter() {
        let credential: Credential = from_value(credential.clone()).map_err(|e| {
            JsValue::from_str(&format!(
                "Error at credential deserialization: {}",
                e.to_string()
            ))
        })?;
        let mut decrypted_fields = Vec::new();

        for field in credential.fields.iter() {
            let encrypted_bytes = decode(&field.field_value).map_err(|e| e.to_string())?;
            let decrypted_bytes = decrypt_message(&policy, &enc_keypair, &encrypted_bytes)
                .map_err(|e| e.to_string())?;

            let decrypted_text = String::from_utf8(decrypted_bytes).map_err(|e| e.to_string())?;

            decrypted_fields.push(MetaField {
                field_id: field.field_id.clone(),
                field_name: field.field_name.clone(),
                field_value: decrypted_text,
                field_type: field.field_type.clone(),
            });
        }

        decrypted_credentials.push(Credential {
            credential_id: credential.credential_id.clone(),
            name: credential.name.clone(),
            description: credential.description.clone(),
            folder_id: credential.folder_id.clone(),
            credential_type: credential.credential_type.clone(),
            created_at: credential.created_at.clone(),
            created_by: credential.created_by.clone(),
            updated_at: credential.updated_at.clone(),
            access_type: credential.access_type.clone(),
            fields: decrypted_fields,
        });
    }

    serde_wasm_bindgen::to_value(&decrypted_credentials)
        .map_err(|e| JsValue::from_str(&e.to_string()))
}

#[wasm_bindgen]
pub fn decrypt_text(encrypted_text: String) -> Result<JsValue, JsValue> {
    let context = GLOBAL_CONTEXT
        .lock()
        .map_err(|_| JsValue::from_str("Failed to lock global context."))?;

    let (enc_keypair, _) = context
        .as_ref()
        .ok_or(JsValue::from_str("Keys are not loaded in the context."))?;

    let policy = StandardPolicy::new();

    let encrypted_bytes = decode(&encrypted_text).map_err(|e| JsValue::from_str(&e.to_string()))?;
    let decrypted_bytes = decrypt_message(&policy, &enc_keypair, &encrypted_bytes)
        .map_err(|e| JsValue::from_str(&e.to_string()))?;

    let decrypted_text =
        String::from_utf8(decrypted_bytes).map_err(|e| JsValue::from_str(&e.to_string()))?;

    Ok(JsValue::from_str(&decrypted_text))
}
#[derive(Serialize, Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct BasicFields {
    field_id: String,
    field_value: String,
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct CredentialFields {
    credential_id: String,
    fields: Vec<BasicFields>,
}

#[wasm_bindgen]
pub fn decrypt_fields(credentials: JsValue) -> Result<JsValue, JsValue> {
    let credentials: Vec<CredentialFields> = serde_wasm_bindgen::from_value(credentials)
        .map_err(|e| JsValue::from_str(&e.to_string()))?;

    let context = GLOBAL_CONTEXT
        .lock()
        .map_err(|_| JsValue::from_str("Failed to lock global context."))?;

    let (enc_keypair, _) = context
        .as_ref()
        .ok_or(JsValue::from_str("Keys are not loaded in the context."))?;

    let policy: StandardPolicy = StandardPolicy::new();

    let mut decrypted_credentials = Vec::new();

    for credential in credentials {
        let mut decrypted_fields = Vec::new();

        for field in credential.fields {
            let encrypted_bytes =
                decode(&field.field_value).map_err(|e| JsValue::from_str(&e.to_string()))?;
            let decrypted_bytes = decrypt_message(&policy, &enc_keypair, &encrypted_bytes)
                .map_err(|e| JsValue::from_str(&e.to_string()))?;
            let decrypted_text = String::from_utf8(decrypted_bytes)
                .map_err(|e| JsValue::from_str(&e.to_string()))?;

            decrypted_fields.push(BasicFields {
                field_id: field.field_id,
                field_value: decrypted_text,
            });
        }

        decrypted_credentials.push(CredentialFields {
            credential_id: credential.credential_id,
            fields: decrypted_fields,
        });
    }

    serde_wasm_bindgen::to_value(&decrypted_credentials)
        .map_err(|e| JsValue::from_str(&e.to_string()))
}

#[wasm_bindgen]
pub fn encrypt_fields(fields: Array, public_key: String) -> Result<JsValue, JsValue> {
    let policy = StandardPolicy::new();

    let public_key_decoded = base64::decode(&public_key)
        .map_err(|_| JsValue::from_str("Failed to decode public key"))?;

    let public_key_openpgp = Cert::from_bytes(&public_key_decoded)
        .map_err(|_| JsValue::from_str("Failed to parse public key"))?;

    let mut encrypted_fields = Vec::new();

    for field in fields {
        let field: BasicFields = from_value(field.clone())
            .map_err(|_| JsValue::from_str("Failed to deserialize field"))?;
        let mut sink = Vec::new();
        encrypt(&policy, &mut sink, &field.field_value, &public_key_openpgp)
            .map_err(|_| JsValue::from_str("Failed to encrypt field value"))?;
        let encrypted_text = encode(&sink);

        encrypted_fields.push(BasicFields {
            field_id: field.field_id,
            field_value: encrypted_text,
        });
    }

    serde_wasm_bindgen::to_value(&encrypted_fields).map_err(|e| JsValue::from_str(&e.to_string()))
}

#[wasm_bindgen]
pub fn get_pub_key(private_key_b64: &str) -> Result<JsValue, JsValue> {
    // Parse the certificate
    let pub_key_str =
        get_pub_key_str(private_key_b64).map_err(|e| JsValue::from_str(&e.to_string()))?;

    // Return the public key
    Ok(JsValue::from_str(&pub_key_str))
}

#[wasm_bindgen]
pub fn sign_hash_message(text: &str) -> Result<JsValue, JsValue> {
    let encoded_text = base64::encode(text);
    let hash = hash_text_sha512(&encoded_text).map_err(|e| JsValue::from_str(&e))?;
    let hash_str = encode(&hash);
    let keypair = get_sign_keypair().map_err(|e| JsValue::from_str(&e))?;

    let base64_encoded_signature =
        sign_message_with_keypair(&hash_str, keypair).map_err(|e| JsValue::from_str(&e))?; // Convert error to JsValue and propagate if any

    // Return the result wrapped in a JsValue
    Ok(JsValue::from_str(&base64_encoded_signature))
}

fn get_sign_keypair() -> Result<KeyPair, String> {
    let context = GLOBAL_CONTEXT
        .lock()
        .map_err(|_| "Failed to lock global context.".to_string())?;
    let sign_keypair = context
        .as_ref()
        .ok_or_else(|| "No keys stored in context.".to_string())?
        .1
        .clone();

    // Convert the stored keypair into a form suitable for signing
    let keypair = sign_keypair
        .into_keypair()
        .map_err(|_| "Failed to convert secret key into keypair.".to_string())?;

    Ok(keypair)
}

#[wasm_bindgen]
pub fn encrypt_field_value(field_value: String, users: JsValue) -> Result<JsValue, JsValue> {
    // Parse the users JSON
    let users: Vec<HashMap<String, String>> =
        from_value(users).map_err(|e| JsValue::from_str(&e.to_string()))?;

    // Create a buffer to hold the encrypted data
    let mut encrypted_data = Vec::new();

    // Create a policy

    let policy = StandardPolicy::new();
    // Process each user
    let mut results = Vec::new();
    for user in users {
        // Get the user ID and public key
        let user_id = user
            .get("userId")
            .ok_or_else(|| JsValue::from_str("Missing userId"))?
            .clone();
        let public_key = user
            .get("publicKey")
            .ok_or_else(|| JsValue::from_str("Missing publicKey"))?
            .clone();

        // Decode the public key from base64
        let public_key_bytes =
            base64::decode(&public_key).map_err(|e| JsValue::from_str(&e.to_string()))?;

        // Parse the public key
        let public_key =
            Cert::from_bytes(&public_key_bytes).map_err(|e| JsValue::from_str(&e.to_string()))?;

        // Encrypt the field value with the public key
        encrypt(&policy, &mut encrypted_data, &field_value, &public_key)
            .map_err(|e| JsValue::from_str(&e.to_string()))?;

        // Encode the encrypted data to base64
        let encrypted_field_value_base64 = base64::encode(&encrypted_data);

        // Add the user ID and the encrypted field value to the results
        results.push(serde_json::json!({
            "userId": user_id,
            "fieldValue": encrypted_field_value_base64,
        }));
    }

    // Return the results
    to_value(&results).map_err(|e| JsValue::from_str(&e.to_string()))
}
#[derive(Serialize, Deserialize)]
pub struct UrlMap {
    value: String,
    credentialId: String,
}
#[wasm_bindgen]

pub fn decrypt_urls(urls: JsValue) -> Result<JsValue, JsValue> {
    let urls: Vec<UrlMap> = from_value(urls).map_err(|e| JsValue::from_str(&e.to_string()))?;
    let mut decrypted_urls: Vec<UrlMap> = Vec::new();
    let context = GLOBAL_CONTEXT
        .lock()
        .map_err(|_| JsValue::from_str("Failed to lock global context."))?;

    let (enc_keypair, _) = context
        .as_ref()
        .ok_or(JsValue::from_str("Keys are not loaded in the context."))?;

    let policy: StandardPolicy = StandardPolicy::new();
    for url in urls {
        let encrypted_bytes = decode(&url.value).map_err(|e| JsValue::from_str(&e.to_string()))?;
        let decrypted_bytes = decrypt_message(&policy, &enc_keypair, &encrypted_bytes)
            .map_err(|e| JsValue::from_str(&e.to_string()))?;
        let decrypted_text =
            String::from_utf8(decrypted_bytes).map_err(|e| JsValue::from_str(&e.to_string()))?;
        decrypted_urls.push(UrlMap {
            value: decrypted_text,
            credentialId: url.credentialId,
        });
    }
    to_value(&decrypted_urls).map_err(|e| JsValue::from_str(&e.to_string()))
}

use sequoia_openpgp as openpgp;
use openpgp::cert::prelude::*;
use openpgp::serialize::Serialize;
use wasm_bindgen::prelude::*;
use serde_wasm_bindgen::to_value;
use base64::{encode, decode};
use openpgp::parse::Parse; // Make sure Parse is in scope
use openpgp::serialize::stream::{Message, Encryptor2, LiteralWriter};
use openpgp::policy::StandardPolicy;
use std::time::Instant;
use std::io::Write; // Required for write_all
use console_error_panic_hook;

#[wasm_bindgen(start)]
pub fn start() {
    console_error_panic_hook::set_once();
}

#[wasm_bindgen]
pub fn generate_openpgp_keypair() -> Result<JsValue, JsValue> {
    let (cert, _revocation) = CertBuilder::new()
        .add_userid("someone@example.org")
        .add_transport_encryption_subkey()
        .generate()
        .map_err(|err| JsValue::from_str(&err.to_string()))?;

    // Serialize the private key to an armored string.
    let mut armored_private_key = Vec::new();
    cert.as_tsk().serialize(&mut armored_private_key)
        .map_err(|err| JsValue::from_str(&err.to_string()))?;

    // Serialize the public key to an armored string.
    let mut armored_public_key = Vec::new();
    cert.serialize(&mut armored_public_key)
        .map_err(|err| JsValue::from_str(&err.to_string()))?;

    let base64_private_key = encode(&armored_private_key);
    let base64_public_key = encode(&armored_public_key);
    // Convert the armored keys into `JsValue`.
    Ok(to_value(&serde_json::json!({
        "privateKey": base64_private_key,
        "publicKey": base64_public_key,
    })).map_err(|err| JsValue::from_str(&err.to_string()))?)
}


#[wasm_bindgen]
pub fn encrypt_data_for_js(base64_public_key: String, texts: Vec<String>) -> Result<JsValue, JsValue> {
    println!("Starting encryption...");
    let public_key_bytes = decode(&base64_public_key).map_err(|e| {
        let err_msg = format!("Error decoding base64 public key: {}", e);
        println!("{}", &err_msg);
        e.to_string()
    })?;
    let cert = Cert::from_bytes(&public_key_bytes)
        .map_err(|e| {
            let err_msg = format!("Error parsing Cert from bytes: {}", e);
            println!("{}",&err_msg);
            JsValue::from_str(&err_msg)
        })?;
    println!("Cert parsed successfully.");
    let policy = StandardPolicy::new();

    let mut encrypted_texts = Vec::new();
    let mut encryption_times = Vec::new(); // Vector to store encryption times

    for text in texts.iter() {
        let recipients = cert.keys().with_policy(&policy, None).alive().for_transport_encryption();

        let mut encrypted_data = Vec::new();
        let message = Message::new(&mut encrypted_data);

        let start_time = Instant::now(); // Start timing

        let encryptor = Encryptor2::for_recipients(message, recipients)
            .build()
            .map_err(|e| JsValue::from_str(&format!("Failed to create encryptor: {}", e)))?;

        let mut literal_writer = LiteralWriter::new(encryptor)
            .build()
            .map_err(|e| JsValue::from_str(&format!("Failed to create literal writer: {}", e)))?;
        
        literal_writer.write_all(text.as_bytes())
            .map_err(|e| JsValue::from_str(&format!("Failed to write data: {}", e)))?;
        literal_writer.finalize()
            .map_err(|e| JsValue::from_str(&format!("Failed to finalize writer: {}", e)))?;

        let encryption_duration = start_time.elapsed(); // End timing
        encryption_times.push(encryption_duration.as_secs_f64()); // Store encryption time in seconds

        let base64_encrypted_data = encode(&encrypted_data);
        encrypted_texts.push(base64_encrypted_data);
    }

    // Combine encrypted texts and their encryption times into a single JSON object to return
    let result = serde_wasm_bindgen::to_value(&serde_json::json!({
        "encrypted_texts": encrypted_texts,
        "encryption_times": encryption_times,
    })).map_err(|e| JsValue::from_str(&e.to_string()))?;

    Ok(result)
}
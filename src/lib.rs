// lib.rs
use sequoia_openpgp as openpgp;
use wasm_bindgen::prelude::*;
use openpgp::cert::prelude::*;
use openpgp::crypto::SessionKey;
use openpgp::types::SymmetricAlgorithm;
use openpgp::serialize::stream::*;
use openpgp::parse::{Parse, stream::*};
use openpgp::policy::Policy;
use std::io::{self, Write};
use std::time::Instant;
use serde_wasm_bindgen::to_value;
use base64::{encode, decode};
use openpgp::policy::StandardPolicy;
use std::io::Cursor;
use anyhow::Result;
use openpgp::serialize::Serialize;




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
pub fn encrypt_message(public_key_b64: &str, plaintext: &str) -> Result<JsValue, JsValue> {
    let public_key_bytes = decode(public_key_b64).map_err(|e| e.to_string())?;
    let cert = Cert::from_bytes(&public_key_bytes).map_err(|e| e.to_string())?;

    let policy = StandardPolicy::new();
    let mut encrypted_data = Vec::new();
    encrypt(&policy, &mut encrypted_data, plaintext, &cert).map_err(|e| e.to_string())?;

    let encrypted_b64 = encode(&encrypted_data);
    Ok(JsValue::from_str(&encrypted_b64))
}


#[wasm_bindgen]
pub fn decrypt_message(private_key_b64: &str, encrypted_b64: &str) -> Result<JsValue, JsValue> {
    let private_key_bytes = decode(private_key_b64).map_err(|e| e.to_string())?;
    let cert = Cert::from_bytes(&private_key_bytes).map_err(|e| e.to_string())?;

    let encrypted_bytes = decode(encrypted_b64).map_err(|e| e.to_string())?;
    let policy = StandardPolicy::new();
    let mut decrypted_data = Cursor::new(Vec::new());
    decrypt(&policy, &mut decrypted_data, &encrypted_bytes, &cert).map_err(|e| e.to_string())?;

    let decrypted_data = decrypted_data.into_inner();
    let decrypted_text = String::from_utf8(decrypted_data).map_err(|e| e.to_string())?;

    Ok(JsValue::from_str(&decrypted_text))
}

/// Generates an encryption-capable key and measures the time taken.
pub fn generate_and_measure() -> openpgp::Result<()> {
    let start = Instant::now();
    let cert = generate()?;
    let duration = start.elapsed();

    println!("Key generation took: {:?}", duration);
    Ok(())
}

/// Encrypts a message and measures the time taken.
pub fn encrypt_and_measure(p: &dyn Policy, sink: &mut (dyn Write + Send + Sync),
                           plaintext: &str, recipient: &openpgp::Cert) -> openpgp::Result<()> {
    let start = Instant::now();
    encrypt(p, sink, plaintext, recipient)?;
    let duration = start.elapsed();

    println!("Encryption took: {:?}", duration);
    Ok(())
}

/// Decrypts a message and measures the time taken.
pub fn decrypt_and_measure(p: &dyn Policy, sink: &mut dyn Write,
                           ciphertext: &[u8], recipient: &openpgp::Cert) -> openpgp::Result<()> {
    let start = Instant::now();
    decrypt(p, sink, ciphertext, recipient)?;
    let duration = start.elapsed();

    println!("Decryption took: {:?}", duration);
    Ok(())
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

/// Encrypts the given message.
pub fn encrypt(p: &dyn Policy, sink: &mut (dyn Write + Send + Sync),
               plaintext: &str, recipient: &openpgp::Cert)
    -> openpgp::Result<()> {
    let recipients =
        recipient.keys().with_policy(p, None).supported().alive().revoked(false)
        .for_transport_encryption();

    // Start streaming an OpenPGP message.
    let message = Message::new(sink);

    // We want to encrypt a literal data packet.
    let message = Encryptor2::for_recipients(message, recipients)
        .build()?;

    // Emit a literal data packet.
    let mut message = LiteralWriter::new(message).build()?;

    // Encrypt the data.
    message.write_all(plaintext.as_bytes())?;

    // Finalize the OpenPGP message to make sure that all data is
    // written.
    message.finalize()?;

    Ok(())
}

/// Decrypts the given message.
pub fn decrypt(p: &dyn Policy,
               sink: &mut dyn Write, ciphertext: &[u8], recipient: &openpgp::Cert)
    -> openpgp::Result<()> {
    // Make a helper that feeds the recipient's secret key to the
    // decryptor.
    let helper = Helper {
        secret: recipient,
        policy: p,
    };

    // Now, create a decryptor with a helper using the given Certs.
    let mut decryptor = DecryptorBuilder::from_bytes(ciphertext)?
        .with_policy(p, None, helper)?;

    // Decrypt the data.
    io::copy(&mut decryptor, sink)?;

    Ok(())
}

struct Helper<'a> {
    secret: &'a openpgp::Cert,
    policy: &'a dyn Policy,
}

impl<'a> VerificationHelper for Helper<'a> {
    fn get_certs(&mut self, _ids: &[openpgp::KeyHandle])
                       -> openpgp::Result<Vec<openpgp::Cert>> {
        Ok(Vec::new())
    }

    fn check(&mut self, _structure: MessageStructure)
             -> openpgp::Result<()> {
        Ok(())
    }
}

impl<'a> DecryptionHelper for Helper<'a> {
    fn decrypt<D>(&mut self,
                  pkesks: &[openpgp::packet::PKESK],
                  _skesks: &[openpgp::packet::SKESK],
                  sym_algo: Option<SymmetricAlgorithm>,
                  mut decrypt: D)
                  -> openpgp::Result<Option<openpgp::Fingerprint>>
        where D: FnMut(SymmetricAlgorithm, &SessionKey) -> bool {
        let key = self.secret.keys().unencrypted_secret()
            .with_policy(self.policy, None)
            .for_transport_encryption().next().unwrap().key().clone();

        // The secret key is not encrypted.
        let mut pair = key.into_keypair()?;

        pkesks[0].decrypt(&mut pair, sym_algo)
            .map(|(algo, session_key)| decrypt(algo, &session_key));

        Ok(None)
    }
}



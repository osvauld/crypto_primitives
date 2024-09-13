use crate::types::{
    BasicFields, Credential, CredentialFields, EncryptedField, EncryptedFieldValue, Field,
    GeneratedKeys, MetaField, PublicKey, UrlMap,
};
use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce,
};
use anyhow::{anyhow, Result};
use argon2::password_hash::rand_core::OsRng;
use argon2::Argon2;
use base64::{decode, encode};
use lazy_static::lazy_static;
use openpgp::cert::{CertBuilder, CipherSuite};
use openpgp::crypto::KeyPair;
use openpgp::packet::key::PublicParts;
use openpgp::packet::key::UnspecifiedRole;
use openpgp::packet::Key;
use openpgp::parse::stream::MessageStructure;
use openpgp::parse::{stream::*, Parse};
use openpgp::policy::StandardPolicy;
use openpgp::serialize::stream::Message;
use openpgp::serialize::stream::*;
use openpgp::serialize::Marshal;
use openpgp::types::HashAlgorithm;
use openpgp::types::KeyFlags;
use openpgp::Cert;
use rand::RngCore;
use sequoia_openpgp::{self as openpgp};
use std::io::Write;
use std::sync::Mutex;
use std::{error::Error, io::Stderr};
lazy_static! {
    static ref GLOBAL_CONTEXT: Mutex<Option<Cert>> = Mutex::new(None);
}

pub fn is_context_set() -> bool {
    GLOBAL_CONTEXT.lock().unwrap().is_some()
}

pub fn clear_context() -> Result<()> {
    let mut context = GLOBAL_CONTEXT
        .lock()
        .map_err(|_| anyhow::anyhow!("Failed to lock global context"))?;
    *context = None;
    Ok(())
}

pub fn generate_certificate(username: &str) -> Result<openpgp::Cert> {
    println!("Generating certificate for user: {}", username);

    let (cert, _revocation) = CertBuilder::new()
        .add_userid(username)
        .set_cipher_suite(CipherSuite::Cv25519)
        .add_subkey(KeyFlags::empty().set_signing(), None, None)
        .add_subkey(KeyFlags::empty().set_storage_encryption(), None, None)
        .generate()?;

    println!("Certificate generated. Fingerprint: {}", cert.fingerprint());

    Ok(cert)
}
pub fn derive_key(password: &str, salt: &[u8; 16]) -> [u8; 32] {
    let mut output_key_material = [0u8; 32];
    Argon2::default()
        .hash_password_into(password.as_bytes(), salt, &mut output_key_material)
        .unwrap();
    // TODO: change unwrap
    output_key_material
}
pub fn encrypt_certificate(
    data: &[u8],
    password: &str,
    salt: &[u8; 16],
) -> Result<String, Box<dyn Error>> {
    let key = derive_key(password, salt);
    let cipher = Aes256Gcm::new_from_slice(&key).unwrap(); // Note: Using unwrap()
    let nonce = Nonce::from_slice(&salt[..12]);
    let encrypted_data = cipher
        .encrypt(nonce, data)
        .map_err(|e| Box::new(e) as Box<dyn Error>)?;

    Ok(encode(encrypted_data))
}

pub fn decrypt_certificate(
    encrypted_data: &[u8],
    salt: &[u8; 16],
    password: &str,
) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let key = derive_key(password, salt);

    let cipher = Aes256Gcm::new_from_slice(&key).map_err(|e| {
        let error_msg = format!("Failed to create cipher: {}", e);
        error_msg
    })?;

    let nonce = Nonce::from_slice(&salt[..12]);

    let decrypted_data = cipher.decrypt(nonce, encrypted_data).map_err(|e| {
        let error_msg = format!("Decryption failed: {}", e);
        error_msg
    })?;

    Ok(decrypted_data)
}

pub fn generate_keys(password: &str, username: &str) -> Result<GeneratedKeys, Box<dyn Error>> {
    let cert = generate_certificate(username)?;
    println!("Certificate loaded. Fingerprint: {}", cert.fingerprint());
    let mut salt = [0u8; 16];
    OsRng.fill_bytes(&mut salt);
    let mut cert_data = Vec::new();
    cert.as_tsk().serialize(&mut cert_data)?;
    let encrypted_private_key = encrypt_certificate(&cert_data, password, &salt)?;
    let public_key = get_public_key_armored(&cert)?;

    Ok(GeneratedKeys {
        private_key: encrypted_private_key,
        public_key,
        salt: encode(salt),
    })
}
pub fn gen_keys_without_password(username: &str) -> Result<GeneratedKeys, Box<dyn Error>> {
    let cert = generate_certificate(username)?;
    println!("Certificate loaded. Fingerprint: {}", cert.fingerprint());
    let mut cert_data = Vec::new();
    cert.as_tsk().serialize(&mut cert_data)?;
    let encoded_pirvate_key = encode(cert_data);
    let public_key = get_public_key_armored(&cert)?;

    Ok(GeneratedKeys {
        private_key: encoded_pirvate_key,
        public_key,
        salt: encode("".as_bytes()),
    })
}

pub fn get_public_key_armored(cert: &openpgp::Cert) -> Result<String> {
    let mut buf = Vec::new();
    cert.armored().serialize(&mut buf)?;
    Ok(String::from_utf8(buf)?)
}

pub fn decrypt_and_load_certificate(
    encrypted_cert_b64: &str,
    salt_b64: &str,
    passphrase: &str,
) -> Result<()> {
    // Decode the base64 encoded encrypted certificate and salt
    let encrypted_cert = base64::decode(encrypted_cert_b64)?;
    let salt = base64::decode(salt_b64)?;

    // Ensure salt is exactly 16 bytes
    if salt.len() != 16 {
        return Err(anyhow!("Salt must be exactly 16 bytes"));
    }
    let salt_array: [u8; 16] = salt
        .try_into()
        .map_err(|_| anyhow!("Failed to convert salt"))?;

    // Decrypt the certificate
    let decrypted_cert_bytes = decrypt_certificate(&encrypted_cert, &salt_array, passphrase)
        .map_err(|e| anyhow!("Failed to decrypt certificate: {}", e))?;

    // Load the certificate from the decrypted data
    let cert = Cert::from_bytes(&decrypted_cert_bytes)?;

    // Store the certificate in the global context
    let mut context = GLOBAL_CONTEXT
        .lock()
        .map_err(|_| anyhow!("Failed to lock global context"))?;
    *context = Some(cert);

    Ok(())
}

pub fn sign_message_with_stored_cert(message: &str) -> Result<String> {
    println!("Entering sign_message_with_stored_cert");

    // Fetch the stored certificate
    let cert = {
        let context = GLOBAL_CONTEXT
            .lock()
            .map_err(|_| anyhow!("Failed to lock global context"))?;
        match context.as_ref() {
            Some(c) => c.clone(),
            None => {
                println!("No certificate stored in context");
                return Err(anyhow!("No certificate stored in context"));
            }
        }
    };

    println!("Certificate loaded. Fingerprint: {}", cert.fingerprint());

    // Sign the message
    let policy = &StandardPolicy::new();

    let signing_key = cert
        .keys()
        .with_policy(policy, None)
        .for_signing()
        .unencrypted_secret()
        .next()
        .ok_or_else(|| anyhow!("No suitable signing key found"))?;

    let keypair = signing_key.key().clone().into_keypair()?;
    let mut signature = Vec::new();
    {
        let message_writer = Message::new(&mut signature);
        let mut signer = Signer::new(message_writer, keypair).detached().build()?;

        // Write the message directly to the signer
        signer.write_all(message.as_bytes())?;
        signer.finalize()?;
    }

    let mut armored_signature = Vec::new();
    {
        let mut armor_writer =
            openpgp::armor::Writer::new(&mut armored_signature, openpgp::armor::Kind::Signature)?;
        armor_writer.write_all(&signature)?;
        armor_writer.finalize()?;
    }

    println!("Message signed successfully");
    Ok(base64::encode(&armored_signature))
}

pub fn get_recipient(public_key: &str) -> Result<Key<PublicParts, UnspecifiedRole>, anyhow::Error> {
    // Parse the public key bytes into a Cert
    let cert = Cert::from_bytes(&public_key.as_bytes())?;

    // Create a policy for key selection
    let policy = &StandardPolicy::new();

    // Find a suitable encryption key
    let recipient = cert
        .keys()
        .with_policy(policy, None)
        .supported()
        .alive()
        .revoked(false)
        .for_storage_encryption()
        .next()
        .ok_or_else(|| anyhow!("No suitable encryption key found"))?;

    Ok(recipient.key().clone())
}

pub fn encrypt_fields_for_multiple_keys(
    public_keys: Vec<PublicKey>,
    fields: Vec<Field>,
) -> Result<Vec<EncryptedField>, Box<dyn std::error::Error>> {
    let mut encrypted_fields = Vec::new();
    for public_key in public_keys {
        let recipient = get_recipient(&public_key.public_key).unwrap();
        let mut fields_for_user = Vec::new();
        for field in &fields {
            let encrypted_value = encrypt_text(&recipient, &field.field_value)?;
            fields_for_user.push(Field {
                field_name: field.field_name.clone(),
                field_value: encrypted_value,
                field_type: field.field_type.clone(),
            });
        }

        encrypted_fields.push(EncryptedField {
            user_id: public_key.id,
            fields: fields_for_user,
        });
    }
    Ok(encrypted_fields)
}
pub fn encrypt_text(
    recipient: &Key<PublicParts, UnspecifiedRole>,
    text: &str,
) -> Result<String, anyhow::Error> {
    // Perform the encryption
    let mut encrypted = Vec::new();
    {
        let message = Message::new(&mut encrypted);
        let message = Encryptor2::for_recipients(message, vec![recipient]).build()?;
        let mut writer = LiteralWriter::new(message).build()?;
        writer.write_all(text.as_bytes())?;
        writer.finalize()?;
    }

    // Armor the encrypted data
    let mut armored = Vec::new();
    {
        let mut writer = openpgp::armor::Writer::new(&mut armored, openpgp::armor::Kind::Message)?;
        writer.write_all(&encrypted)?;
        writer.finalize()?;
    }

    // Convert to base64 for easy transmission
    Ok(base64::encode(&armored))
}

// --------------------------------------------------------------------------------------

pub fn decrypt_credentials(
    credentials: Vec<Credential>,
) -> Result<Vec<Credential>, Box<dyn Error>> {
    let context = GLOBAL_CONTEXT
        .lock()
        .map_err(|_| "Failed to lock global context.")?;

    let cert = context
        .as_ref()
        .ok_or("Certificate is not loaded in the context.")?
        .clone();

    let policy = &StandardPolicy::new();

    // Extract the decryption key from the certificate
    let decrypt_keys: Vec<_> = cert
        .keys()
        .unencrypted_secret()
        .with_policy(policy, None)
        .supported()
        .alive()
        .revoked(false)
        .for_storage_encryption()
        .collect();

    if decrypt_keys.is_empty() {
        return Err("No suitable decryption key found.".into());
    }

    let decrypt_key = decrypt_keys[0].key().clone();

    let mut decrypted_credentials = Vec::new();

    for credential in credentials {
        let mut decrypted_fields = Vec::new();

        for field in &credential.fields {
            let encrypted_bytes = base64::decode(&field.field_value)?;

            let decrypted_bytes = decrypt_message(policy, &decrypt_key, &encrypted_bytes)?;

            let decrypted_text = String::from_utf8(decrypted_bytes)?;

            decrypted_fields.push(MetaField {
                field_id: field.field_id.clone(),
                field_name: field.field_name.clone(),
                field_value: decrypted_text,
                field_type: field.field_type.clone(),
            });
        }

        let decrypted_credential = Credential {
            credential_id: credential.credential_id,
            fields: decrypted_fields,
            name: credential.name,
            description: credential.description,
            folder_id: credential.folder_id,
            credential_type: credential.credential_type,
            created_at: credential.created_at,
            created_by: credential.created_by,
            updated_at: credential.updated_at,
            access_type: credential.access_type,
        };

        decrypted_credentials.push(decrypted_credential);
    }

    Ok(decrypted_credentials)
}

pub fn decrypt_message(
    policy: &dyn openpgp::policy::Policy,
    decrypt_key: &openpgp::packet::Key<
        openpgp::packet::key::SecretParts,
        openpgp::packet::key::UnspecifiedRole,
    >,
    ciphertext: &[u8],
) -> Result<Vec<u8>, Box<dyn Error>> {
    let helper = DecryptionHelperStruct {
        decrypt_key: decrypt_key.clone(),
    };

    let mut decryptor =
        DecryptorBuilder::from_bytes(ciphertext)?.with_policy(policy, None, helper)?;

    let mut plaintext = Vec::new();
    std::io::copy(&mut decryptor, &mut plaintext)?;

    Ok(plaintext)
}

impl VerificationHelper for DecryptionHelperStruct {
    fn get_certs(
        &mut self,
        _ids: &[sequoia_openpgp::KeyHandle],
    ) -> Result<Vec<sequoia_openpgp::Cert>> {
        Ok(Vec::new())
    }

    fn check(&mut self, _structure: MessageStructure) -> Result<()> {
        Ok(())
    }
}
struct DecryptionHelperStruct {
    decrypt_key: openpgp::packet::Key<
        openpgp::packet::key::SecretParts,
        openpgp::packet::key::UnspecifiedRole,
    >,
}

impl DecryptionHelper for DecryptionHelperStruct {
    fn decrypt<D>(
        &mut self,
        pkesks: &[openpgp::packet::PKESK],
        _skesks: &[openpgp::packet::SKESK],
        sym_algo: Option<openpgp::types::SymmetricAlgorithm>,
        mut decrypt: D,
    ) -> openpgp::Result<Option<openpgp::Fingerprint>>
    where
        D: FnMut(openpgp::types::SymmetricAlgorithm, &openpgp::crypto::SessionKey) -> bool,
    {
        if pkesks.is_empty() {
            return Err(anyhow::anyhow!("No PKESKs provided"));
        }

        let mut pair = KeyPair::from(self.decrypt_key.clone().into_keypair()?);

        // Attempt to decrypt the first PKESK
        pkesks[0]
            .decrypt(&mut pair, sym_algo)
            .map(|(algo, session_key)| {
                decrypt(algo, &session_key);
            });

        Ok(None)
    }
}

pub fn decrypt_text(encrypted_text: String) -> Result<String, Box<dyn Error>> {
    // Access the global context to get the certificate
    let context = GLOBAL_CONTEXT
        .lock()
        .map_err(|_| "Failed to lock global context.")?;

    let cert = context
        .as_ref()
        .ok_or("Certificate is not loaded in the context.")?
        .clone();

    let policy = &StandardPolicy::new();

    // Extract the decryption key from the certificate
    let decrypt_keys: Vec<_> = cert
        .keys()
        .unencrypted_secret()
        .with_policy(policy, None)
        .supported()
        .alive()
        .revoked(false)
        .for_storage_encryption()
        .collect();

    if decrypt_keys.is_empty() {
        return Err("No suitable decryption key found.".into());
    }

    let decrypt_key = decrypt_keys[0].key().clone();

    // Decode the base64-encoded encrypted text
    let encrypted_bytes = decode(&encrypted_text)?;

    // Decrypt the message
    let decrypted_bytes = decrypt_message(policy, &decrypt_key, &encrypted_bytes)?;

    // Convert decrypted bytes to String
    let decrypted_text = String::from_utf8(decrypted_bytes)?;

    Ok(decrypted_text)
}

pub fn decrypt_fields(
    credentials: Vec<CredentialFields>,
) -> Result<Vec<CredentialFields>, Box<dyn Error>> {
    let context = GLOBAL_CONTEXT
        .lock()
        .map_err(|_| "Failed to lock global context.")?;

    let cert = context
        .as_ref()
        .ok_or("Certificate is not loaded in the context.")?
        .clone();

    let policy = &StandardPolicy::new();

    // Extract the decryption key from the certificate
    let decrypt_keys: Vec<_> = cert
        .keys()
        .unencrypted_secret()
        .with_policy(policy, None)
        .supported()
        .alive()
        .revoked(false)
        .for_storage_encryption()
        .collect();

    if decrypt_keys.is_empty() {
        return Err("No suitable decryption key found.".into());
    }

    let decrypt_key = decrypt_keys[0].key().clone();

    let mut decrypted_credentials = Vec::new();

    for credential in credentials {
        let mut decrypted_fields = Vec::new();

        for field in credential.fields {
            let encrypted_bytes = match decode(&field.field_value) {
                Ok(bytes) => bytes,
                Err(_) => continue,
            };

            let decrypted_bytes = match decrypt_message(policy, &decrypt_key, &encrypted_bytes) {
                Ok(bytes) => bytes,
                Err(_) => continue,
            };

            let decrypted_text = match String::from_utf8(decrypted_bytes) {
                Ok(text) => text,
                Err(_) => continue,
            };

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

    Ok(decrypted_credentials)
}

pub fn encrypt_fields(fields: Vec<BasicFields>, public_key: &str) -> Result<Vec<BasicFields>> {
    // Get the recipient key using get_recipient function
    let recipient_key = get_recipient(public_key)?;

    let mut encrypted_fields = Vec::new();

    for field in fields {
        // Use encrypt_text function to encrypt the field value
        let encrypted_value = encrypt_text(&recipient_key, &field.field_value)?;

        encrypted_fields.push(BasicFields {
            field_id: field.field_id,
            field_value: encrypted_value,
        });
    }

    Ok(encrypted_fields)
}

pub fn sign_and_hash_message(message: &str) -> Result<String, Box<dyn Error>> {
    let hash_text = hash_text_sha512(message).unwrap();
    let hash_base64 = base64::encode(&hash_text);
    let signature = sign_message_with_stored_cert(&hash_base64)?;
    Ok((signature))
}

pub fn hash_text_sha512(text: &str) -> Result<Vec<u8>, String> {
    let mut ctx = HashAlgorithm::SHA512
        .context()
        .map_err(|e| format!("Failed to create hash context: {}", e))?;

    ctx.update(text.as_bytes());

    let mut digest = vec![0; ctx.digest_size()];
    ctx.digest(&mut digest)
        .map_err(|e| format!("Failed to compute digest: {}", e))?;

    Ok(digest)
}

pub fn encrypt_field_value(
    field_value: &str,
    public_keys: Vec<PublicKey>,
) -> Result<Vec<EncryptedFieldValue>, Box<dyn Error>> {
    let mut results = Vec::new();
    for public_key in public_keys {
        let recipient = get_recipient(&public_key.public_key)
            .map_err(|e| format!("Failed to get recipient: {}", e))?;
        let encrypted_text = encrypt_text(&recipient, field_value).unwrap();
        results.push(EncryptedFieldValue {
            id: public_key.id,
            field_value: encrypted_text,
        })
    }
    Ok(results)
}

pub fn decrypt_urls(url_map: Vec<UrlMap>) -> Result<Vec<UrlMap>, Box<dyn Error>> {
    let mut results = Vec::new();
    for url in url_map {
        let decrypted_url = decrypt_text(url.value).unwrap();
        results.push(UrlMap {
            value: decrypted_url,
            credentialId: url.credentialId,
        })
    }
    Ok(results)
}

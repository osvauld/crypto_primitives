use crate::crypto_core::{
    decrypt_certificate, decrypt_message, encrypt_certificate, encrypt_text, generate_certificate,
    get_decryption_key, get_public_key_armored, get_recipient, get_salt_arr, get_signing_keypair,
    hash_text_sha512, sign_message,
};
use crate::errors::CryptoUtilsError;
use crate::types::{
    BasicFields, Credential, CredentialFields, EncryptedField, EncryptedFieldValue, Field,
    GeneratedKeys, MetaField, PublicKey, UrlMap,
};
use anyhow::{anyhow, Result};
use argon2::password_hash::rand_core::OsRng;
use base64::encode;
use lazy_static::lazy_static;
use openpgp::{policy::StandardPolicy, serialize::Marshal, Cert};
use rand::RngCore;
use sequoia_openpgp::{self as openpgp};
use std::error::Error;
use std::str::FromStr;
use std::sync::Mutex;
lazy_static! {
    static ref GLOBAL_CONTEXT: Mutex<Option<Cert>> = Mutex::new(None);
}

pub fn is_context_set() -> bool {
    GLOBAL_CONTEXT.lock().unwrap().is_some()
}

pub fn clear_context() -> Result<()> {
    let mut context = GLOBAL_CONTEXT
        .lock()
        .map_err(|e| CryptoUtilsError::ContextLockError(e.to_string()))?;
    *context = None;
    Ok(())
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

pub fn decrypt_and_load_certificate(
    encrypted_cert_b64: &str,
    salt_b64: &str,
    passphrase: &str,
) -> Result<(), CryptoUtilsError> {
    let cert = decrypt_certificate(encrypted_cert_b64, salt_b64, passphrase)
        .map_err(|e| CryptoUtilsError::CertificateDecryptionError(e.to_string()))?;

    let mut context = GLOBAL_CONTEXT
        .lock()
        .map_err(|e| CryptoUtilsError::ContextLockError(e.to_string()))?;
    *context = Some(cert);

    Ok(())
}

pub fn get_stored_certificate() -> Result<Cert> {
    let context = GLOBAL_CONTEXT
        .lock()
        .map_err(|e| CryptoUtilsError::ContextLockError(e.to_string()))?;

    context
        .as_ref()
        .cloned()
        .ok_or_else(|| anyhow!(CryptoUtilsError::NoCertificateError))
}

pub fn sign_message_with_stored_cert(message: &str) -> Result<String, CryptoUtilsError> {
    println!("Entering sign_message_with_stored_cert");

    let cert = get_stored_certificate().map_err(|_| CryptoUtilsError::NoCertificateError)?;
    let keypair =
        get_signing_keypair(&cert).map_err(|e| CryptoUtilsError::SigningKeyError(e.to_string()))?;

    let signature = sign_message(&keypair, message)
        .map_err(|e| CryptoUtilsError::SigningError(e.to_string()))?;

    Ok(encode(signature))
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

pub fn decrypt_credentials(
    credentials: Vec<Credential>,
) -> Result<Vec<Credential>, Box<dyn Error>> {
    let cert = get_stored_certificate()?;
    let decrypt_key = get_decryption_key(&cert)?;
    let mut decrypted_credentials = Vec::new();
    let policy = StandardPolicy::new();

    for credential in credentials {
        let mut decrypted_fields = Vec::new();

        for field in &credential.fields {
            let decrypted_bytes =
                decrypt_message(&policy, &decrypt_key, field.field_value.as_bytes())?;

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

pub fn decrypt_text(encrypted_text: String) -> Result<String, Box<dyn Error>> {
    // Access the global context to get the certificate
    let cert = get_stored_certificate()?;
    let policy = &StandardPolicy::new();

    // Extract the decryption key from the certificate
    let decrypt_key = get_decryption_key(&cert)?;
    let decrypted_bytes = decrypt_message(policy, &decrypt_key, encrypted_text.as_bytes())?;

    // Convert decrypted bytes to String
    let decrypted_text = String::from_utf8(decrypted_bytes)?;

    Ok(decrypted_text)
}

pub fn decrypt_fields(
    credentials: Vec<CredentialFields>,
) -> Result<Vec<CredentialFields>, Box<dyn Error>> {
    let policy = &StandardPolicy::new();

    let cert = get_stored_certificate()?;
    let decrypt_key = get_decryption_key(&cert)?;
    // Extract the decryption key from the certificate

    let mut decrypted_credentials = Vec::new();

    for credential in credentials {
        let mut decrypted_fields = Vec::new();

        for field in credential.fields {
            let decrypted_bytes =
                match decrypt_message(policy, &decrypt_key, field.field_value.as_bytes()) {
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
    let hash_base64 = encode(&hash_text);
    let signature = sign_message_with_stored_cert(&hash_base64)?;
    Ok(signature)
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

pub fn import_certificate(
    cert_string: String,
    passphrase: String,
) -> Result<GeneratedKeys, Box<dyn Error>> {
    let cert = Cert::from_str(&cert_string)?;
    let public_key = get_public_key_armored(&cert)?;
    let mut salt = [0u8; 16];
    OsRng.fill_bytes(&mut salt);
    let mut cert_data = Vec::new();
    cert.as_tsk().serialize(&mut cert_data)?;
    let enc_priv_key = encrypt_certificate(&cert_data, &passphrase, &salt)?;
    Ok(GeneratedKeys {
        private_key: enc_priv_key,
        public_key,
        salt: encode(salt),
    })
}

pub fn export_certificate(passphrase: &str, enc_pvt_key: &str, salt: &str) -> Result<String> {
    let cert = decrypt_certificate(enc_pvt_key, salt, passphrase)
        .map_err(|e| CryptoUtilsError::CertificateDecryptionError(e.to_string()))?;
    let mut armored = Vec::new();
    cert.as_tsk().armored().serialize(&mut armored)?;
    Ok(String::from_utf8(armored)?)
}

pub fn change_certificate_password(
    encrypted_cert_b64: &str,
    salt_b64: &str,
    old_password: &str,
    new_password: &str,
) -> Result<String, Box<dyn Error>> {
    let cert = decrypt_certificate(encrypted_cert_b64, salt_b64, old_password)
        .map_err(|e| CryptoUtilsError::CertificateDecryptionError(e.to_string()))?;

    let mut cert_data = Vec::new();
    cert.as_tsk().serialize(&mut cert_data)?;
    let salt_array = get_salt_arr(salt_b64)?;

    // Re-encrypt the certificate with the new password
    let new_encrypted_cert = encrypt_certificate(&cert_data, new_password, &salt_array)?;

    Ok(new_encrypted_cert)
}

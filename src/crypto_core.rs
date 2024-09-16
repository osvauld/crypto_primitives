use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce,
};
use anyhow::{anyhow, Result};
use argon2::Argon2;
use base64::encode;
use openpgp::{
    cert::{CertBuilder, CipherSuite},
    crypto::KeyPair,
    packet::{
        key::{PublicParts, SecretParts, UnspecifiedRole},
        Key,
    },
    parse::{
        stream::{MessageStructure, *},
        Parse,
    },
    policy::StandardPolicy,
    serialize::{
        stream::{Message, *},
        Marshal,
    },
    types::{HashAlgorithm, KeyFlags},
    Cert,
};
use sequoia_openpgp::{self as openpgp};
use std::error::Error;
use std::io::Write;

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

pub fn get_public_key_armored(cert: &openpgp::Cert) -> Result<String> {
    let mut buf = Vec::new();
    cert.armored().serialize(&mut buf)?;
    Ok(String::from_utf8(buf)?)
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

pub fn get_signing_keypair(cert: &Cert) -> Result<KeyPair> {
    println!("Fetching signing keypair");
    println!("Certificate loaded. Fingerprint: {}", cert.fingerprint());

    let policy = &StandardPolicy::new();
    let signing_key = cert
        .keys()
        .with_policy(policy, None)
        .for_signing()
        .unencrypted_secret()
        .next()
        .ok_or_else(|| anyhow!("No suitable signing key found"))?;

    let keypair = signing_key.key().clone().into_keypair()?;
    Ok(keypair)
}

pub fn get_decryption_key(
    cert: &Cert,
) -> Result<openpgp::packet::Key<SecretParts, UnspecifiedRole>> {
    let policy = &StandardPolicy::new();

    let decrypt_key = cert
        .keys()
        .unencrypted_secret()
        .with_policy(policy, None)
        .supported()
        .alive()
        .revoked(false)
        .for_storage_encryption()
        .next()
        .ok_or_else(|| anyhow!("No suitable decryption key found"))?;

    Ok(decrypt_key.key().clone())
}

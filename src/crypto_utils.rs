use aes_gcm::{
    aead::{Aead, Error as AeadError, KeyInit},
    Aes256Gcm, Nonce,
};
use anyhow::{anyhow, Result};
use argon2::password_hash::rand_core::OsRng;
use argon2::Argon2;
use base64::{decode, encode};
use lazy_static::lazy_static;
use openpgp::cert::{CertBuilder, CipherSuite};
use openpgp::crypto::KeyPair;
use openpgp::crypto::Password;
use openpgp::parse::stream::MessageStructure;
use openpgp::parse::{stream::*, Parse};
use openpgp::policy::Policy;
use openpgp::policy::StandardPolicy;
use openpgp::serialize::stream::Message;
use openpgp::serialize::stream::*;
use openpgp::serialize::Marshal;
use openpgp::types::HashAlgorithm;
use openpgp::types::KeyFlags;
use openpgp::Cert;
use rand::RngCore;
use sequoia_openpgp::{self as openpgp, policy};
use std::io::Cursor;
use std::io::Write;
use std::sync::Mutex;
lazy_static! {
    static ref GLOBAL_CONTEXT: Mutex<Option<Cert>> = Mutex::new(None);
}
use std::{error::Error, io::Stderr};

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

pub struct GeneratedKeys {
    pub private_key: String,
    pub public_key: String,
    pub salt: String,
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
pub fn generate_certificate_without_password(
    flags: KeyFlags,
    username: &str,
) -> openpgp::Result<openpgp::Cert> {
    let (cert, _revocation) = CertBuilder::new()
        .add_userid(username)
        .set_cipher_suite(CipherSuite::Cv25519) // This specifies ECC keys with Curve25519
        .add_subkey(flags, None, None)
        .generate()?;
    Ok(cert)
}

impl<'a> VerificationHelper for Helper<'a> {
    fn get_certs(&mut self, _ids: &[openpgp::KeyHandle]) -> openpgp::Result<Vec<openpgp::Cert>> {
        Ok(Vec::new())
    }

    fn check(&mut self, _structure: MessageStructure) -> openpgp::Result<()> {
        Ok(())
    }
}
/// Encrypts the given message.
pub fn encrypt(
    p: &dyn Policy,
    sink: &mut (dyn Write + Send + Sync),
    plaintext: &str,
    recipient: &openpgp::Cert,
) -> openpgp::Result<()> {
    let recipients = recipient
        .keys()
        .with_policy(p, None)
        .supported()
        .alive()
        .revoked(false)
        .for_storage_encryption();

    // Start streaming an OpenPGP message.
    let message = Message::new(sink);

    // We want to encrypt a literal data packet.
    let message = Encryptor2::for_recipients(message, recipients).build()?;

    // Emit a literal data packet.
    let mut message = LiteralWriter::new(message).build()?;

    // Encrypt the data.
    message.write_all(plaintext.as_bytes())?;

    // Finalize the OpenPGP message to make sure that all data is
    // written.
    message.finalize()?;

    Ok(())
}
pub fn decrypt_message(
    p: &dyn Policy,
    sk: &openpgp::packet::Key<
        openpgp::packet::key::SecretParts,
        openpgp::packet::key::UnspecifiedRole,
    >,
    ciphertext: &[u8],
) -> openpgp::Result<Vec<u8>> {
    let helper = Helper {
        secret: &sk,
        policy: p,
    };

    // Parse the message and create a decryptor with the helper.
    let mut decryptor = DecryptorBuilder::from_bytes(ciphertext)?.with_policy(p, None, helper)?;

    // Read the decrypted data
    let mut plaintext = Cursor::new(Vec::new());

    // Copy the decrypted data to the plaintext Vec<u8>
    std::io::copy(&mut decryptor, &mut plaintext)?;

    // Get the plaintext Vec<u8> from the Cursor
    let plaintext = plaintext.into_inner();
    Ok(plaintext)
}

struct Helper<'a> {
    secret: &'a openpgp::packet::Key<
        openpgp::packet::key::SecretParts,
        openpgp::packet::key::UnspecifiedRole,
    >,
    policy: &'a dyn Policy,
}

impl<'a> openpgp::parse::stream::DecryptionHelper for Helper<'a> {
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
        // The secret key is already decrypted.
        let mut pair = KeyPair::from(self.secret.clone().into_keypair()?);

        pkesks[0]
            .decrypt(&mut pair, sym_algo)
            .map(|(algo, session_key)| decrypt(algo, &session_key));

        Ok(None)
    }
}

pub fn decrypt_private_key(
    private_key_b64: &str,
    password: &str,
    for_signing: bool,
) -> Result<
    openpgp::packet::Key<openpgp::packet::key::SecretParts, openpgp::packet::key::UnspecifiedRole>,
    Box<dyn Error>,
> {
    let private_key_bytes = decode(private_key_b64)?;
    let cert = Cert::from_bytes(&private_key_bytes)?;
    let p = &StandardPolicy::new();

    // Get the secret key from the certificate
    let keypair = if for_signing {
        cert.keys()
            .with_policy(p, None)
            .secret()
            .for_signing()
            .nth(0)
            .ok_or_else(|| "No suitable key found in Cert.")?
            .key()
            .clone()
    } else {
        cert.keys()
            .with_policy(p, None)
            .secret()
            .for_storage_encryption()
            .nth(0)
            .ok_or_else(|| "No suitable key found in Cert.")?
            .key()
            .clone()
    };

    // Convert the password to a SessionKey
    let password = Password::from(password);

    // Decrypt the secret key with the password
    let decrypted_keypair = keypair.decrypt_secret(&password)?;

    // The keypair now contains the decrypted secret key
    // You can use it to perform cryptographic operations

    Ok(decrypted_keypair)
}

pub fn get_pub_key_str(private_key_b64: &str) -> Result<String, Box<dyn Error>> {
    let private_key_bytes = decode(private_key_b64)?;

    let cert = Cert::from_bytes(&private_key_bytes)?;

    let mut enc_public_key = Vec::new();
    cert.armored().serialize(&mut enc_public_key)?;
    // Get the primary key from the certificate
    let base64_enc_public_key = encode(&enc_public_key);
    Ok(base64_enc_public_key)
}

pub fn sign_message_with_keypair(message: &str, keypair: KeyPair) -> Result<String, String> {
    let mut signed_message = Vec::new();
    let message_writer = Message::new(&mut signed_message);

    let mut signer = Signer::new(message_writer, keypair)
        .detached()
        .build()
        .map_err(|e| e.to_string())?;

    signer
        .write_all(message.as_bytes())
        .map_err(|_| "Failed to write message to signer.")?;
    signer
        .finalize()
        .map_err(|_| "Failed to finalize signer.")?;

    let mut armored_signature = Vec::new();
    let mut armor_writer =
        openpgp::armor::Writer::new(&mut armored_signature, openpgp::armor::Kind::Signature)
            .map_err(|e| e.to_string())?;

    armor_writer
        .write_all(&signed_message)
        .map_err(|_| "Failed to write signature.")?;
    armor_writer
        .finalize()
        .map_err(|_| "Failed to finalize armored writer.")?;

    let base64_encoded_signature = base64::encode(armored_signature);
    Ok(base64_encoded_signature)
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

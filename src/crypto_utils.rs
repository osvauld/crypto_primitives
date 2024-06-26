// lib.rs

use base64::{decode, encode};
use openpgp::cert::{CertBuilder, CipherSuite};
use openpgp::crypto::KeyPair;
use openpgp::crypto::Password;
use openpgp::packet::Key;
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
use sequoia_openpgp as openpgp;
use std::error::Error;
use std::io::Cursor;
use std::io::Write;
use web_sys::console;

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

pub fn generate_certificate(
    flags: KeyFlags,
    password: &str,
    username: &str,
) -> openpgp::Result<openpgp::Cert> {
    let passphrase = Password::from(password);

    let (cert, _revocation) = CertBuilder::new()
        .add_userid(username)
        .set_cipher_suite(CipherSuite::Cv25519) // This specifies ECC keys with Curve25519
        .add_subkey(flags, None, None)
        .set_password(Some(passphrase))
        .generate()?;
    Ok(cert)
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

pub fn decrypt_message(
    p: &dyn Policy,
    sk: &Key<openpgp::packet::key::SecretParts, openpgp::packet::key::UnspecifiedRole>,
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
    secret: &'a Key<openpgp::packet::key::SecretParts, openpgp::packet::key::UnspecifiedRole>,
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
    Key<openpgp::packet::key::SecretParts, openpgp::packet::key::UnspecifiedRole>,
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

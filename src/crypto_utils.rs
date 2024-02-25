// lib.rs
use base64::decode;
use openpgp::cert::{CertBuilder, CipherSuite};
use openpgp::crypto::KeyPair;
use openpgp::crypto::Password;
use openpgp::packet::Key;
use openpgp::parse::stream::MessageStructure;
use openpgp::parse::{stream::*, Parse};
use openpgp::policy::Policy;
use openpgp::policy::StandardPolicy;
use openpgp::serialize::stream::*;
use openpgp::types::KeyFlags;
use openpgp::Cert;
use sequoia_openpgp as openpgp;
use std::error::Error;
use std::io::Cursor;
use std::io::Write;
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

pub fn generate_cert_for_usage(flags: KeyFlags, password: &str) -> openpgp::Result<openpgp::Cert> {
    let passphrase = Password::from(password);

    let (cert, _revocation) = CertBuilder::new()
        .add_userid("someone@example.org")
        .set_cipher_suite(CipherSuite::Cv25519) // This specifies ECC keys with Curve25519
        .add_subkey(flags, None, None)
        .set_password(Some(passphrase))
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

// extractPUb{

//     let mut armor_writer =
//         openpgp::armor::Writer::new(&mut output, openpgp::armor::Kind::PublicKey)
//             .map_err(|_| JsValue::from_str("Failed to decrypt signing private key."))?;
//     sequoia_openpgp::serialize::Marshal::serialize(public_key, &mut armor_writer)
//         .map_err(|_| JsValue::from_str("Failed to serialize public key."))?;

//     armor_writer
//         .finalize()
//         .map_err(|_| JsValue::from_str("Failed to decrypt signing private key."))?;
//     let armored_str = String::from_utf8(output)
//         .map_err(|_| JsValue::from_str("Failed to convert armored data to string."))?;

//     // Encode the armored string into a base64 string
//     let base64_armored_str = base64::encode(&armored_str);

//     // Return the base64-encoded armored public key
//     Ok(to_value(&serde_json::json!({
//         "public_key": base64_armored_str,
//     }))
//     .map_err(|err| JsValue::from_str(&err.to_string()))?)
// }

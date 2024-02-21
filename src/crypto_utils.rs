// lib.rs
use sequoia_openpgp as openpgp;
use openpgp::types:: KeyFlags;
use openpgp::serialize::stream::*;
use openpgp::parse::{Parse, stream::*};
use openpgp::policy::Policy;
use openpgp::crypto::Password;
use openpgp::cert::{CertBuilder, CipherSuite};
use std::io:: Write;
use openpgp::parse::stream::MessageStructure;
use openpgp::crypto::KeyPair;
use openpgp::packet::Key;
use std::io::Cursor;


/// Encrypts the given message.
pub fn encrypt(p: &dyn Policy, sink: &mut (dyn Write + Send + Sync),
               plaintext: &str, recipient: &openpgp::Cert)
    -> openpgp::Result<()> {
    let recipients =
        recipient.keys().with_policy(p, None).supported().alive().revoked(false)
        .for_storage_encryption();

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
    fn get_certs(&mut self, _ids: &[openpgp::KeyHandle])
                       -> openpgp::Result<Vec<openpgp::Cert>> {
        Ok(Vec::new())
    }

    fn check(&mut self, _structure: MessageStructure)
             -> openpgp::Result<()> {
        Ok(())
    }
}







pub fn decrypt_message(p: &dyn Policy, sk: &Key<openpgp::packet::key::SecretParts, openpgp::packet::key::UnspecifiedRole>, ciphertext: &[u8]) -> openpgp::Result<Vec<u8>> {
    let helper = Helper {
        secret: &sk,
        policy: p,
    };

    // Parse the message and create a decryptor with the helper.
    let mut decryptor = DecryptorBuilder::from_bytes( ciphertext)?
        .with_policy(p, None, helper)?;

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
    fn decrypt<D>(&mut self,
                  pkesks: &[openpgp::packet::PKESK],
                  _skesks: &[openpgp::packet::SKESK],
                  sym_algo: Option<openpgp::types::SymmetricAlgorithm>,
                  mut decrypt: D)
                  -> openpgp::Result<Option<openpgp::Fingerprint>>
        where D: FnMut(openpgp::types::SymmetricAlgorithm, &openpgp::crypto::SessionKey) -> bool {
        // The secret key is already decrypted.
        let mut pair = KeyPair::from(self.secret.clone().into_keypair()?);

        pkesks[0].decrypt(&mut pair, sym_algo)
            .map(|(algo, session_key)| decrypt(algo, &session_key));

        Ok(None)
    }
}
// lib.rs
use sequoia_openpgp as openpgp;
use openpgp::types::{SymmetricAlgorithm, KeyFlags,};
use openpgp::serialize::stream::*;
use openpgp::parse::{Parse, stream::*};
use openpgp::policy::Policy;
use openpgp::crypto::{Password, SessionKey, S2K, random };
use openpgp::cert::{CertBuilder, CipherSuite};
use std::io::{self, Write};
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
            .for_storage_encryption().next().unwrap().key().clone();

        // The secret key is not encrypted.
        let mut pair = key.into_keypair()?;

        pkesks[0].decrypt(&mut pair, sym_algo)
            .map(|(algo, session_key)| decrypt(algo, &session_key));

        Ok(None)
    }
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



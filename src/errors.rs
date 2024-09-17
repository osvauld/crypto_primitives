use std::io;
use thiserror::Error;
#[derive(Error, Debug)]
pub enum AesError {
    #[error("Key derivation failed: {0}")]
    KeyDerivationError(String),

    #[error("Cipher creation failed: {0}")]
    CipherCreationError(String),

    #[error("Encryption failed: {0}")]
    EncryptionError(String),

    #[error("Decryption failed: {0}")]
    DecryptionError(String),

    #[error("Failed to parse certificate: {0}")]
    CertificateParseError(String),
    #[error("Failed to decode: {0}")]
    Base64DecodeError(String),
    #[error("Failed to convert salt: {0}")]
    SaltConversionError(String),
    #[error("Invalid salt length")]
    InvalidSaltLength,
}

#[derive(Error, Debug)]
pub enum PgpError {
    #[error("Failed to create message: {0}")]
    MessageCreationError(String),

    #[error("Failed to create hash context: {0}")]
    HashContextCreationError(String),

    #[error("Failed to compute digest: {0}")]
    DigestComputationError(String),

    #[error("Failed to create encryptor: {0}")]
    EncryptorCreationError(String),

    #[error("Failed to create literal writer: {0}")]
    LiteralWriterCreationError(String),

    #[error("Failed to finalize encryption: {0}")]
    FinalizationError(String),

    #[error("Failed to create armor writer: {0}")]
    ArmorWriterCreationError(String),

    #[error("Failed to create decryptor: {0}")]
    DecryptorCreationError(String),

    #[error("Failed to apply policy: {0}")]
    PolicyApplicationError(String),

    #[error("Decryption failed: {0}")]
    DecryptionError(String),
    #[error("No suitable encryption key found")]
    NoSuitableEncryptionKeyError,

    #[error("No suitable signing key found")]
    NoSuitableSigningKeyError,

    #[error("No suitable decryption key found")]
    NoSuitableDecryptionKeyError,

    #[error("Key pair creation failed: {0}")]
    KeyPairCreationError(String),

    #[error("IO error: {0}")]
    IoError(#[from] io::Error),

    #[error("Failed to create signer: {0}")]
    SignerCreationError(String),
    #[error("Failed to write message: {0}")]
    MessageWriteError(String),
    #[error("Failed to finalize signature: {0}")]
    SignatureFinalizationError(String),
    #[error("Failed to write signature: {0}")]
    SignatureWriteError(String),
    #[error("Failed to finalize armored signature: {0}")]
    ArmorFinalizationError(String),
    #[error("Failed to parse certificate: {0}")]
    CertificateParseError(String),
}

#[derive(Error, Debug)]
pub enum CryptoUtilsError {
    #[error("No certificate stored in context")]
    NoCertificateError,

    #[error("Failed to lock global context: {0}")]
    ContextLockError(String),

    #[error("Missing field value")]
    MissingFieldValue,

    #[error("Invalid salt length")]
    InvalidSaltLength,

    #[error("Failed to get signing key: {0}")]
    SigningKeyError(String),
    #[error("Failed to sign message: {0}")]
    SigningError(String),
    #[error("UTF-8 conversion error: {0}")]
    Utf8ConversionError(String),
    #[error("Failed to get decryption key: {0}")]
    CertificateDecryptionError(String),
}

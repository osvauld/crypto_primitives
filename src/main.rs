mod crypto_utils;
mod types;

use crypto_utils::{
    decrypt_and_load_certificate, decrypt_credentials, decrypt_fields,
    encrypt_fields_for_multiple_keys, generate_keys,
};
use types::{
    BasicFields, Credential, CredentialFields, EncryptedField, Field, MetaField, PublicKey,
};

fn main() {
    // Generate keys for the user
    let password = "my_secure_password";
    let username = "test_user";

    let keys = generate_keys(password, username).unwrap();

    // Decrypt and load the certificate into GLOBAL_CONTEXT
    decrypt_and_load_certificate(&keys.private_key, &keys.salt, password).unwrap();

    // Prepare sample public keys
    let public_keys = vec![PublicKey {
        id: username.to_string(),
        public_key: keys.public_key.clone(),
    }];

    // Prepare sample fields to encrypt
    let fields = vec![
        Field {
            field_name: Some("Field1".to_string()),
            field_value: "SecretValue1".to_string(),
            field_type: Some("String".to_string()),
        },
        Field {
            field_name: Some("Field2".to_string()),
            field_value: "SecretValue2".to_string(),
            field_type: Some("String".to_string()),
        },
    ];

    // Encrypt fields for multiple public keys
    let encrypted_fields =
        encrypt_fields_for_multiple_keys(public_keys.clone(), fields.clone()).unwrap();

    println!("Encrypted Fields: {:?}", encrypted_fields);

    // Now, we need to transform EncryptedField into the format expected by decrypt_credentials
    // Prepare credentials for decryption
    // let credentials: Vec<Credential> = encrypted_fields
    //     .into_iter()
    //     .map(|ef| {
    //         let meta_fields: Vec<MetaField> = ef
    //             .fields
    //             .into_iter()
    //             .map(|field| MetaField {
    //                 field_id: field.field_name.clone().unwrap_or_default(),
    //                 field_name: field.field_name.clone(),
    //                 field_value: field.field_value.clone(),
    //                 field_type: field.field_type.clone(),
    //             })
    //             .collect();

    //         Credential {
    //             credential_id: ef.user_id.clone(),
    //             fields: meta_fields,
    //             name: "Test Credential".to_string(),
    //             description: "A test credential".to_string(),
    //             folder_id: "folder1".to_string(),
    //             credential_type: "type1".to_string(),
    //             created_at: "now".to_string(),
    //             created_by: "me".to_string(),
    //             updated_at: "now".to_string(),
    //             access_type: "read".to_string(),
    //         }
    //     })
    //     .collect();

    // // Now call decrypt_credentials
    // let decrypted_credentials = decrypt_credentials(credentials).unwrap();

    // println!("Decrypted Credentials: {:?}", decrypted_credentials);
    //

    // Transform EncryptedField into CredentialFields for decrypt_fields
    let credential_fields: Vec<CredentialFields> = encrypted_fields
        .into_iter()
        .map(|ef| {
            let basic_fields: Vec<BasicFields> = ef
                .fields
                .into_iter()
                .map(|field| BasicFields {
                    field_id: field.field_name.clone().unwrap_or_default(),
                    field_value: field.field_value.clone(),
                })
                .collect();

            CredentialFields {
                credential_id: ef.user_id.clone(),
                fields: basic_fields,
            }
        })
        .collect();

    // Now call decrypt_fields
    let decrypted_credentials = decrypt_fields(credential_fields).unwrap();

    println!("Decrypted Credentials: {:?}", decrypted_credentials);
}

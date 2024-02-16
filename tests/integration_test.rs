
// tests/integration_test.rs

#[cfg(test)]
mod tests {
    use rust_openpgp_wasm::{generate_openpgp_keypair, encrypt_data_for_js};
    use wasm_bindgen::JsValue;

    #[test]
    fn test_generate_keypair_and_encrypt() {
        let keypair_result = generate_openpgp_keypair();
        assert!(keypair_result.is_ok());

        let keypair = keypair_result.unwrap();
        let public_key = keypair.as_object().unwrap().get("publicKey").unwrap().as_string().unwrap();

        let texts = vec!["test".to_string()];
        let encryption_result = encrypt_data_for_js(JsValue::from_str(&public_key), texts);
        assert!(encryption_result.is_ok());

        let encryption_data = encryption_result.unwrap();
        println!("Encryption Data: {:?}", encryption_data);
    }
}

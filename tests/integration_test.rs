#[cfg(test)]
use sequoia_openpgp as openpgp;
use rust_openpgp_wasm::{generate_and_measure, encrypt_and_measure, decrypt_and_measure, generate};
mod tests {
    use super::*;
    use openpgp::policy::StandardPolicy;
    use std::io::Cursor;

    #[test]
    fn benchmark_operations() -> openpgp::Result<()> {
        let p = StandardPolicy::new();

        generate_and_measure()?;

        let key = generate()?;
        let mut ciphertext = Vec::new();
        let mut cursor = Cursor::new(&mut ciphertext);

        encrypt_and_measure(&p, &mut cursor, "Hello, world!", &key)?;

        let mut plaintext = Vec::new();
        let mut cursor = Cursor::new(&mut plaintext);

        decrypt_and_measure(&p, &mut cursor, &ciphertext, &key)?;

        Ok(())
    }
}



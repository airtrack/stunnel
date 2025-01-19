use std::{fs::File, io::Write};

use rcgen::{generate_simple_self_signed, CertifiedKey};

fn main() {
    let subject_alt_names = vec!["stunnel".to_string()];
    let CertifiedKey { cert, key_pair } = generate_simple_self_signed(subject_alt_names).unwrap();

    let mut cert_file = File::create("stunnel_cert.pem").unwrap();
    cert_file.write(cert.pem().as_bytes()).unwrap();

    let mut priv_file = File::create("private_key.pem").unwrap();
    priv_file
        .write(key_pair.serialize_pem().as_bytes())
        .unwrap();
}

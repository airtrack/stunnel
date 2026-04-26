use std::{fs::File, io::Write};

use clap::Parser;
use rcgen::{CertifiedKey, generate_simple_self_signed};
use stunnel::print_version;

#[derive(Parser)]
#[command(disable_version_flag = true)]
struct Args {
    #[arg(long, help = "Print version and build information")]
    version: bool,
}

fn main() {
    let args = Args::parse();
    if args.version {
        print_version("certgen");
        return;
    }

    let subject_alt_names = vec!["stunnel".to_string()];
    let CertifiedKey { cert, key_pair } = generate_simple_self_signed(subject_alt_names).unwrap();

    let mut cert_file = File::create("stunnel_cert.pem").unwrap();
    cert_file.write(cert.pem().as_bytes()).unwrap();

    let mut priv_file = File::create("private_key.pem").unwrap();
    priv_file
        .write(key_pair.serialize_pem().as_bytes())
        .unwrap();
}

use std::fs;

use anyhow::{Result, bail};
use base64::Engine;
use base64::prelude::BASE64_STANDARD;
use p384::SecretKey;
use p384::elliptic_curve::sec1::ToEncodedPoint;
use p384::pkcs8::DecodePrivateKey;

pub fn get_list_der_from_pem<F>(pem_str: &str, mut f: F) -> Result<Vec<Vec<u8>>>
where
    F: FnMut(&pem::Pem) -> bool,
{
    let pems = pem::parse_many(pem_str)?;
    let mut out = Vec::new();

    for p in pems {
        if f(&p) {
            out.push(p.contents().to_vec());
        }
    }

    if out.is_empty() {
        bail!("No matching PEM blocks found");
    }

    Ok(out)
}

pub fn display_der_pem(list: &[Vec<u8>]) {
    for (i, der) in list.iter().enumerate() {
        println!("CERT[{}] ({} bytes):", i, der.len());

        for (i, byte) in der.iter().enumerate() {
            if i % 15 == 0 {
                print!("    "); // indent
            }

            print!("{:02x}", byte);

            if i + 1 < der.len() {
                print!(":");
            }

            if (i + 1) % 15 == 0 {
                print!("\n");
            }
        }
        println!("\n");
        println!("    Base64 Equivalent:\n");
        let b64 = BASE64_STANDARD.encode(der);
        for chunk in b64.as_bytes().chunks(64) {
            println!("    {}", std::str::from_utf8(chunk).unwrap());
        }
        println!("========================================================================");
    }
}

fn print_ec384_private_key(pem_str: &str) -> anyhow::Result<()> {
    let pem = pem::parse(pem_str)?;

    let b64 = BASE64_STANDARD.encode(pem.contents());

    println!("Base64 Format:\n");

    for chunk in b64.as_bytes().chunks(64) {
        println!("{}", std::str::from_utf8(chunk).unwrap());
    }

    println!("\nDER (Hex Format):\n");
    let der = pem.contents();
    for (i, byte) in der.iter().enumerate() {
        if i % 15 == 0 {
            print!("    "); // indent
        }

        print!("{:02x}", byte);

        if i + 1 < der.len() {
            print!(":");
        }

        if (i + 1) % 15 == 0 {
            print!("\n");
        }
    }

    println!();
    // Parse EC private key
    let sk = SecretKey::from_pkcs8_der(&pem.contents())?;
    let sk_bytes = sk.to_bytes();

    println!("\n=== EC PRIVATE KEY (P-384 / secp384r1) ===");
    println!("Private-Key: (384 bit)");

    // Show private scalar in hex, OpenSSL style
    print!("priv:\n");
    for (i, byte) in sk_bytes.iter().enumerate() {
        if i % 15 == 0 {
            print!("    "); // indentation like OpenSSL
        }

        print!("{:02x}", byte); // print byte

        // Print colon only if NOT last byte
        if i + 1 < sk_bytes.len() {
            print!(":");
        }

        // New line every 15 bytes
        if (i + 1) % 15 == 0 {
            print!("\n");
        }
    }
    println!();

    // Extract public key
    let pk = sk.public_key();
    let encoded = pk.to_encoded_point(false);
    let pub_bytes = encoded.as_bytes();

    print!("pub:\n");
    for (i, byte) in pub_bytes.iter().enumerate() {
        if i % 15 == 0 {
            print!("    "); // indentation like OpenSSL
        }

        print!("{:02x}", byte); // print byte

        // Print colon only if NOT last byte
        if i + 1 < pub_bytes.len() {
            print!(":");
        }

        // New line every 15 bytes
        if (i + 1) % 15 == 0 {
            print!("\n");
        }
    }
    println!();
    println!("ASN1 OID: secp384r1");
    println!("NIST CURVE: P-384");

    Ok(())
}

fn main() -> anyhow::Result<()> {
    // Read EC private key PEM
    let pem_str = fs::read_to_string("ec384-private.pem")?;
    print_ec384_private_key(&pem_str)?;

    let list = get_list_der_from_pem(&pem_str, |pem| pem.tag() == "PRIVATE KEY")?;
    display_der_pem(&list);
    Ok(())
}

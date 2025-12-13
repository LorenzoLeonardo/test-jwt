mod ec;

use base64::Engine;
use base64::prelude::BASE64_STANDARD;
use elliptic_curve::sec1::ToEncodedPoint;
use pkcs8::DecodePrivateKey;

use p384::SecretKey as P384SecretKey;

use crate::ec::{ECPrivateKey, ECX509Cert};

fn main() -> anyhow::Result<()> {
    test_ec("ec384-cert.pem", "ec384-private.pem")?;
    test_ec("ec256-cert.pem", "ec256-private.pem")?;
    test_ec("ec521-cert.pem", "ec521-private.pem")?;
    Ok(())
}

fn test_ec(cert: &str, privkey: &str) -> anyhow::Result<()> {
    let private_key = ECPrivateKey::load_privatekey_pem(privkey)?;
    let pubkey_from_priv = private_key.extract_publickey()?;
    display_der(&[&pubkey_from_priv]);

    let x509 = ECX509Cert::load_x509_pem(cert)?;
    let pubkey_from_cert = x509.extract_publickey(0)?;
    println!("Num Certs: {}", x509.get_num_certs());
    display_der(&[&pubkey_from_cert]);

    assert_eq!(pubkey_from_priv, pubkey_from_cert);
    Ok(())
}

fn display_der(list: &[&[u8]]) {
    for (i, der) in list.iter().enumerate() {
        println!("[{i}]DER Equivalent: ({}) bytes", der.len());

        for (i, byte) in der.iter().enumerate() {
            if i % 15 == 0 {
                print!("    "); // indent
            }

            print!("{:02x}", byte);

            if i + 1 < der.len() {
                print!(":");
            }

            if (i + 1) % 15 == 0 {
                println!();
            }
        }
        println!("\n");
        println!("[{i}]Base64 Equivalent:\n");
        let b64 = BASE64_STANDARD.encode(der);
        for chunk in b64.as_bytes().chunks(64) {
            println!("    {}", std::str::from_utf8(chunk).unwrap());
        }
        println!("========================================================================");
    }
}

fn _print_ec384_private_key(pem_str: &str) -> anyhow::Result<()> {
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
            println!();
        }
    }

    println!();
    // Parse EC private key
    let sk = P384SecretKey::from_pkcs8_der(pem.contents())?;
    let sk_bytes = sk.to_bytes();

    println!("\n=== EC PRIVATE KEY (P-384 / secp384r1) ===");
    println!("Private-Key: (384 bit)");

    // Show private scalar in hex, OpenSSL style
    println!("priv:");
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
            println!();
        }
    }
    println!();

    // Extract public key
    let pk = sk.public_key();
    let encoded = pk.to_encoded_point(false);
    let pub_bytes = encoded.as_bytes();

    println!("pub:");
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
            println!();
        }
    }
    println!();
    println!("ASN1 OID: secp384r1");
    println!("NIST CURVE: P-384");

    Ok(())
}

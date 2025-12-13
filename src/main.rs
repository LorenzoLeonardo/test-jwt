mod ec;

use anyhow::{Result, anyhow, bail};
use base64::Engine;
use base64::prelude::BASE64_STANDARD;
use elliptic_curve::sec1::ToEncodedPoint;
use pkcs8::{
    DecodePrivateKey, ObjectIdentifier, PrivateKeyInfo,
    der::{Decode, Encode},
};
use x509_parser::oid_registry::OID_KEY_TYPE_EC_PUBLIC_KEY;
use x509_parser::prelude::{FromDer, X509Certificate};

use p256::SecretKey as P256SecretKey;
use p384::SecretKey as P384SecretKey;
use p521::SecretKey as P521SecretKey;

use crate::ec::{ECPrivateKey, ECX509Cert};

/// Extract EC public key (uncompressed SEC1) from a PKCS#8 EC private key
pub fn extract_ec_public_key_from_private_key(private_der: &[u8]) -> Result<Vec<u8>> {
    // Parse PKCS#8 only once
    let pk_info = PrivateKeyInfo::from_der(private_der)?;
    let params = pk_info
        .algorithm
        .parameters
        .ok_or_else(|| anyhow::anyhow!("Missing EC parameters"))?;
    let der = params.to_der()?;
    let curve_oid = ObjectIdentifier::from_der(&der)?;

    match curve_oid.to_string().as_str() {
        // secp256r1 / prime256v1
        "1.2.840.10045.3.1.7" => {
            let sk = P256SecretKey::from_pkcs8_der(private_der)?;
            let pubkey = sk.public_key();
            Ok(pubkey.to_encoded_point(false).as_bytes().to_vec())
        }

        // secp384r1
        "1.3.132.0.34" => {
            let sk = P384SecretKey::from_pkcs8_der(private_der)?;
            let pubkey = sk.public_key();
            Ok(pubkey.to_encoded_point(false).as_bytes().to_vec())
        }

        // secp521r1
        "1.3.132.0.35" => {
            let sk = P521SecretKey::from_pkcs8_der(private_der)?;
            let pubkey = sk.public_key();
            Ok(pubkey.to_encoded_point(false).as_bytes().to_vec())
        }

        _ => bail!("Unsupported EC curve OID: {}", curve_oid),
    }
}

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

pub fn display_der(list: &[&[u8]]) {
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

pub fn extract_ec_public_key_from_cert_der(cert_der: &[u8]) -> Result<Vec<u8>> {
    // Parse certificate
    let (_, cert) = X509Certificate::from_der(cert_der)
        .map_err(|_| anyhow!("Invalid X.509 certificate DER"))?;

    let spki = cert.public_key();

    // Ensure EC key
    if spki.algorithm.algorithm != OID_KEY_TYPE_EC_PUBLIC_KEY {
        bail!("Certificate public key is not EC");
    }

    // Extract EC parameters (named curve)
    let params = spki
        .algorithm
        .parameters
        .as_ref()
        .ok_or_else(|| anyhow!("Missing EC parameters"))?;

    let curve_oid = params
        .as_oid()
        .map_err(|_| anyhow!("EC parameters are not a named curve"))?
        .to_id_string();

    let spk_bytes = &spki.subject_public_key.data;

    if spk_bytes.is_empty() {
        bail!("Empty EC public key");
    }
    println!("OID: {}", curve_oid.as_str());
    // Auto-select curve
    let pub_key = match curve_oid.as_str() {
        // P-256
        "1.2.840.10045.3.1.7" => {
            println!("EC P-256");
            let pk = p256::PublicKey::from_sec1_bytes(spk_bytes)
                .map_err(|_| anyhow!("Invalid P-256 public key"))?;
            pk.to_encoded_point(false).as_bytes().into()
        }
        // P-384
        "1.3.132.0.34" => {
            println!("EC P-384");
            let pk = p384::PublicKey::from_sec1_bytes(spk_bytes)
                .map_err(|_| anyhow!("Invalid P-384 public key"))?;
            pk.to_encoded_point(false).as_bytes().into()
        }
        // P-521
        "1.3.132.0.35" => {
            let pk = p521::PublicKey::from_sec1_bytes(spk_bytes)
                .map_err(|_| anyhow!("Invalid P-521 public key"))?;
            pk.to_encoded_point(false).as_bytes().into()
        }

        _ => bail!("Unsupported EC curve OID: {}", curve_oid),
    };

    Ok(pub_key)
}

fn test_ec(cert: &str, privkey: &str) -> anyhow::Result<()> {
    let private_key = ECPrivateKey::load_privatekey_pem(privkey)?;
    let pubkey_from_priv = private_key.extract_publickey()?;
    display_der(&[&pubkey_from_priv]);

    let x509 = ECX509Cert::load_x509_pem(cert)?;
    let pubkey_from_cert = x509.extract_publickey(0)?;
    display_der(&[&pubkey_from_cert]);

    assert_eq!(pubkey_from_priv, pubkey_from_cert);
    Ok(())
}

fn main() -> anyhow::Result<()> {
    test_ec("ec384-cert.pem", "ec384-private.pem")?;
    test_ec("ec256-cert.pem", "ec256-private.pem")?;
    test_ec("ec521-cert.pem", "ec521-private.pem")?;
    Ok(())
}

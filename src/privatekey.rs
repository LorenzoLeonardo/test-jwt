use std::{fs, path::Path};

use anyhow::{Result, anyhow, bail};
use elliptic_curve::sec1::ToEncodedPoint;
use pkcs8::{
    AssociatedOid, DecodePrivateKey, ObjectIdentifier, PrivateKeyInfo,
    der::{Decode, Encode},
};

use p224::SecretKey as P224SecretKey;
use p256::SecretKey as P256SecretKey;
use p384::SecretKey as P384SecretKey;
use p521::SecretKey as P521SecretKey;

use p224::NistP224;
use p256::NistP256;
use p384::NistP384;
use p521::NistP521;

#[derive(Debug)]
pub struct ECPrivateKey(Vec<u8>);

impl ECPrivateKey {
    pub fn load_privatekey_pem<P: AsRef<Path>>(path: P) -> Result<Self> {
        let pem_str = fs::read_to_string(path)?;

        Self::from_pem(&pem_str)
    }

    pub fn from_pem(pem_str: &str) -> Result<Self> {
        let ders = get_list_der_from_pem(pem_str, |pem| {
            pem.tag() == "PRIVATE KEY" || pem.tag() == "EC PRIVATE KEY"
        })?;

        let der = ders
            .into_iter()
            .next()
            .ok_or_else(|| anyhow!("No PRIVATE KEY found in PEM"))?;

        Ok(Self(der))
    }
    #[allow(unused)]
    pub fn from_der(der: Vec<u8>) -> Self {
        Self(der)
    }

    pub fn extract_publickey(&self) -> Result<Vec<u8>> {
        let private_der = &self.0;
        // Parse PKCS#8 only once
        if let Ok(pk_info) = PrivateKeyInfo::from_der(private_der) {
            let params = pk_info
                .algorithm
                .parameters
                .ok_or_else(|| anyhow::anyhow!("Missing EC parameters"))?;
            let der = params.to_der()?;
            let curve_oid = ObjectIdentifier::from_der(&der)?;

            match curve_oid {
                // secp224r1
                NistP224::OID => {
                    let sk = P224SecretKey::from_pkcs8_der(private_der)?;
                    let pubkey = sk.public_key();
                    Ok(pubkey.to_encoded_point(false).as_bytes().to_vec())
                }
                // prime256v1
                NistP256::OID => {
                    let sk = P256SecretKey::from_pkcs8_der(private_der)?;
                    let pubkey = sk.public_key();
                    Ok(pubkey.to_encoded_point(false).as_bytes().to_vec())
                }
                // secp384r1
                NistP384::OID => {
                    let sk = P384SecretKey::from_pkcs8_der(private_der)?;
                    let pubkey = sk.public_key();
                    Ok(pubkey.to_encoded_point(false).as_bytes().to_vec())
                }
                // secp521r1
                NistP521::OID => {
                    let sk = P521SecretKey::from_pkcs8_der(private_der)?;
                    let pubkey = sk.public_key();
                    Ok(pubkey.to_encoded_point(false).as_bytes().to_vec())
                }

                _ => bail!("Unsupported EC curve OID: {}", curve_oid),
            }
        } else {
            // If PKCS#8 parsing fails, try SEC1 parsing directly (old style EC PRIVATE KEY)
            // Try parsing as P224
            if let Ok(sk) = P224SecretKey::from_sec1_der(private_der) {
                let pubkey = sk.public_key();
                return Ok(pubkey.to_encoded_point(false).as_bytes().to_vec());
            }
            // Try parsing as P256
            if let Ok(sk) = P256SecretKey::from_sec1_der(private_der) {
                let pubkey = sk.public_key();
                return Ok(pubkey.to_encoded_point(false).as_bytes().to_vec());
            }
            // Try parsing as P384
            if let Ok(sk) = P384SecretKey::from_sec1_der(private_der) {
                let pubkey = sk.public_key();
                return Ok(pubkey.to_encoded_point(false).as_bytes().to_vec());
            }
            // Try parsing as P521
            if let Ok(sk) = P521SecretKey::from_sec1_der(private_der) {
                let pubkey = sk.public_key();
                return Ok(pubkey.to_encoded_point(false).as_bytes().to_vec());
            }

            bail!("Failed to parse EC private key in either PKCS#8 or SEC1 format");
        }
    }

    /// Try to get raw private key bytes from SecretKey API
    pub fn extract_private_key_bytes(&self) -> Result<Vec<u8>> {
        let der = &self.0;

        // Try PKCS#8 parse first, then get raw scalar bytes from SecretKey
        if let Ok(sk) = P224SecretKey::from_pkcs8_der(der) {
            return Ok(sk.to_bytes().to_vec());
        }
        if let Ok(sk) = P256SecretKey::from_pkcs8_der(der) {
            return Ok(sk.to_bytes().to_vec());
        }
        if let Ok(sk) = P384SecretKey::from_pkcs8_der(der) {
            return Ok(sk.to_bytes().to_vec());
        }
        if let Ok(sk) = P521SecretKey::from_pkcs8_der(der) {
            return Ok(sk.to_bytes().to_vec());
        }

        // Try SEC1 parse as fallback
        if let Ok(sk) = P224SecretKey::from_sec1_der(der) {
            return Ok(sk.to_bytes().to_vec());
        }
        if let Ok(sk) = P256SecretKey::from_sec1_der(der) {
            return Ok(sk.to_bytes().to_vec());
        }
        if let Ok(sk) = P384SecretKey::from_sec1_der(der) {
            return Ok(sk.to_bytes().to_vec());
        }
        if let Ok(sk) = P521SecretKey::from_sec1_der(der) {
            return Ok(sk.to_bytes().to_vec());
        }

        bail!("Failed to parse EC private key to extract raw bytes");
    }

    /// Extract the curve OID string and friendly curve name from PKCS#8 info
    pub fn extract_curve_oid_and_name(&self) -> Result<(String, String)> {
        // Try PKCS#8 parse for OID
        if let Ok(pk_info) = pkcs8::PrivateKeyInfo::from_der(&self.0)
            && let Some(params) = &pk_info.algorithm.parameters
        {
            let der = params.to_der()?;
            if let Ok(oid) = ObjectIdentifier::from_der(&der) {
                let friendly = match oid {
                    NistP224::OID => "P-224",
                    NistP256::OID => "P-256",
                    NistP384::OID => "P-384",
                    NistP521::OID => "P-521",
                    _ => "Unknown",
                };
                return Ok((oid.to_string(), friendly.to_string()));
            }
        }

        // Guess by private key length fallback
        let priv_len = self.extract_private_key_bytes()?.len();
        let (oid_str, friendly_name) = match priv_len {
            28 => ("secp224r1".to_string(), "P-224".to_string()),
            32 => ("prime256v1".to_string(), "P-256".to_string()),
            48 => ("secp384r1".to_string(), "P-384".to_string()),
            66 => ("secp521r1".to_string(), "P-521".to_string()),
            _ => ("Unknown".to_string(), "Unknown".to_string()),
        };
        Ok((oid_str, friendly_name))
    }
}

fn get_list_der_from_pem<F>(pem_str: &str, mut f: F) -> Result<Vec<Vec<u8>>>
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

#[cfg(test)]
mod tests {
    use super::*;
    use base64::{Engine, prelude::BASE64_STANDARD};
    use elliptic_curve::rand_core;
    use p256::SecretKey as P256SecretKey;
    use p384::SecretKey as P384SecretKey;
    use p521::SecretKey as P521SecretKey;
    use pkcs8::EncodePrivateKey;
    use tempfile::NamedTempFile;

    /// Helper: wrap DER into PKCS#8 PEM
    fn pkcs8_pem_from_der(der: &[u8]) -> String {
        let b64 = BASE64_STANDARD.encode(der);
        format!(
            "-----BEGIN PRIVATE KEY-----\n{}\n-----END PRIVATE KEY-----\n",
            b64.as_bytes()
                .chunks(64)
                .map(|c| std::str::from_utf8(c).unwrap())
                .collect::<Vec<_>>()
                .join("\n")
        )
    }

    #[test]
    fn from_pem_ok() {
        let sk = P256SecretKey::random(&mut rand_core::OsRng);
        let der = sk.to_pkcs8_der().unwrap();
        let pem = pkcs8_pem_from_der(der.as_bytes());

        let key = ECPrivateKey::from_pem(&pem).unwrap();
        assert!(!key.0.is_empty());
    }

    #[test]
    fn from_pem_no_private_key() {
        let pem = "-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----";

        let err = ECPrivateKey::from_pem(pem).unwrap_err();
        assert!(err.to_string().contains("No matching PEM blocks found"));
    }

    #[test]
    fn load_privatekey_pem_ok() {
        let sk = P384SecretKey::random(&mut rand_core::OsRng);
        let der = sk.to_pkcs8_der().unwrap();
        let pem = pkcs8_pem_from_der(der.as_bytes());

        let file = NamedTempFile::new().unwrap();
        fs::write(file.path(), pem).unwrap();

        let key = ECPrivateKey::load_privatekey_pem(file.path()).unwrap();
        assert!(!key.0.is_empty());
    }

    #[test]
    fn extract_publickey_p256() {
        let sk = P256SecretKey::random(&mut rand_core::OsRng);
        let der = sk.to_pkcs8_der().unwrap();
        let key = ECPrivateKey::from_der(der.as_bytes().to_vec());

        let pubkey = key.extract_publickey().unwrap();

        // Uncompressed EC point
        assert_eq!(pubkey[0], 0x04);
        assert_eq!(pubkey.len(), 65); // 1 + 32 + 32
    }

    #[test]
    fn extract_publickey_p384() {
        let sk = P384SecretKey::random(&mut rand_core::OsRng);
        let der = sk.to_pkcs8_der().unwrap();
        let key = ECPrivateKey::from_der(der.as_bytes().to_vec());

        let pubkey = key.extract_publickey().unwrap();

        assert_eq!(pubkey[0], 0x04);
        assert_eq!(pubkey.len(), 97); // 1 + 48 + 48
    }

    #[test]
    fn extract_publickey_p521() {
        let sk = P521SecretKey::random(&mut rand_core::OsRng);
        let der = sk.to_pkcs8_der().unwrap();
        let key = ECPrivateKey::from_der(der.as_bytes().to_vec());

        let pubkey = key.extract_publickey().unwrap();

        assert_eq!(pubkey[0], 0x04);
        assert_eq!(pubkey.len(), 133); // 1 + 66 + 66
    }
}

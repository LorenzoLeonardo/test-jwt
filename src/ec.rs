use std::{fs, path::Path};

use anyhow::{Result, anyhow, bail};
use elliptic_curve::sec1::ToEncodedPoint;
use pkcs8::{
    AssociatedOid, DecodePrivateKey, ObjectIdentifier, PrivateKeyInfo,
    der::{Decode, Encode},
};
use x509_parser::oid_registry::OID_KEY_TYPE_EC_PUBLIC_KEY;
use x509_parser::prelude::{FromDer, X509Certificate};

use p256::SecretKey as P256SecretKey;
use p384::SecretKey as P384SecretKey;
use p521::SecretKey as P521SecretKey;

use p256::NistP256;
use p384::NistP384;
use p521::NistP521;

#[derive(Debug)]
pub struct ECX509Cert(Vec<Vec<u8>>);

impl ECX509Cert {
    pub fn load_x509_pem<P: AsRef<Path>>(path: P) -> Result<Self> {
        let pem_str = fs::read_to_string(path)?;

        Self::from_pem(&pem_str)
    }

    pub fn from_pem(pem_str: &str) -> Result<Self> {
        Ok(Self(get_list_der_from_pem(pem_str, |pem| {
            pem.tag() == "CERTIFICATE"
        })?))
    }
    #[allow(unused)]
    pub fn from_der(der: Vec<u8>) -> Self {
        Self(vec![der])
    }

    pub fn get_num_certs(&self) -> usize {
        self.0.len()
    }

    pub fn extract_publickey(&self, index: usize) -> Result<Vec<u8>> {
        let cert_der = self
            .0
            .get(index)
            .ok_or_else(|| anyhow!("Index out of bounds"))?;
        // Parse certificate
        let (rem, cert) = X509Certificate::from_der(cert_der)
            .map_err(|_| anyhow!("Invalid X.509 certificate DER"))?;

        if !rem.is_empty() {
            bail!("Trailing data after X.509 certificate");
        }
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
        let curve_oid =
            ObjectIdentifier::new(&curve_oid).map_err(|_| anyhow!("Invalid EC Curve OID"))?;

        let spk_bytes = &spki.subject_public_key.data;

        if spk_bytes.is_empty() {
            bail!("Empty EC public key");
        }

        // Auto-select curve
        let pub_key = match curve_oid {
            // P-256
            NistP256::OID => {
                let pk = p256::PublicKey::from_sec1_bytes(spk_bytes)
                    .map_err(|_| anyhow!("Invalid P-256 public key"))?;
                pk.to_encoded_point(false).as_bytes().into()
            }
            // P-384
            NistP384::OID => {
                let pk = p384::PublicKey::from_sec1_bytes(spk_bytes)
                    .map_err(|_| anyhow!("Invalid P-384 public key"))?;
                pk.to_encoded_point(false).as_bytes().into()
            }
            // P-521
            NistP521::OID => {
                let pk = p521::PublicKey::from_sec1_bytes(spk_bytes)
                    .map_err(|_| anyhow!("Invalid P-521 public key"))?;
                pk.to_encoded_point(false).as_bytes().into()
            }

            _ => bail!("Unsupported EC curve OID: {}", curve_oid),
        };

        Ok(pub_key)
    }
}

#[derive(Debug)]
pub struct ECPrivateKey(Vec<u8>);

impl ECPrivateKey {
    pub fn load_privatekey_pem<P: AsRef<Path>>(path: P) -> Result<Self> {
        let pem_str = fs::read_to_string(path)?;

        Self::from_pem(&pem_str)
    }

    pub fn from_pem(pem_str: &str) -> Result<Self> {
        let ders = get_list_der_from_pem(pem_str, |pem| pem.tag() == "PRIVATE KEY")?;

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
        let pk_info = PrivateKeyInfo::from_der(private_der)?;
        let params = pk_info
            .algorithm
            .parameters
            .ok_or_else(|| anyhow::anyhow!("Missing EC parameters"))?;
        let der = params.to_der()?;
        let curve_oid = ObjectIdentifier::from_der(&der)?;

        match curve_oid {
            // secp256r1 / prime256v1
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
    use elliptic_curve::{rand_core, sec1::FromEncodedPoint};
    use p256::SecretKey as P256SecretKey;
    use p384::SecretKey as P384SecretKey;
    use p521::SecretKey as P521SecretKey;
    use pkcs8::EncodePrivateKey;
    use rcgen::{CertificateParams, KeyPair};
    use tempfile::NamedTempFile;

    fn make_ec_cert_der(curve: &str) -> Vec<u8> {
        let alg = match curve {
            "P256" => &rcgen::PKCS_ECDSA_P256_SHA256,
            "P384" => &rcgen::PKCS_ECDSA_P384_SHA384,
            "P521" => &rcgen::PKCS_ECDSA_P521_SHA512,
            _ => panic!("unsupported curve"),
        };

        let keypair = KeyPair::generate_for(alg).unwrap();

        let params = CertificateParams::new(vec!["localhost".into()]).unwrap();

        // ✅ Works on older rcgen
        let cert = params.self_signed(&keypair).unwrap();
        cert.der().to_vec()
    }

    fn make_rsa_cert_der() -> Vec<u8> {
        let keypair = KeyPair::generate_for(&rcgen::PKCS_RSA_SHA256).unwrap();
        let params = CertificateParams::new(vec!["localhost".into()]).unwrap();
        let cert = params.self_signed(&keypair).unwrap();
        cert.der().to_vec()
    }

    fn wrap_single_cert(der: Vec<u8>) -> ECX509Cert {
        ECX509Cert(vec![der])
    }

    #[test]
    fn extract_p256_public_key() {
        let certs = wrap_single_cert(make_ec_cert_der("P256"));
        let pk = certs.extract_publickey(0).unwrap();

        assert_eq!(pk.len(), 65);
        assert_eq!(pk[0], 0x04);

        let point = p256::EncodedPoint::from_bytes(&pk).unwrap();
        let _ = p256::PublicKey::from_encoded_point(&point).unwrap();
    }

    #[test]
    fn extract_p384_public_key() {
        let certs = wrap_single_cert(make_ec_cert_der("P384"));
        let pk = certs.extract_publickey(0).unwrap();

        assert_eq!(pk.len(), 97);
        assert_eq!(pk[0], 0x04);

        let point = p384::EncodedPoint::from_bytes(&pk).unwrap();
        let _ = p384::PublicKey::from_encoded_point(&point).unwrap();
    }

    #[test]
    fn extract_p521_public_key() {
        let certs = wrap_single_cert(make_ec_cert_der("P521"));
        let pk = certs.extract_publickey(0).unwrap();

        assert_eq!(pk.len(), 133);
        assert_eq!(pk[0], 0x04);

        let point = p521::EncodedPoint::from_bytes(&pk).unwrap();
        let _ = p521::PublicKey::from_encoded_point(&point).unwrap();
    }

    #[test]
    fn pem_roundtrip_single_cert() {
        let der = make_ec_cert_der("P256");
        let pem = pem::Pem::new("CERTIFICATE", der.clone());
        let pem_str = pem::encode(&pem);

        let certs = ECX509Cert::from_pem(&pem_str).unwrap();
        let pk = certs.extract_publickey(0).unwrap();

        assert_eq!(pk.len(), 65);
    }

    #[test]
    fn pem_multiple_certificates() {
        let der1 = make_ec_cert_der("P256");
        let der2 = make_ec_cert_der("P384");

        let pem = format!(
            "{}{}",
            pem::encode(&pem::Pem::new("CERTIFICATE", der1)),
            pem::encode(&pem::Pem::new("CERTIFICATE", der2)),
        );

        let certs = ECX509Cert::from_pem(&pem).unwrap();
        assert_eq!(certs.get_num_certs(), 2);

        assert_eq!(certs.extract_publickey(0).unwrap().len(), 65);
        assert_eq!(certs.extract_publickey(1).unwrap().len(), 97);
    }

    #[test]
    fn reject_non_ec_certificate() {
        let certs = wrap_single_cert(make_rsa_cert_der());
        let err = certs.extract_publickey(0).unwrap_err();

        assert!(err.to_string().contains("not EC"));
    }

    #[test]
    fn trailing_data_is_rejected() {
        let mut der = make_ec_cert_der("P256");
        der.extend_from_slice(b"garbage");

        let certs = wrap_single_cert(der);
        let err = certs.extract_publickey(0).unwrap_err();

        assert!(err.to_string().contains("Trailing data"));
    }

    #[test]
    fn index_out_of_bounds() {
        let certs = wrap_single_cert(make_ec_cert_der("P256"));
        let err = certs.extract_publickey(1).unwrap_err();

        assert!(err.to_string().contains("Index out of bounds"));
    }

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

    #[test_case::test_case("ec384-cert.pem", "ec384-private.pem")]
    #[test_case::test_case("ec256-cert.pem", "ec256-private.pem")]
    #[test_case::test_case("ec521-cert.pem", "ec521-private.pem")]
    fn test_actual_file_ec(cert: &str, privkey: &str) -> anyhow::Result<()> {
        let private_key = ECPrivateKey::load_privatekey_pem(privkey).unwrap();
        let pubkey_from_priv = private_key.extract_publickey().unwrap();

        let x509 = ECX509Cert::load_x509_pem(cert).unwrap();
        let pubkey_from_cert = x509.extract_publickey(0).unwrap();

        assert_eq!(pubkey_from_priv, pubkey_from_cert);
        Ok(())
    }
}

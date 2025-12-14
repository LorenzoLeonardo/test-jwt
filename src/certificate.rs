use std::{fs, ops::Deref, path::Path};

use anyhow::{Result, anyhow, bail};
use elliptic_curve::sec1::ToEncodedPoint;
use pkcs8::{AssociatedOid, ObjectIdentifier};
use x509_parser::{
    oid_registry,
    prelude::{FromDer, X509Certificate},
};

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
        if spki.algorithm.algorithm != oid_registry::OID_KEY_TYPE_EC_PUBLIC_KEY {
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

impl Deref for ECX509Cert {
    type Target = [Vec<u8>];

    fn deref(&self) -> &Self::Target {
        &self.0
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
    use elliptic_curve::sec1::FromEncodedPoint;
    use rcgen::{CertificateParams, KeyPair};
    use std::io::Write;
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

    #[test]
    fn deref_exposes_der_slices() {
        let der = make_ec_cert_der("P256");
        let certs = wrap_single_cert(der.clone());

        assert_eq!(certs.len(), 1);
        assert_eq!(certs[0], der);
    }

    #[test]
    fn load_x509_pem_from_file() {
        let der = make_ec_cert_der("P256");
        let pem = pem::encode(&pem::Pem::new("CERTIFICATE", der));

        let mut file = NamedTempFile::new().unwrap();
        file.write_all(pem.as_bytes()).unwrap();

        let certs = ECX509Cert::load_x509_pem(file.path()).unwrap();
        assert_eq!(certs.get_num_certs(), 1);
    }

    #[test]
    fn pem_with_no_certificates_is_rejected() {
        let pem = pem::encode(&pem::Pem::new("PRIVATE KEY", b"nope".to_vec()));
        let err = ECX509Cert::from_pem(&pem).unwrap_err();

        assert!(err.to_string().contains("No matching PEM blocks"));
    }

    #[test]
    fn invalid_pem_is_rejected() {
        let err = ECX509Cert::from_pem("-----BEGIN GARBAGE-----").unwrap_err();
        assert!(!err.to_string().is_empty());
    }

    #[test]
    fn mixed_ec_and_rsa_certificates() {
        let ec = make_ec_cert_der("P256");
        let rsa = make_rsa_cert_der();

        let pem = format!(
            "{}{}",
            pem::encode(&pem::Pem::new("CERTIFICATE", ec)),
            pem::encode(&pem::Pem::new("CERTIFICATE", rsa)),
        );

        let certs = ECX509Cert::from_pem(&pem).unwrap();
        assert_eq!(certs.get_num_certs(), 2);

        // EC works
        assert_eq!(certs.extract_publickey(0).unwrap().len(), 65);

        // RSA fails
        let err = certs.extract_publickey(1).unwrap_err();
        assert!(err.to_string().contains("not EC"));
    }

    #[test]
    fn missing_ec_parameters_is_rejected() {
        // Corrupt SPKI parameters by truncating DER
        let mut der = make_ec_cert_der("P256");
        der.truncate(der.len() / 2);

        let certs = wrap_single_cert(der);
        let err = certs.extract_publickey(0).unwrap_err();

        assert!(
            err.to_string().contains("Invalid X.509")
                || err.to_string().contains("Missing EC parameters")
        );
    }

    #[test]
    fn extract_publickey_error_messages_are_stable() {
        let certs = wrap_single_cert(make_rsa_cert_der());
        let err = certs.extract_publickey(0).unwrap_err().to_string();

        assert!(
            err.contains("EC"),
            "error message should mention EC, got: {err}"
        );
    }
}

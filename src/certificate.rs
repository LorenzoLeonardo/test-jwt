use std::{fs, path::Path};

use anyhow::{Result, anyhow, bail};
use pkcs8::ObjectIdentifier;
use x509_parser::{
    oid_registry,
    prelude::{FromDer, X509Certificate},
};

#[allow(unused)]
/// Structured EC public key extracted from X.509
#[derive(Debug, Clone)]
pub struct EcPublicKey {
    pub curve_oid: ObjectIdentifier,
    /// SEC1 encoded EC point (SubjectPublicKeyInfo)
    pub sec1_bytes: Vec<u8>,
}

/// Owned X.509 certificate bundle (DER only, parsed on demand)
#[derive(Debug)]
pub struct ECX509Cert {
    pub ders: Vec<Vec<u8>>,
}

impl ECX509Cert {
    /* =========================
     * Constructors
     * ========================= */

    pub fn load_x509_pem<P: AsRef<Path>>(path: P) -> Result<Self> {
        let pem_str = fs::read_to_string(path)?;
        Self::from_pem(&pem_str)
    }

    pub fn from_pem(pem_str: &str) -> Result<Self> {
        let ders = get_list_der_from_pem(pem_str, |pem| pem.tag() == "CERTIFICATE")?;
        Ok(Self { ders })
    }
    #[allow(unused)]
    pub fn from_der(der: Vec<u8>) -> Self {
        Self { ders: vec![der] }
    }

    pub fn num_certs(&self) -> usize {
        self.ders.len()
    }

    /* =========================
     * Internal helpers
     * ========================= */

    fn cert_at(&self, index: usize) -> Result<X509Certificate<'_>> {
        let der = self
            .ders
            .get(index)
            .ok_or_else(|| anyhow!("Certificate index out of bounds"))?;

        let (rem, cert) =
            X509Certificate::from_der(der).map_err(|_| anyhow!("Invalid X.509 DER"))?;

        if !rem.is_empty() {
            bail!("Trailing data after X.509 certificate");
        }

        Ok(cert)
    }

    /* =========================
     * Public API
     * ========================= */

    pub fn ec_public_key(&self, index: usize) -> Result<EcPublicKey> {
        let cert = self.cert_at(index)?;
        let spki = cert.public_key();

        // Ensure EC key
        if spki.algorithm.algorithm != oid_registry::OID_KEY_TYPE_EC_PUBLIC_KEY {
            bail!("Certificate public key is not EC");
        }

        // Extract named curve OID
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
            ObjectIdentifier::new(&curve_oid).map_err(|_| anyhow!("Invalid curve OID"))?;

        let sec1_bytes = spki.subject_public_key.data.to_vec();

        if sec1_bytes.is_empty() {
            bail!("Empty EC public key");
        }

        Ok(EcPublicKey {
            curve_oid,
            sec1_bytes,
        })
    }
}

/* =========================
 * PEM helper
 * ========================= */

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
        ECX509Cert::from_der(der)
    }

    #[test]
    fn extract_p256_public_key() {
        let certs = wrap_single_cert(make_ec_cert_der("P256"));
        let pk = certs.ec_public_key(0).unwrap();

        assert_eq!(pk.sec1_bytes.len(), 65);
        assert_eq!(pk.sec1_bytes[0], 0x04);

        let point = p256::EncodedPoint::from_bytes(&pk.sec1_bytes).unwrap();
        let _ = p256::PublicKey::from_encoded_point(&point).unwrap();
    }

    #[test]
    fn extract_p384_public_key() {
        let certs = wrap_single_cert(make_ec_cert_der("P384"));
        let pk = certs.ec_public_key(0).unwrap();

        assert_eq!(pk.sec1_bytes.len(), 97);
        assert_eq!(pk.sec1_bytes[0], 0x04);

        let point = p384::EncodedPoint::from_bytes(&pk.sec1_bytes).unwrap();
        let _ = p384::PublicKey::from_encoded_point(&point).unwrap();
    }

    #[test]
    fn extract_p521_public_key() {
        let certs = wrap_single_cert(make_ec_cert_der("P521"));
        let pk = certs.ec_public_key(0).unwrap();

        assert_eq!(pk.sec1_bytes.len(), 133);
        assert_eq!(pk.sec1_bytes[0], 0x04);

        let point = p521::EncodedPoint::from_bytes(&pk.sec1_bytes).unwrap();
        let _ = p521::PublicKey::from_encoded_point(&point).unwrap();
    }

    #[test]
    fn pem_roundtrip_single_cert() {
        let der = make_ec_cert_der("P256");
        let pem = pem::encode(&pem::Pem::new("CERTIFICATE", der));

        let certs = ECX509Cert::from_pem(&pem).unwrap();
        let pk = certs.ec_public_key(0).unwrap();

        assert_eq!(pk.sec1_bytes.len(), 65);
    }

    #[test]
    fn pem_multiple_certificates() {
        let pem = format!(
            "{}{}",
            pem::encode(&pem::Pem::new("CERTIFICATE", make_ec_cert_der("P256"))),
            pem::encode(&pem::Pem::new("CERTIFICATE", make_ec_cert_der("P384"))),
        );

        let certs = ECX509Cert::from_pem(&pem).unwrap();
        assert_eq!(certs.num_certs(), 2);

        assert_eq!(certs.ec_public_key(0).unwrap().sec1_bytes.len(), 65);
        assert_eq!(certs.ec_public_key(1).unwrap().sec1_bytes.len(), 97);
    }

    #[test]
    fn reject_non_ec_certificate() {
        let certs = wrap_single_cert(make_rsa_cert_der());
        let err = certs.ec_public_key(0).unwrap_err();
        assert!(err.to_string().contains("not EC"));
    }

    #[test]
    fn trailing_data_is_rejected() {
        let mut der = make_ec_cert_der("P256");
        der.extend_from_slice(b"garbage");

        let certs = wrap_single_cert(der);
        let err = certs.ec_public_key(0).unwrap_err();
        assert!(err.to_string().contains("Trailing data"));
    }

    #[test]
    fn index_out_of_bounds() {
        let certs = wrap_single_cert(make_ec_cert_der("P256"));
        let err = certs.ec_public_key(1).unwrap_err();
        assert!(err.to_string().contains("Certificate index out of bounds"));
    }

    #[test]
    fn load_x509_pem_from_file() {
        let der = make_ec_cert_der("P256");
        let pem = pem::encode(&pem::Pem::new("CERTIFICATE", der));

        let mut file = NamedTempFile::new().unwrap();
        file.write_all(pem.as_bytes()).unwrap();

        let certs = ECX509Cert::load_x509_pem(file.path()).unwrap();
        assert_eq!(certs.num_certs(), 1);
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
        let pem = format!(
            "{}{}",
            pem::encode(&pem::Pem::new("CERTIFICATE", make_ec_cert_der("P256"))),
            pem::encode(&pem::Pem::new("CERTIFICATE", make_rsa_cert_der())),
        );

        let certs = ECX509Cert::from_pem(&pem).unwrap();
        assert_eq!(certs.num_certs(), 2);

        assert_eq!(certs.ec_public_key(0).unwrap().sec1_bytes.len(), 65);

        let err = certs.ec_public_key(1).unwrap_err();
        assert!(err.to_string().contains("not EC"));
    }

    #[test]
    fn extract_publickey_error_messages_are_stable() {
        let certs = wrap_single_cert(make_rsa_cert_der());
        let err = certs.ec_public_key(0).unwrap_err().to_string();

        assert!(
            err.contains("EC"),
            "error message should mention EC, got: {err}"
        );
    }
}

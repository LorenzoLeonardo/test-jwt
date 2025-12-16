use std::{fs, path::Path};

use anyhow::{Result, anyhow, bail};

use pkcs8::ObjectIdentifier;
use x509_parser::{
    asn1_rs::{Oid, oid},
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
    #[allow(unused)]
    pub fn certs(&self) -> Result<Vec<X509Certificate<'_>>> {
        let mut out = Vec::with_capacity(self.ders.len());

        for i in 0..self.ders.len() {
            out.push(self.cert_at(i)?);
        }

        Ok(out)
    }
    #[allow(unused)]
    pub fn cert_at(&self, index: usize) -> Result<X509Certificate<'_>> {
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
#[allow(unused)]
pub fn verify_leaf_signed_by_ca(
    leaf: &X509Certificate<'_>,
    ca: &X509Certificate<'_>,
) -> Result<()> {
    /* =========================
     * 1. Issuer / Subject check
     * ========================= */
    if leaf.issuer() != ca.subject() {
        bail!("Leaf issuer does not match CA subject");
    }

    /* =========================
     * 2. Ensure ECDSA signature
     * ========================= */
    let sig_alg = &leaf.signature_algorithm.algorithm;
    if sig_alg != &oid_registry::OID_SIG_ECDSA_WITH_SHA224
        && sig_alg != &oid_registry::OID_SIG_ECDSA_WITH_SHA256
        && sig_alg != &oid_registry::OID_SIG_ECDSA_WITH_SHA384
        && sig_alg != &oid_registry::OID_SIG_ECDSA_WITH_SHA512
    {
        bail!("Unsupported signature algorithm");
    }

    /* =========================
     * 3. Extract CA public key
     * ========================= */
    let spki = ca.public_key();

    if spki.algorithm.algorithm != oid_registry::OID_KEY_TYPE_EC_PUBLIC_KEY {
        bail!("CA public key is not EC");
    }

    let params = spki
        .algorithm
        .parameters
        .as_ref()
        .ok_or_else(|| anyhow!("Missing EC parameters"))?;

    let curve_oid = params
        .as_oid()
        .map_err(|_| anyhow!("EC parameters are not named curve"))?;

    let ca_pk_bytes = spki.subject_public_key.data.as_ref();

    if ca_pk_bytes.is_empty() {
        bail!("Empty CA public key");
    }

    /* =========================
     * 4. Data & signature
     * ========================= */
    let tbs = leaf.tbs_certificate.as_ref();
    let sig = leaf.signature_value.data.as_ref();

    /* =========================
     * 5. Curve dispatch
     * ========================= */
    // ===== P-224 =====
    const OID_NIST_EC_P224: Oid<'static> = oid!(1.3.132.0.33);
    if curve_oid == OID_NIST_EC_P224 {
        use p224::{
            EncodedPoint, NistP224,
            ecdsa::{Signature, VerifyingKey, signature::Verifier},
        };
        let point = EncodedPoint::from_bytes(ca_pk_bytes)
            .map_err(|_| anyhow!("Invalid P-224 public key"))?;

        let vk = VerifyingKey::from_encoded_point(&point)
            .map_err(|_| anyhow!("Invalid P-224 verifying key"))?;

        let sig = Signature::from_der(sig).map_err(|_| anyhow!("Invalid ECDSA signature"))?;

        vk.verify(tbs, &sig)
            .map_err(|_| anyhow!("ECDSA verification failed"))?;
    } else if curve_oid == oid_registry::OID_EC_P256 {
        use p256::{
            EncodedPoint, NistP256,
            ecdsa::{Signature, VerifyingKey, signature::Verifier},
        };
        // ===== P-256 =====
        let point = EncodedPoint::from_bytes(ca_pk_bytes)
            .map_err(|_| anyhow!("Invalid P-256 public key"))?;

        let vk = VerifyingKey::from_encoded_point(&point)
            .map_err(|_| anyhow!("Invalid P-256 verifying key"))?;

        let sig = Signature::from_der(sig).map_err(|_| anyhow!("Invalid ECDSA signature"))?;

        vk.verify(tbs, &sig)
            .map_err(|_| anyhow!("ECDSA verification failed"))?;
    } else if curve_oid == oid_registry::OID_NIST_EC_P384 {
        use p384::{
            EncodedPoint, NistP384,
            ecdsa::{Signature, VerifyingKey, signature::Verifier},
        };
        // ===== P-384 =====
        let point = EncodedPoint::from_bytes(ca_pk_bytes)
            .map_err(|_| anyhow!("Invalid P-384 public key"))?;

        let vk = VerifyingKey::from_encoded_point(&point)
            .map_err(|_| anyhow!("Invalid P-384 verifying key"))?;

        let sig = Signature::from_der(sig).map_err(|_| anyhow!("Invalid ECDSA signature"))?;

        vk.verify(tbs, &sig)
            .map_err(|_| anyhow!("ECDSA verification failed"))?;
    } else if curve_oid == oid_registry::OID_NIST_EC_P521 {
        use p521::{
            EncodedPoint, NistP521,
            ecdsa::{Signature, VerifyingKey, signature::Verifier},
        };
        let point = EncodedPoint::from_bytes(ca_pk_bytes)
            .map_err(|_| anyhow!("Invalid P-521 public key"))?;

        let vk = VerifyingKey::from_encoded_point(&point)
            .map_err(|_| anyhow!("Invalid P-521 verifying key"))?;

        let sig = Signature::from_der(sig).map_err(|_| anyhow!("Invalid ECDSA P-521 signature"))?;

        vk.verify(tbs, &sig)
            .map_err(|_| anyhow!("ECDSA P-521 verification failed"))?;
    } else {
        bail!("Unsupported EC curve OID {curve_oid}")
    }

    Ok(())
}

#[allow(unused)]
pub fn verify_leaf_signed_by_ca_bundle(
    leaf: &X509Certificate<'_>,
    ca_bundle: &[X509Certificate<'_>],
) -> Result<()> {
    let mut last_err: Option<anyhow::Error> = None;

    for ca in ca_bundle {
        match verify_leaf_signed_by_ca(leaf, ca) {
            Ok(()) => return Ok(()), // ✅ success with this CA
            Err(e) => last_err = Some(e),
        }
    }

    Err(last_err.unwrap_or_else(|| {
        anyhow!("Leaf certificate could not be verified by any CA in the bundle")
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
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
        use p256::elliptic_curve::sec1::FromEncodedPoint;

        let certs = wrap_single_cert(make_ec_cert_der("P256"));
        let pk = certs.ec_public_key(0).unwrap();

        assert_eq!(pk.sec1_bytes.len(), 65);
        assert_eq!(pk.sec1_bytes[0], 0x04);

        let point = p256::EncodedPoint::from_bytes(&pk.sec1_bytes).unwrap();
        let _ = p256::PublicKey::from_encoded_point(&point).unwrap();
    }

    #[test]
    fn extract_p384_public_key() {
        use p384::elliptic_curve::sec1::FromEncodedPoint;

        let certs = wrap_single_cert(make_ec_cert_der("P384"));
        let pk = certs.ec_public_key(0).unwrap();

        assert_eq!(pk.sec1_bytes.len(), 97);
        assert_eq!(pk.sec1_bytes[0], 0x04);

        let point = p384::EncodedPoint::from_bytes(&pk.sec1_bytes).unwrap();
        let _ = p384::PublicKey::from_encoded_point(&point).unwrap();
    }

    #[test]
    fn extract_p521_public_key() {
        use p521::elliptic_curve::sec1::FromEncodedPoint;

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

    #[test_case::test_case("ec224/ca-cert.pem", "ec224/leaf-cert.pem")]
    #[test_case::test_case("ec256/ca-cert.pem", "ec256/leaf-cert.pem")]
    #[test_case::test_case("ec384/ca-cert.pem", "ec384/leaf-cert.pem")]
    #[test_case::test_case("ec521/ca-cert.pem", "ec521/leaf-cert.pem")]
    fn verify_leaf(ca: &str, leaf: &str) {
        let ca = ECX509Cert::load_x509_pem(ca).unwrap();
        let leaf = ECX509Cert::load_x509_pem(leaf).unwrap();

        verify_leaf_signed_by_ca(&leaf.cert_at(0).unwrap(), &ca.cert_at(0).unwrap()).unwrap();
    }

    #[test]
    fn verify_leaf_from_ca_bundle() {
        let ca = ECX509Cert::load_x509_pem("test-pki/ca-bundle.pem").unwrap();
        let leaf = ECX509Cert::load_x509_pem("test-pki/leaf-cert.pem").unwrap();

        verify_leaf_signed_by_ca_bundle(&leaf.cert_at(0).unwrap(), &ca.certs().unwrap()).unwrap();
    }
}

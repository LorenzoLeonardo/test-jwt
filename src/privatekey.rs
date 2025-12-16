use std::{fs, path::Path};

use anyhow::{Result, anyhow, bail};
use pkcs8::{
    AssociatedOid, DecodePrivateKey, ObjectIdentifier, PrivateKeyInfo,
    der::{Decode, Encode},
};

use p224::{NistP224, SecretKey as P224SecretKey};
use p256::{NistP256, SecretKey as P256SecretKey};
use p384::{NistP384, SecretKey as P384SecretKey};
use p521::{NistP521, SecretKey as P521SecretKey};

#[derive(Debug, Clone)]
pub struct ECPrivateKey {
    der: Vec<u8>,
}

impl ECPrivateKey {
    /* =========================
     * Constructors
     * ========================= */

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

        Ok(Self { der })
    }
    #[allow(unused)]
    pub fn from_der(der: Vec<u8>) -> Self {
        Self { der }
    }

    /* =========================
     * Core parsing
     * ========================= */

    fn parse_any(&self) -> Result<ParsedEcKey> {
        // Prefer PKCS#8
        if let Ok(pkcs8) = PrivateKeyInfo::from_der(&self.der) {
            let params = pkcs8
                .algorithm
                .parameters
                .ok_or_else(|| anyhow!("Missing EC parameters"))?;

            let oid = ObjectIdentifier::from_der(&params.to_der()?)?;
            return ParsedEcKey::from_pkcs8(&oid, &self.der);
        }

        // Fallback: SEC1 guessing
        ParsedEcKey::from_sec1(&self.der)
    }

    /* =========================
     * Public API
     * ========================= */

    pub fn extract_publickey(&self) -> Result<Vec<u8>> {
        Ok(self.parse_any()?.public_key_bytes())
    }

    pub fn extract_private_key_bytes(&self) -> Result<Vec<u8>> {
        Ok(self.parse_any()?.private_key_bytes())
    }

    pub fn extract_curve_oid_and_name(&self) -> Result<(String, String)> {
        Ok(self.parse_any()?.curve_oid_and_name())
    }
}

/* =========================
 * Curve dispatch
 * ========================= */

enum ParsedEcKey {
    P224(P224SecretKey),
    P256(P256SecretKey),
    P384(P384SecretKey),
    P521(P521SecretKey),
}

impl ParsedEcKey {
    fn from_pkcs8(oid: &ObjectIdentifier, der: &[u8]) -> Result<Self> {
        match *oid {
            NistP224::OID => Ok(Self::P224(P224SecretKey::from_pkcs8_der(der)?)),
            NistP256::OID => Ok(Self::P256(P256SecretKey::from_pkcs8_der(der)?)),
            NistP384::OID => Ok(Self::P384(P384SecretKey::from_pkcs8_der(der)?)),
            NistP521::OID => Ok(Self::P521(P521SecretKey::from_pkcs8_der(der)?)),
            _ => bail!("Unsupported EC curve OID: {}", oid),
        }
    }

    fn from_sec1(der: &[u8]) -> Result<Self> {
        if let Ok(sk) = P224SecretKey::from_sec1_der(der) {
            return Ok(Self::P224(sk));
        }
        if let Ok(sk) = P256SecretKey::from_sec1_der(der) {
            return Ok(Self::P256(sk));
        }
        if let Ok(sk) = P384SecretKey::from_sec1_der(der) {
            return Ok(Self::P384(sk));
        }
        if let Ok(sk) = P521SecretKey::from_sec1_der(der) {
            return Ok(Self::P521(sk));
        }

        bail!("Failed to parse EC private key (PKCS#8 or SEC1)")
    }

    fn public_key_bytes(&self) -> Vec<u8> {
        match self {
            Self::P224(sk) => {
                use p224::elliptic_curve::sec1::ToEncodedPoint;
                sk.public_key().to_encoded_point(false).as_bytes().to_vec()
            }
            Self::P256(sk) => {
                use p256::elliptic_curve::sec1::ToEncodedPoint;
                sk.public_key().to_encoded_point(false).as_bytes().to_vec()
            }
            Self::P384(sk) => {
                use p384::elliptic_curve::sec1::ToEncodedPoint;
                sk.public_key().to_encoded_point(false).as_bytes().to_vec()
            }
            Self::P521(sk) => {
                use p521::elliptic_curve::sec1::ToEncodedPoint;
                sk.public_key().to_encoded_point(false).as_bytes().to_vec()
            }
        }
    }

    fn private_key_bytes(&self) -> Vec<u8> {
        match self {
            Self::P224(sk) => sk.to_bytes().to_vec(),
            Self::P256(sk) => sk.to_bytes().to_vec(),
            Self::P384(sk) => sk.to_bytes().to_vec(),
            Self::P521(sk) => sk.to_bytes().to_vec(),
        }
    }

    fn curve_oid_and_name(&self) -> (String, String) {
        match self {
            Self::P224(_) => (NistP224::OID.to_string(), "P-224".into()),
            Self::P256(_) => (NistP256::OID.to_string(), "P-256".into()),
            Self::P384(_) => (NistP384::OID.to_string(), "P-384".into()),
            Self::P521(_) => (NistP521::OID.to_string(), "P-521".into()),
        }
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

/* =========================
 * Tests
 * ========================= */

#[cfg(test)]
mod tests {
    use super::*;
    use pkcs8::EncodePrivateKey;
    use tempfile::NamedTempFile;
    use x509_parser::nom::AsBytes;

    fn pem_from_pkcs8(der: &[u8]) -> String {
        pem::encode(&pem::Pem::new("PRIVATE KEY", der.to_vec()))
    }

    #[test]
    fn from_pem_ok() {
        use p224::elliptic_curve::rand_core::OsRng;

        let sk = P256SecretKey::random(&mut OsRng);
        let der = sk.to_pkcs8_der().unwrap();
        let pem = pem_from_pkcs8(der.as_bytes());

        let key = ECPrivateKey::from_pem(&pem).unwrap();
        assert!(!key.der.is_empty());
    }

    #[test]
    fn load_privatekey_pem_ok() {
        use p384::elliptic_curve::rand_core::OsRng;

        let sk = P384SecretKey::random(&mut OsRng);
        let der = sk.to_pkcs8_der().unwrap();
        let pem = pem_from_pkcs8(der.as_bytes());

        let file = NamedTempFile::new().unwrap();
        fs::write(file.path(), pem).unwrap();

        let key = ECPrivateKey::load_privatekey_pem(file.path()).unwrap();
        assert!(!key.der.is_empty());
    }

    #[test]
    fn extract_publickey_p256() {
        use p256::elliptic_curve::rand_core::OsRng;

        let sk = P256SecretKey::random(&mut OsRng);
        let der = sk.to_pkcs8_der().unwrap();
        let key = ECPrivateKey::from_der(der.as_bytes().to_vec());

        let pk = key.extract_publickey().unwrap();
        assert_eq!(pk[0], 0x04);
        assert_eq!(pk.len(), 65);
    }

    #[test]
    fn extract_publickey_p384() {
        use p384::elliptic_curve::rand_core::OsRng;

        let sk = P384SecretKey::random(&mut OsRng);
        let der = sk.to_pkcs8_der().unwrap();
        let key = ECPrivateKey::from_der(der.as_bytes().to_vec());

        let pk = key.extract_publickey().unwrap();
        assert_eq!(pk.len(), 97);
    }

    #[test]
    fn extract_publickey_p521() {
        use p521::elliptic_curve::rand_core::OsRng;

        let sk = P521SecretKey::random(&mut OsRng);
        let der = sk.to_pkcs8_der().unwrap();
        let key = ECPrivateKey::from_der(der.as_bytes().to_vec());

        let pk = key.extract_publickey().unwrap();
        assert_eq!(pk.len(), 133);
    }

    #[test]
    fn extract_private_key_bytes_ok() {
        use p256::elliptic_curve::rand_core::OsRng;

        let sk = P256SecretKey::random(&mut OsRng);
        let der = sk.to_pkcs8_der().unwrap();
        let key = ECPrivateKey::from_der(der.as_bytes().to_vec());

        let raw = key.extract_private_key_bytes().unwrap();
        assert_eq!(raw.len(), 32);
    }

    #[test]
    fn extract_curve_oid_and_name_ok() {
        use p384::elliptic_curve::rand_core::OsRng;

        let sk = P384SecretKey::random(&mut OsRng);
        let der = sk.to_pkcs8_der().unwrap();
        let key = ECPrivateKey::from_der(der.as_bytes().to_vec());

        let (_, name) = key.extract_curve_oid_and_name().unwrap();
        assert_eq!(name, "P-384");
    }

    #[test]
    fn invalid_der_is_rejected() {
        let key = ECPrivateKey::from_der(b"garbage".to_vec());
        assert!(key.extract_publickey().is_err());
    }

    #[test]
    fn extract_publickey_p224_pkcs8() {
        use p224::elliptic_curve::rand_core::OsRng;

        let sk = P224SecretKey::random(&mut OsRng);
        let der = sk.to_pkcs8_der().unwrap();
        let key = ECPrivateKey::from_der(der.as_bytes().to_vec());

        let pk = key.extract_publickey().unwrap();

        // Uncompressed SEC1 format
        assert_eq!(pk[0], 0x04);
        // 1 + 28 + 28
        assert_eq!(pk.len(), 57);
    }

    #[test]
    fn extract_private_key_bytes_p224() {
        use p224::elliptic_curve::rand_core::OsRng;

        let sk = P224SecretKey::random(&mut OsRng);
        let der = sk.to_pkcs8_der().unwrap();
        let key = ECPrivateKey::from_der(der.as_bytes().to_vec());

        let raw = key.extract_private_key_bytes().unwrap();
        assert_eq!(raw.len(), 28);
    }

    #[test]
    fn extract_curve_oid_and_name_p224() {
        use p224::elliptic_curve::rand_core::OsRng;

        let sk = P224SecretKey::random(&mut OsRng);
        let der = sk.to_pkcs8_der().unwrap();
        let key = ECPrivateKey::from_der(der.as_bytes().to_vec());

        let (oid, name) = key.extract_curve_oid_and_name().unwrap();

        assert_eq!(oid, NistP224::OID.to_string());
        assert_eq!(name, "P-224");
    }

    #[test]
    fn from_pem_p224_pkcs8_ok() {
        use p224::elliptic_curve::rand_core::OsRng;

        let sk = P224SecretKey::random(&mut OsRng);
        let der = sk.to_pkcs8_der().unwrap();
        let pem = pem_from_pkcs8(der.as_bytes());

        let key = ECPrivateKey::from_pem(&pem).unwrap();
        let pk = key.extract_publickey().unwrap();

        assert_eq!(pk.len(), 57);
    }

    #[test]
    fn sec1_p224_is_accepted() {
        use p224::elliptic_curve::rand_core::OsRng;

        let sk = P224SecretKey::random(&mut OsRng);

        // Explicit SEC1 DER
        let sec1_der = sk.to_sec1_der().unwrap();
        let key = ECPrivateKey::from_der(sec1_der.as_bytes().to_vec());

        let pk = key.extract_publickey().unwrap();
        let raw = key.extract_private_key_bytes().unwrap();

        assert_eq!(pk.len(), 57);
        assert_eq!(raw.len(), 28);
    }

    #[test]
    fn p224_round_trip_private_key_matches() {
        use p224::elliptic_curve::rand_core::OsRng;

        let sk = P224SecretKey::random(&mut OsRng);
        let original_bytes = sk.to_bytes();

        let der = sk.to_pkcs8_der().unwrap();
        let key = ECPrivateKey::from_der(der.as_bytes().to_vec());

        let extracted = key.extract_private_key_bytes().unwrap();
        assert_eq!(original_bytes.as_bytes(), extracted);
    }

    #[test]
    fn extract_private_key_bytes_p256() {
        use p256::elliptic_curve::rand_core::OsRng;

        let sk = P256SecretKey::random(&mut OsRng);
        let der = sk.to_pkcs8_der().unwrap();
        let key = ECPrivateKey::from_der(der.as_bytes().to_vec());

        let raw = key.extract_private_key_bytes().unwrap();
        assert_eq!(raw.len(), 32);
    }

    #[test]
    fn extract_curve_oid_and_name_p256() {
        use p256::elliptic_curve::rand_core::OsRng;

        let sk = P256SecretKey::random(&mut OsRng);
        let der = sk.to_pkcs8_der().unwrap();
        let key = ECPrivateKey::from_der(der.as_bytes().to_vec());

        let (oid, name) = key.extract_curve_oid_and_name().unwrap();
        assert_eq!(oid, NistP256::OID.to_string());
        assert_eq!(name, "P-256");
    }

    #[test]
    fn sec1_p256_is_accepted() {
        use p256::elliptic_curve::rand_core::OsRng;

        let sk = P256SecretKey::random(&mut OsRng);
        let sec1_der = sk.to_sec1_der().unwrap();
        let key = ECPrivateKey::from_der(sec1_der.as_bytes().to_vec());

        let pk = key.extract_publickey().unwrap();
        let raw = key.extract_private_key_bytes().unwrap();

        assert_eq!(pk.len(), 65);
        assert_eq!(raw.len(), 32);
    }

    #[test]
    fn p256_round_trip_private_key_matches() {
        use p256::elliptic_curve::rand_core::OsRng;

        let sk = P256SecretKey::random(&mut OsRng);
        let original = sk.to_bytes();

        let der = sk.to_pkcs8_der().unwrap();
        let key = ECPrivateKey::from_der(der.as_bytes().to_vec());

        let extracted = key.extract_private_key_bytes().unwrap();
        assert_eq!(original.as_bytes(), extracted);
    }

    #[test]
    fn extract_private_key_bytes_p384() {
        use p384::elliptic_curve::rand_core::OsRng;

        let sk = P384SecretKey::random(&mut OsRng);
        let der = sk.to_pkcs8_der().unwrap();
        let key = ECPrivateKey::from_der(der.as_bytes().to_vec());

        let raw = key.extract_private_key_bytes().unwrap();
        assert_eq!(raw.len(), 48);
    }

    #[test]
    fn extract_curve_oid_and_name_p384_full() {
        use p384::elliptic_curve::rand_core::OsRng;

        let sk = P384SecretKey::random(&mut OsRng);
        let der = sk.to_pkcs8_der().unwrap();
        let key = ECPrivateKey::from_der(der.as_bytes().to_vec());

        let (oid, name) = key.extract_curve_oid_and_name().unwrap();
        assert_eq!(oid, NistP384::OID.to_string());
        assert_eq!(name, "P-384");
    }

    #[test]
    fn sec1_p384_is_accepted() {
        use p384::elliptic_curve::rand_core::OsRng;

        let sk = P384SecretKey::random(&mut OsRng);
        let sec1_der = sk.to_sec1_der().unwrap();
        let key = ECPrivateKey::from_der(sec1_der.as_bytes().to_vec());

        let pk = key.extract_publickey().unwrap();
        let raw = key.extract_private_key_bytes().unwrap();

        assert_eq!(pk.len(), 97);
        assert_eq!(raw.len(), 48);
    }

    #[test]
    fn p384_round_trip_private_key_matches() {
        use p384::elliptic_curve::rand_core::OsRng;

        let sk = P384SecretKey::random(&mut OsRng);
        let original = sk.to_bytes();

        let der = sk.to_pkcs8_der().unwrap();
        let key = ECPrivateKey::from_der(der.as_bytes().to_vec());

        let extracted = key.extract_private_key_bytes().unwrap();
        assert_eq!(original.as_bytes(), extracted);
    }

    #[test]
    fn extract_private_key_bytes_p521() {
        use p521::elliptic_curve::rand_core::OsRng;

        let sk = P521SecretKey::random(&mut OsRng);
        let der = sk.to_pkcs8_der().unwrap();
        let key = ECPrivateKey::from_der(der.as_bytes().to_vec());

        let raw = key.extract_private_key_bytes().unwrap();
        assert_eq!(raw.len(), 66);
    }

    #[test]
    fn extract_curve_oid_and_name_p521() {
        use p521::elliptic_curve::rand_core::OsRng;

        let sk = P521SecretKey::random(&mut OsRng);
        let der = sk.to_pkcs8_der().unwrap();
        let key = ECPrivateKey::from_der(der.as_bytes().to_vec());

        let (oid, name) = key.extract_curve_oid_and_name().unwrap();
        assert_eq!(oid, NistP521::OID.to_string());
        assert_eq!(name, "P-521");
    }

    #[test]
    fn sec1_p521_is_accepted() {
        use p521::elliptic_curve::rand_core::OsRng;

        let sk = P521SecretKey::random(&mut OsRng);
        let sec1_der = sk.to_sec1_der().unwrap();
        let key = ECPrivateKey::from_der(sec1_der.as_bytes().to_vec());

        let pk = key.extract_publickey().unwrap();
        let raw = key.extract_private_key_bytes().unwrap();

        assert_eq!(pk.len(), 133);
        assert_eq!(raw.len(), 66);
    }

    #[test]
    fn p521_round_trip_private_key_matches() {
        use p521::elliptic_curve::rand_core::OsRng;

        let sk = P521SecretKey::random(&mut OsRng);
        let original = sk.to_bytes();

        let der = sk.to_pkcs8_der().unwrap();
        let key = ECPrivateKey::from_der(der.as_bytes().to_vec());

        let extracted = key.extract_private_key_bytes().unwrap();
        assert_eq!(original.as_bytes(), extracted);
    }
}

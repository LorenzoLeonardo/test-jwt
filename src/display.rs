use std::fmt;

use time::OffsetDateTime;
use x509_parser::{
    prelude::{FromDer, ParsedExtension, X509Certificate},
    time::ASN1Time,
};

use crate::certificate::ECX509Cert;

impl fmt::Display for ECX509Cert {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for (idx, der) in self.as_ref().iter().enumerate() {
            let cert = match X509Certificate::from_der(der) {
                Ok((_, cert)) => cert,
                Err(e) => {
                    writeln!(f, "Certificate {}: <parse error: {}>", idx, e)?;
                    continue;
                }
            };

            if self.as_ref().len() > 1 {
                writeln!(f, "Certificate {}:", idx)?;
            } else {
                writeln!(f, "Certificate:")?;
            }

            dump_cert(f, &cert)?;
            if idx + 1 < self.as_ref().len() {
                writeln!(f)?;
            }
        }
        Ok(())
    }
}

fn dump_cert(f: &mut fmt::Formatter<'_>, cert: &X509Certificate) -> fmt::Result {
    let tbs = &cert.tbs_certificate;

    writeln!(f, "    Data:")?;

    // Version
    writeln!(
        f,
        "        Version: {} ({:#x})",
        tbs.version().0 + 1,
        tbs.version().0
    )?;

    // Serial Number
    writeln!(f, "        Serial Number:")?;
    writeln!(f, "            {}", hex_colon(tbs.raw_serial()))?;

    // Signature Algorithm
    writeln!(
        f,
        "        Signature Algorithm: {}",
        tbs.signature.algorithm.to_id_string()
    )?;

    // Issuer
    writeln!(f, "        Issuer: {}", tbs.issuer)?;

    // Validity
    writeln!(f, "        Validity")?;
    writeln!(
        f,
        "            Not Before: {}",
        format_time(&tbs.validity.not_before)
    )?;
    writeln!(
        f,
        "            Not After : {}",
        format_time(&tbs.validity.not_after)
    )?;

    // Subject
    writeln!(f, "        Subject: {}", tbs.subject)?;

    // Subject Public Key Info
    let spki = &tbs.subject_pki;
    writeln!(f, "        Subject Public Key Info:")?;
    writeln!(
        f,
        "            Public Key Algorithm: {}",
        spki.algorithm.algorithm.to_id_string()
    )?;

    if let Some(params) = &spki.algorithm.parameters
        && let Ok(oid) = params.as_oid()
    {
        writeln!(f, "                ASN1 OID: {}", oid.to_id_string())?;
    }

    let pubkey = &spki.subject_public_key.data;
    writeln!(f, "                Public-Key: ({} bit)", pubkey.len() * 8)?;
    writeln!(f, "                pub:")?;
    for chunk in pubkey.chunks(15) {
        writeln!(f, "                    {}", hex_colon(chunk))?;
    }

    // Extensions
    writeln!(f, "        X509v3 extensions:")?;
    for ext in tbs.extensions().iter() {
        match ext.parsed_extension() {
            ParsedExtension::BasicConstraints(bc) => {
                writeln!(
                    f,
                    "            X509v3 Basic Constraints:{}",
                    if ext.critical { " critical" } else { "" }
                )?;
                writeln!(f, "                CA:{}", bc.ca)?;
            }
            ParsedExtension::KeyUsage(ku) => {
                writeln!(
                    f,
                    "            X509v3 Key Usage:{}",
                    if ext.critical { " critical" } else { "" }
                )?;
                writeln!(f, "                {:?}", ku)?;
            }
            ParsedExtension::ExtendedKeyUsage(eku) => {
                writeln!(f, "            X509v3 Extended Key Usage:")?;
                for oid in &eku.other {
                    writeln!(f, "                {}", oid.to_id_string())?;
                }
            }
            ParsedExtension::SubjectKeyIdentifier(ski) => {
                writeln!(f, "            X509v3 Subject Key Identifier:")?;
                writeln!(f, "                {}", hex_colon(ski.0))?;
            }
            _ => {
                writeln!(f, "            {}:", ext.oid.to_id_string())?;
            }
        }
    }

    // Signature
    writeln!(
        f,
        "    Signature Algorithm: {}",
        cert.signature_algorithm.algorithm
    )?;

    writeln!(f, "    Signature Value:")?;
    for chunk in cert.signature_value.data.chunks(18) {
        writeln!(f, "        {}", hex_colon(chunk))?;
    }

    Ok(())
}

fn hex_colon(bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(|b| format!("{:02X}", b))
        .collect::<Vec<_>>()
        .join(":")
}

fn format_time(t: &ASN1Time) -> String {
    let dt: OffsetDateTime = t.to_datetime();
    dt.format(&time::format_description::well_known::Rfc2822)
        .unwrap()
}

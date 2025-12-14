use crate::certificate::ECX509Cert;
use crate::privatekey::ECPrivateKey;

#[test_case::test_case("ec384-cert.pem", "ec384-private.pem")]
#[test_case::test_case("ec256-cert.pem", "ec256-private.pem")]
#[test_case::test_case("ec521-cert.pem", "ec521-private.pem")]
#[test_case::test_case("ec384-oldcert.pem", "ec384-oldprivate.pem")]
fn test_actual_file_ec(cert: &str, privkey: &str) -> anyhow::Result<()> {
    let private_key = ECPrivateKey::load_privatekey_pem(privkey).unwrap();
    let pubkey_from_priv = private_key.extract_publickey().unwrap();

    let x509 = ECX509Cert::load_x509_pem(cert).unwrap();
    let pubkey_from_cert = x509.extract_publickey(0).unwrap();

    assert_eq!(pubkey_from_priv, pubkey_from_cert);
    Ok(())
}

use crate::certificate::ECX509Cert;
use crate::privatekey::ECPrivateKey;

#[test_case::test_case("ec224/ec224-cert.pem", "ec224/ec224-private.pem")]
#[test_case::test_case("ec256/ec256-cert.pem", "ec256/ec256-private.pem")]
#[test_case::test_case("ec384/ec384-cert.pem", "ec384/ec384-private.pem")]
#[test_case::test_case("ec521/ec521-cert.pem", "ec521/ec521-private.pem")]
#[test_case::test_case("ec224/ec224-oldcert.pem", "ec224/ec224-oldprivate.pem")]
#[test_case::test_case("ec256/ec256-oldcert.pem", "ec256/ec256-oldprivate.pem")]
#[test_case::test_case("ec384/ec384-oldcert.pem", "ec384/ec384-oldprivate.pem")]
#[test_case::test_case("ec521/ec521-oldcert.pem", "ec521/ec521-oldprivate.pem")]
fn test_actual_file_ec(cert: &str, privkey: &str) -> anyhow::Result<()> {
    let private_key = ECPrivateKey::load_privatekey_pem(privkey).unwrap();
    let pubkey_from_priv = private_key.extract_publickey().unwrap();

    let x509 = ECX509Cert::load_x509_pem(cert).unwrap();
    let pubkey_from_cert = x509.ec_public_key(0).unwrap();

    assert_eq!(pubkey_from_priv, pubkey_from_cert.sec1_bytes);
    Ok(())
}

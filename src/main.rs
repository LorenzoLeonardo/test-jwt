mod certificate;
mod display;
mod privatekey;

#[cfg(test)]
mod test;

use crate::certificate::ECX509Cert;
use crate::privatekey::ECPrivateKey;

fn main() -> anyhow::Result<()> {
    test_ec("ec224/ec224-cert.pem", "ec224/ec224-private.pem")?;
    test_ec("ec256/ec256-cert.pem", "ec256/ec256-private.pem")?;
    test_ec("ec384/ec384-cert.pem", "ec384/ec384-private.pem")?;
    test_ec("ec521/ec521-cert.pem", "ec521/ec521-private.pem")?;
    test_ec("ec224/ec224-oldcert.pem", "ec224/ec224-oldprivate.pem")?;
    test_ec("ec256/ec256-oldcert.pem", "ec256/ec256-oldprivate.pem")?;
    test_ec("ec384/ec384-oldcert.pem", "ec384/ec384-oldprivate.pem")?;
    test_ec("ec521/ec521-oldcert.pem", "ec521/ec521-oldprivate.pem")?;
    Ok(())
}

fn test_ec(cert: &str, privkey: &str) -> anyhow::Result<()> {
    let private_key = ECPrivateKey::load_privatekey_pem(privkey)?;
    let pubkey_from_priv = private_key.extract_publickey()?;
    println!("{private_key}");

    let x509 = ECX509Cert::load_x509_pem(cert)?;
    let pubkey_from_cert = x509.ec_public_key(0)?;
    println!("Num Certs: {}", x509.num_certs());
    println!("{x509}");

    assert_eq!(pubkey_from_priv, pubkey_from_cert.sec1_bytes);
    Ok(())
}

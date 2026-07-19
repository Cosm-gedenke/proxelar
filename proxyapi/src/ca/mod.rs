pub mod cert_server;

use std::{
    path::Path,
    sync::Arc,
    time::{Duration, SystemTime},
};

use async_trait::async_trait;
use bytes::Bytes;
use http::uri::Authority;
use moka::future::Cache;
use openssl::{
    asn1::{Asn1Integer, Asn1Time},
    bn::BigNum,
    ec::{EcGroup, EcKey},
    hash::MessageDigest,
    nid::Nid,
    pkey::{PKey, Private},
    rand,
    x509::{
        extension::{BasicConstraints, KeyUsage, SubjectAlternativeName},
        X509Builder, X509NameBuilder, X509,
    },
};
use rustls_pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use tokio_rustls::rustls::ServerConfig;

const TTL_SECS: i64 = 365 * 24 * 60 * 60;
const CACHE_TTL: u64 = TTL_SECS as u64 / 2;
const NOT_BEFORE_OFFSET: i64 = 60;
const CA_TTL_SECS: i64 = 10 * 365 * 24 * 60 * 60;

#[async_trait]
pub trait CertificateAuthority: Send + Sync + 'static {
    async fn gen_server_config(
        &self,
        authority: &Authority,
    ) -> Result<Arc<ServerConfig>, crate::error::Error>;
}

#[derive(Clone)]
pub struct Ssl {
    pkey: PKey<Private>,
    ca_cert: X509,
    ca_cert_pem: Bytes,
    hash: MessageDigest,
    cache: Cache<Authority, Arc<ServerConfig>>,
}

impl Ssl {
    pub fn load_or_generate(dir: &Path) -> Result<Self, crate::error::Error> {
        std::fs::create_dir_all(dir)?;

        let cert_path = dir.join("proxelar-ca.pem");
        let key_path = dir.join("proxelar-ca.key");

        let (pkey, ca_cert) = if cert_path.exists() && key_path.exists() {
            tracing::info!("Loading CA certificate from {}", dir.display());
            let key_pem = std::fs::read(&key_path)?;
            let cert_pem = std::fs::read(&cert_path)?;
            let pkey = PKey::private_key_from_pem(&key_pem)?;
            let ca_cert = X509::from_pem(&cert_pem)?;

            // Verify the loaded key matches the certificate
            if !ca_cert.public_key()?.public_eq(&pkey) {
                return Err(crate::error::Error::Other(
                    "CA certificate does not match private key".into(),
                ));
            }

            (pkey, ca_cert)
        } else {
            tracing::info!("Generating new CA certificate in {}", dir.display());
            let (pkey, ca_cert) = generate_ca()?;

            let key_pem = pkey.private_key_to_pem_pkcs8()?;
            let cert_pem = ca_cert.to_pem()?;

            std::fs::write(&key_path, &key_pem)?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                std::fs::set_permissions(&key_path, std::fs::Permissions::from_mode(0o600))?;
            }
            std::fs::write(&cert_path, &cert_pem)?;

            (pkey, ca_cert)
        };

        let ca_cert_pem = Bytes::from(ca_cert.to_pem()?);

        Ok(Self {
            pkey,
            ca_cert,
            ca_cert_pem,
            hash: MessageDigest::sha256(),
            cache: Cache::builder()
                .max_capacity(1_000)
                .time_to_live(Duration::from_secs(CACHE_TTL))
                .build(),
        })
    }

    pub fn ca_cert_pem(&self) -> Bytes {
        self.ca_cert_pem.clone()
    }

    fn gen_cert(
        &self,
        authority: &Authority,
    ) -> Result<(CertificateDer<'static>, PrivateKeyDer<'static>), crate::error::Error> {
        // Every leaf gets its own P-256 key. Reusing the CA private key as the
        // server key would unnecessarily expose the root of trust to every TLS
        // handshake and makes key rotation/auditing much harder.
        let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1)?;
        let leaf_key = PKey::from_ec_key(EcKey::generate(&group)?)?;
        let mut name_builder = X509NameBuilder::new()?;
        name_builder.append_entry_by_text("CN", authority.host())?;
        let name = name_builder.build();

        let mut x509_builder = X509Builder::new()?;
        x509_builder.set_subject_name(&name)?;
        x509_builder.set_version(2)?;

        let not_before = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)?
            .as_secs() as i64
            - NOT_BEFORE_OFFSET;
        x509_builder.set_not_before(Asn1Time::from_unix(not_before)?.as_ref())?;
        x509_builder.set_not_after(Asn1Time::from_unix(not_before + TTL_SECS)?.as_ref())?;

        x509_builder.set_pubkey(&leaf_key)?;
        x509_builder.set_issuer_name(self.ca_cert.subject_name())?;

        let mut alternative_names = SubjectAlternativeName::new();
        if authority.host().parse::<std::net::IpAddr>().is_ok() {
            alternative_names.ip(authority.host());
        } else {
            alternative_names.dns(authority.host());
        }
        let alternative_name =
            alternative_names.build(&x509_builder.x509v3_context(Some(&self.ca_cert), None))?;
        x509_builder.append_extension(alternative_name)?;

        let mut serial_number = [0; 16];
        rand::rand_bytes(&mut serial_number)?;

        let serial_number = BigNum::from_slice(&serial_number)?;
        let serial_number = Asn1Integer::from_bn(&serial_number)?;
        x509_builder.set_serial_number(&serial_number)?;

        x509_builder.sign(&self.pkey, self.hash)?;
        let x509 = x509_builder.build();
        let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(leaf_key.private_key_to_pkcs8()?));
        Ok((CertificateDer::from(x509.to_der()?), key))
    }
}

fn generate_ca() -> Result<(PKey<Private>, X509), crate::error::Error> {
    let rsa = openssl::rsa::Rsa::generate(4096)?;
    let pkey = PKey::from_rsa(rsa)?;

    let mut name_builder = X509NameBuilder::new()?;
    name_builder.append_entry_by_text("CN", "proxelar")?;
    name_builder.append_entry_by_text("O", "Proxelar")?;
    let name = name_builder.build();

    let mut builder = X509Builder::new()?;
    builder.set_version(2)?;
    builder.set_subject_name(&name)?;
    builder.set_issuer_name(&name)?;
    builder.set_pubkey(&pkey)?;

    let not_before = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)?
        .as_secs() as i64
        - NOT_BEFORE_OFFSET;
    builder.set_not_before(Asn1Time::from_unix(not_before)?.as_ref())?;
    builder.set_not_after(Asn1Time::from_unix(not_before + CA_TTL_SECS)?.as_ref())?;

    let mut serial_number = [0; 16];
    rand::rand_bytes(&mut serial_number)?;
    let serial_number = BigNum::from_slice(&serial_number)?;
    let serial_number = Asn1Integer::from_bn(&serial_number)?;
    builder.set_serial_number(&serial_number)?;

    let basic_constraints = BasicConstraints::new().critical().ca().build()?;
    builder.append_extension(basic_constraints)?;

    let key_usage = KeyUsage::new()
        .critical()
        .key_cert_sign()
        .crl_sign()
        .build()?;
    builder.append_extension(key_usage)?;

    builder.sign(&pkey, MessageDigest::sha512())?;
    let cert = builder.build();

    Ok((pkey, cert))
}

#[async_trait]
impl CertificateAuthority for Ssl {
    async fn gen_server_config(
        &self,
        authority: &Authority,
    ) -> Result<Arc<ServerConfig>, crate::error::Error> {
        if let Some(server_cfg) = self.cache.get(authority).await {
            tracing::debug!("Using cached server config for {authority}");
            return Ok(server_cfg);
        }
        tracing::debug!("Generating server config for {authority}");

        let (certificate, private_key) = self.gen_cert(authority)?;
        let certs = vec![certificate];

        let mut server_cfg = ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(certs, private_key)?;

        server_cfg.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];

        let server_cfg = Arc::new(server_cfg);

        self.cache
            .insert(authority.clone(), Arc::clone(&server_cfg))
            .await;

        Ok(server_cfg)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn minted_leaf_uses_a_distinct_matching_private_key() {
        let directory = tempfile::tempdir().unwrap();
        let ssl = Ssl::load_or_generate(directory.path()).unwrap();
        let authority: Authority = "api.example.test:443".parse().unwrap();

        let (certificate, private_key) = ssl.gen_cert(&authority).unwrap();
        let leaf = X509::from_der(certificate.as_ref()).unwrap();
        let leaf_key = PKey::private_key_from_pkcs8(private_key.secret_der()).unwrap();
        let leaf_public = leaf.public_key().unwrap();

        assert!(leaf_public.public_eq(&leaf_key));
        assert!(!leaf_public.public_eq(&ssl.pkey));
    }

    #[test]
    fn minted_ip_leaf_uses_an_ip_subject_alternative_name() {
        let directory = tempfile::tempdir().unwrap();
        let ssl = Ssl::load_or_generate(directory.path()).unwrap();
        let authority: Authority = "127.0.0.1:443".parse().unwrap();

        let (certificate, _) = ssl.gen_cert(&authority).unwrap();
        let leaf = X509::from_der(certificate.as_ref()).unwrap();
        let names = leaf.subject_alt_names().unwrap();

        assert!(names
            .iter()
            .any(|name| name.ipaddress() == Some([127, 0, 0, 1].as_slice())));
        assert!(names.iter().all(|name| name.dnsname().is_none()));
    }
}

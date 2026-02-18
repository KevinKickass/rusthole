use anyhow::Result;
use std::sync::Arc;
use tokio_rustls::rustls::ServerConfig;
use tokio_rustls::rustls::pki_types::{CertificateDer, PrivateKeyDer};

/// Load TLS config from cert/key files, or generate a self-signed cert.
pub fn load_tls_config(cert_path: Option<&str>, key_path: Option<&str>) -> Result<Arc<ServerConfig>> {
    let (certs, key) = match (cert_path, key_path) {
        (Some(cert_p), Some(key_p)) => {
            let cert_data = std::fs::read(cert_p)?;
            let key_data = std::fs::read(key_p)?;
            let certs = rustls_pemfile::certs(&mut &cert_data[..])
                .collect::<std::result::Result<Vec<_>, _>>()?;
            let key = rustls_pemfile::private_key(&mut &key_data[..])?
                .ok_or_else(|| anyhow::anyhow!("No private key found in {key_p}"))?;
            (certs, key)
        }
        _ => {
            tracing::info!("Generating self-signed TLS certificate for DNS services");
            let cert = rcgen::generate_simple_self_signed(vec![
                "localhost".to_string(),
                "dns.localhost".to_string(),
            ])?;
            let cert_der = CertificateDer::from(cert.cert);
            let key_der = PrivateKeyDer::Pkcs8(cert.key_pair.serialize_der().into());
            (vec![cert_der], key_der)
        }
    };

    let config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)?;

    Ok(Arc::new(config))
}

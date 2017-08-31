use super::common::sha256_hex;

use acme_client;
use chrono;
use openssl;
use rustls;
use std;
use std::collections::HashMap;
use std::fs::{self, File};
use std::io::{Cursor, Read, Write};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};


pub trait CertificateCache: Send + Sync {
    fn store_certificate(&self, identifier: &str, chain: &str, private_key: &str);
    fn fetch_certificate(&self, identifier: &str) -> Option<(String, String)>;
}

fn domains_to_identifier(acme_url: &str, domains: &[String]) -> String {
    sha256_hex(format!("{}|{}", acme_url, domains.join("|")).as_bytes())
}

pub struct DiskCache {
    location: PathBuf,
}

impl DiskCache {
    pub fn new(location: PathBuf) -> DiskCache {
        fs::create_dir_all(&location).unwrap();
        DiskCache { location: location }
    }

    fn chain_path(&self, identifier: &str) -> PathBuf {
        self.location.join(identifier.to_string() + ".chain.pem")
    }

    fn key_path(&self, identifier: &str) -> PathBuf {
        self.location.join(identifier.to_string() + ".key.pem")
    }
}

impl CertificateCache for DiskCache {
    fn store_certificate(&self, identifier: &str, chain: &str, private_key: &str) {
        File::create(self.chain_path(identifier))
            .unwrap()
            .write_all(chain.as_bytes())
            .unwrap();
        File::create(self.key_path(identifier))
            .unwrap()
            .write_all(private_key.as_bytes())
            .unwrap();
    }

    fn fetch_certificate(&self, identifier: &str) -> Option<(String, String)> {
        match (
            File::open(self.chain_path(identifier)),
            File::open(self.key_path(identifier)),
        ) {
            (Ok(mut chain_file), Ok(mut key_file)) => {
                let mut chain_pem = String::new();
                chain_file.read_to_string(&mut chain_pem).unwrap();
                let mut key_pem = String::new();
                key_file.read_to_string(&mut key_pem).unwrap();
                Some((chain_pem, key_pem))
            }
            _ => None,
        }
    }
}

pub struct AutomaticCertResolver<C>
where
    C: CertificateCache,
{
    domains: Vec<String>,
    acme_url: String,
    acme_account: acme_client::Account,
    active_cert: Mutex<Option<rustls::sign::CertifiedKey>>,
    cert_cache: C,
    sni_challenges: Mutex<HashMap<String, rustls::sign::CertifiedKey>>,
}


impl<C> AutomaticCertResolver<C>
where
    C: CertificateCache,
{
    pub fn new(acme_url: &str, domains: Vec<String>, cache: C) -> AutomaticCertResolver<C> {
        let acme_directory = acme_client::Directory::from_url(acme_url).unwrap();
        let pems = cache.fetch_certificate(&domains_to_identifier(acme_url, &domains));
        let active_cert = Mutex::new(pems.map(|(chain_pem, private_key_pem)| {
            pems_to_rustls(&chain_pem, &private_key_pem)
        }));
        AutomaticCertResolver {
            domains: domains,
            cert_cache: cache,
            acme_url: acme_url.to_string(),
            acme_account: acme_directory.account_registration().register().unwrap(),
            active_cert: active_cert,
            sni_challenges: Mutex::new(HashMap::new()),
        }
    }

    fn obtain_new_certificate(&self) {
        // Can't do the smart thing of setting them all up, and then triggering the validations in
        // parallel and waiting for the results because acme-client doesn't expose seperate
        // "trigger validation" and "wait for success" functions.
        for domain in &self.domains {
            let authorization = self.acme_account.authorization(domain).unwrap();
            let tls_sni_challenge = authorization.get_tls_sni_challenge().unwrap();
            self.setup_sni_challenge(tls_sni_challenge);
            tls_sni_challenge.validate().unwrap();
            self.teardown_sni_challenge(tls_sni_challenge);
        }
        let cert = self.acme_account
            .certificate_signer(&self.domains
                .iter()
                .map(|s| s.as_ref())
                .collect::<Vec<&str>>())
            .sign_certificate()
            .unwrap();
        // TODO: intermediates
        let chain = vec![openssl_cert_to_rustls(cert.cert())];
        let signer = openssl_pkey_to_rustls_signer(cert.pkey());
        *self.active_cert.lock().unwrap() =
            Some(rustls::sign::CertifiedKey::new(chain, Arc::new(signer)));
        self.cert_cache.store_certificate(
            &domains_to_identifier(&self.acme_url, &self.domains),
            std::str::from_utf8(&cert.cert().to_pem().unwrap()).unwrap(),
            // TODO: ECDSA
            std::str::from_utf8(
                &cert.pkey().rsa().unwrap().private_key_to_pem().unwrap(),
            ).unwrap(),
        );
    }

    fn setup_sni_challenge(&self, challenge: &acme_client::Challenge) {
        let z_domain = z_domain(challenge);
        let (cert, pkey) = generate_temporary_cert(&z_domain);

        let chain = vec![openssl_cert_to_rustls(&cert)];
        let signer = openssl_pkey_to_rustls_signer(&pkey);
        self.sni_challenges.lock().unwrap().insert(
            z_domain,
            rustls::sign::CertifiedKey::new(chain, Arc::new(signer)),
        );
    }

    fn teardown_sni_challenge(&self, challenge: &acme_client::Challenge) {
        let z_domain = z_domain(challenge);
        self.sni_challenges.lock().unwrap().remove(&z_domain);
    }
}

fn z_domain(challenge: &acme_client::Challenge) -> String {
    let z = sha256_hex(challenge.key_authorization().as_bytes());
    let (z1, z2) = z.split_at(32);
    return format!("{}.{}.acme.invalid", z1, z2);
}

pub fn generate_temporary_cert(domain: &str) -> (openssl::x509::X509, openssl::pkey::PKey) {
    let pkey = openssl::pkey::PKey::from_rsa(openssl::rsa::Rsa::generate(2048).unwrap()).unwrap();
    let mut cert_builder = openssl::x509::X509Builder::new().unwrap();
    cert_builder.set_version(2).unwrap();
    cert_builder.set_pubkey(&pkey).unwrap();

    let mut serial = openssl::bn::BigNum::new().unwrap();
    serial
        .rand(128, openssl::bn::MSB_MAYBE_ZERO, false)
        .unwrap();
    cert_builder
        .set_serial_number(&serial.to_asn1_integer().unwrap())
        .unwrap();

    let mut subject_builder = openssl::x509::X509NameBuilder::new().unwrap();
    subject_builder
        .append_entry_by_text("CN", "ACME SNI Challenge Certificate")
        .unwrap();
    let subject = subject_builder.build();
    cert_builder.set_subject_name(&subject).unwrap();
    cert_builder.set_issuer_name(&subject).unwrap();

    cert_builder
        .set_not_before(&openssl::asn1::Asn1Time::days_from_now(0).unwrap())
        .unwrap();
    cert_builder
        .set_not_after(&openssl::asn1::Asn1Time::days_from_now(1).unwrap())
        .unwrap();

    let mut san = openssl::x509::extension::SubjectAlternativeName::new();
    san.dns(domain);
    let san_ext = san.build(&cert_builder.x509v3_context(None, None)).unwrap();
    cert_builder.append_extension(san_ext).unwrap();

    cert_builder
        .sign(&pkey, openssl::hash::MessageDigest::sha256())
        .unwrap();

    (cert_builder.build(), pkey)
}

pub fn openssl_cert_to_rustls(cert: &openssl::x509::X509) -> rustls::Certificate {
    rustls::Certificate(cert.to_der().unwrap())
}

pub fn openssl_pkey_to_rustls(pkey: &openssl::pkey::PKey) -> rustls::PrivateKey {
    rustls::PrivateKey(pkey.rsa().unwrap().private_key_to_der().unwrap())
}

fn openssl_pkey_to_rustls_signer(pkey: &openssl::pkey::PKey) -> Box<rustls::sign::SigningKey> {
    // TODO: ECDSA
    Box::new(
        rustls::sign::RSASigningKey::new(&openssl_pkey_to_rustls(pkey)).unwrap(),
    )
}

fn pems_to_rustls(chain_pem: &str, private_key_pem: &str) -> rustls::sign::CertifiedKey {
    let chain = rustls::internal::pemfile::certs(&mut Cursor::new(chain_pem)).unwrap();
    // TODO: ECDSA
    let private_key =
        &rustls::internal::pemfile::rsa_private_keys(&mut Cursor::new(private_key_pem)).unwrap()[0];
    rustls::sign::CertifiedKey::new(
        chain,
        Arc::new(Box::new(
            rustls::sign::RSASigningKey::new(private_key).unwrap(),
        )),
    )
}

impl<C> rustls::ResolvesServerCert for AutomaticCertResolver<C>
where
    C: CertificateCache,
{
    fn resolve(
        &self,
        server_name: Option<&str>,
        _: &[rustls::SignatureScheme],
    ) -> Option<rustls::sign::CertifiedKey> {

        if let Some(sni) = server_name {
            if let Some(cert) = self.sni_challenges.lock().unwrap().get(sni) {
                return Some(cert.clone());
            }
        }
        // Seperate scope so that the lock isn't held we enter `obtain_new_certificate`.
        {
            let active_cert = self.active_cert.lock().unwrap();
            if cert_is_valid(&active_cert) {
                // TODO: if it's _close_ to expiring, trigger a background "obtain new cert"
                return active_cert.clone();
            }
        }
        // TODO: Don't try to obtain a new cert if we're currently waiting for one already...
        self.obtain_new_certificate();
        self.active_cert.lock().unwrap().clone()
    }
}

fn cert_is_valid(cert: &Option<rustls::sign::CertifiedKey>) -> bool {
    match *cert {
        Some(ref key) => !cert_is_expired(&key.cert[0]),
        None => false,
    }
}

fn cert_is_expired(cert: &rustls::Certificate) -> bool {
    let openssl_cert = openssl::x509::X509::from_der(&cert.0).unwrap();
    from_asn1_time(openssl_cert.not_after()) < chrono::Utc::now()
}


fn from_asn1_time(t: &openssl::asn1::Asn1TimeRef) -> chrono::DateTime<chrono::Utc> {
    let dt = chrono::DateTime::parse_from_str(
        &t.to_string().replace(" GMT", " +00:00"),
        "%b %e %T %Y %z",
    ).unwrap();
    chrono::DateTime::<chrono::Utc>::from_utc(dt.naive_utc(), chrono::Utc)
}

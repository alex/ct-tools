use std::cell::Cell;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use acme_client;
use chrono;
use openssl;
use rustls;

use super::common::sha256_hex;


pub struct AutomaticCertResolver {
    domains: Vec<String>,
    acme_account: acme_client::Account,
    active_cert: Mutex<Cell<Option<rustls::sign::CertChainAndSigner>>>,
    sni_challenges: Mutex<HashMap<String, rustls::sign::CertChainAndSigner>>,
}


// TODO: Disk cache for reading/writing certs so it doesn't have to obtain a new one on process
// startup everytime.
impl AutomaticCertResolver {
    pub fn new(domains: Vec<String>) -> AutomaticCertResolver {
        // TODO: configure URL
        let acme_directory = acme_client::Directory::from_url("https://acme-staging.api.letsencrypt.org/directory")
            .unwrap();
        return AutomaticCertResolver {
                   domains: domains,
                   acme_account: acme_directory
                       .account_registration()
                       .register()
                       .unwrap(),
                   active_cert: Mutex::new(Cell::new(None)),
                   sni_challenges: Mutex::new(HashMap::new()),
               };
    }

    fn obtain_new_certificate(&self) {
        // Can't do the smart thing of setting them all up, and then triggering the validations in
        // parallel and waiting for the results because acme-client doesn't expose seperate
        // "trigger validation" and "wait for success" functions.
        for domain in self.domains.iter() {
            let authorization = self.acme_account.authorization(&domain).unwrap();
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
        let signer = openssl_pkey_to_rustls(cert.pkey());
        self.active_cert
            .lock()
            .unwrap()
            .replace(Some((chain, Arc::new(signer))));
    }

    fn setup_sni_challenge(&self, challenge: &acme_client::Challenge) {
        let z_domain = z_domain(challenge);
        let (cert, pkey) = generate_temporary_cert(&z_domain);

        let chain = vec![openssl_cert_to_rustls(&cert)];
        let signer = openssl_pkey_to_rustls(&pkey);
        self.sni_challenges
            .lock()
            .unwrap()
            .insert(z_domain, (chain, Arc::new(signer)));
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

fn generate_temporary_cert(domain: &str) -> (openssl::x509::X509, openssl::pkey::PKey) {
    let pkey = openssl::pkey::PKey::from_rsa(openssl::rsa::Rsa::generate(2048).unwrap()).unwrap();
    let mut cert_builder = openssl::x509::X509Builder::new().unwrap();
    cert_builder.set_version(2).unwrap();
    cert_builder.set_pubkey(&pkey).unwrap();

    let mut san = openssl::x509::extension::SubjectAlternativeName::new();
    san.dns(domain);
    let san_ext = san.build(&cert_builder.x509v3_context(None, None))
        .unwrap();
    cert_builder.append_extension(san_ext).unwrap();

    cert_builder
        .sign(&pkey, openssl::hash::MessageDigest::sha256())
        .unwrap();

    return (cert_builder.build(), pkey);
}

fn openssl_cert_to_rustls(cert: &openssl::x509::X509) -> rustls::Certificate {
    return rustls::Certificate(cert.to_der().unwrap());
}

fn openssl_pkey_to_rustls(pkey: &openssl::pkey::PKey) -> Box<rustls::sign::Signer> {
    // TODO: ECDSA
    return Box::new(rustls::sign::RSASigner::new(&rustls::PrivateKey(pkey
                                                         .rsa()
                                                         .unwrap()
                                                         .private_key_to_der()
                                                         .unwrap()))
            .unwrap());
}

impl rustls::ResolvesServerCert for AutomaticCertResolver {
    fn resolve(&self,
               server_name: Option<&str>,
               _: &[rustls::SignatureScheme])
               -> Option<rustls::sign::CertChainAndSigner> {

        if let Some(sni) = server_name {
            if let Some(cert) = self.sni_challenges.lock().unwrap().get(sni) {
                return Some(cert.clone());
            }
        }
        // Seperate scope so that the lock isn't held we enter `obtain_new_certificate`.
        {
            let mut active_cert = self.active_cert.lock().unwrap();
            if cert_is_valid(active_cert.get_mut()) {
                return active_cert.get_mut().clone();
            }
        }
        self.obtain_new_certificate();
        return self.active_cert.lock().unwrap().get_mut().clone();
    }
}

fn cert_is_valid(cert: &Option<rustls::sign::CertChainAndSigner>) -> bool {
    return match cert {
               &Some((ref chain, _)) => cert_is_expired(&chain[0]),
               &None => false,
           };
}

fn cert_is_expired(cert: &rustls::Certificate) -> bool {
    let openssl_cert = openssl::x509::X509::from_der(&cert.0).unwrap();
    return from_asn1_time(openssl_cert.not_after()) < chrono::UTC::now();
}


fn from_asn1_time(t: &openssl::asn1::Asn1TimeRef) -> chrono::DateTime<chrono::UTC> {
    let dt = chrono::DateTime::parse_from_str(&t.to_string().replace(" GMT", " +00:00"),
                                              "%b %e %T %Y %z")
            .unwrap();
    return chrono::DateTime::<chrono::UTC>::from_utc(dt.naive_utc(), chrono::UTC);
}

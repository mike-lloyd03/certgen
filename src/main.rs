use std::fs::File;
use std::ops::Add;
use std::os::unix::prelude::FileExt;

use rcgen::Certificate;
use rcgen::CertificateParams;
use rcgen::{self, CertificateSigningRequest, KeyPair};

use time::{Duration, OffsetDateTime};

fn main() {
    let ca = gen_ca();
    make_pem_cert(&ca, "ca.pem");
    let csr = gen_csr(vec!["github.com".to_string(), "www.github.com".to_string()]);
    sign_csr(csr, ca);
}

fn gen_ca() -> Certificate {
    let mut params = CertificateParams::new(vec![]);
    params.key_usages = vec![
        rcgen::KeyUsagePurpose::CrlSign,
        rcgen::KeyUsagePurpose::KeyCertSign,
    ];
    params.distinguished_name = subject_name("US", "CA", "SD", "ProxyCert", "ProxyCert");
    params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    params.not_before = OffsetDateTime::now_local().unwrap();
    params.not_after = params.not_before.add(Duration::days(3650));

    Certificate::from_params(params).unwrap()
}

fn gen_csr(sub_alt_names: Vec<String>) -> CertificateSigningRequest {
    let mut params = CertificateParams::new(sub_alt_names);
    params.key_usages = vec![
        rcgen::KeyUsagePurpose::ContentCommitment, // non-repudiation
        rcgen::KeyUsagePurpose::DigitalSignature,
        rcgen::KeyUsagePurpose::KeyEncipherment,
    ];
    params.extended_key_usages = vec![rcgen::ExtendedKeyUsagePurpose::ServerAuth];
    params.distinguished_name = subject_name("US", "CA", "SD", "ProxyCert", "ProxyCert");
    params.not_before = OffsetDateTime::now_local().unwrap();
    params.not_after = params.not_before.add(Duration::days(3650));

    let cert = Certificate::from_params(params).unwrap();
    let csr_pem = cert.serialize_request_pem().unwrap();
    CertificateSigningRequest::from_pem(&csr_pem).unwrap()
}

fn sign_csr(csr: CertificateSigningRequest, ca_cert: Certificate) {
    let cert_pem = csr.serialize_pem_with_signer(&ca_cert).unwrap();
    let file = File::create("cert.pem").unwrap();
    file.write_all_at(cert_pem.as_bytes(), 0).unwrap();
}

fn gen_key() -> KeyPair {
    // from https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-gpnap/a48b02b2-2a10-4eb0-bed4-1807a6d2f5ad
    let sha512rsa_oid: [u64; 7] = [1, 2, 840, 113549, 1, 1, 13];
    let sha512rsa = rcgen::SignatureAlgorithm::from_oid(&sha512rsa_oid).unwrap();
    KeyPair::generate(sha512rsa).unwrap()
}

fn subject_name(c: &str, st: &str, l: &str, o: &str, cn: &str) -> rcgen::DistinguishedName {
    use rcgen::DnType::*;

    let mut dn = rcgen::DistinguishedName::new();
    dn.push(CountryName, c);
    dn.push(StateOrProvinceName, st);
    dn.push(LocalityName, l);
    dn.push(OrganizationName, o);
    dn.push(CommonName, cn);
    dn
}

fn make_pem_cert(cert: &Certificate, path: &str) {
    let pem = cert.serialize_pem().unwrap();
    let file = File::create(path).unwrap();
    file.write_all_at(pem.as_bytes(), 0).unwrap();
}

// fn make_pem_cert(csr: CertificateSigningRequest, path: &str) {
//     let pem = csr.serialize_pem_with_signer
//     let file = File::create(path).unwrap();
//     file.write_all_at(pem.as_bytes(), 0).unwrap();
// }

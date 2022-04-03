use std::fs::File;
use std::os::unix::prelude::FileExt;

use openssl::asn1::Asn1Time;
use openssl::hash::MessageDigest;
use openssl::pkey::{PKey, Private};
use openssl::rsa::Rsa;
use openssl::stack::Stack;
use openssl::x509;
use openssl::x509::extension;

fn main() {
    let key = gen_key();
    let ca = gen_ca(&key);
    // make_pem_ca(ca);
    let csr = gen_csr();
    // make_pem_req(&csr);
    let cert = sign_csr(&csr, &ca, &key);
    make_pem_cert(&cert);
}

fn gen_ca(key: &PKey<Private>) -> x509::X509 {
    let mut ca_builder = x509::X509Builder::new().unwrap();
    let key_usage = extension::KeyUsage::new()
        .crl_sign()
        .key_cert_sign()
        .build()
        .unwrap();
    let basic_constraints = extension::BasicConstraints::new().ca().build().unwrap();
    ca_builder.append_extension(key_usage).unwrap();
    ca_builder.append_extension(basic_constraints).unwrap();

    let subj_name = subject_name("US", "CA", "SD", "ProxyCert", "ProxyCert");
    ca_builder.set_subject_name(&subj_name).unwrap();

    let valid_days = days(3650);
    ca_builder.set_not_before(&valid_days.0).unwrap();
    ca_builder.set_not_after(&valid_days.1).unwrap();

    ca_builder.set_pubkey(key).unwrap();

    ca_builder.sign(&key, MessageDigest::sha512()).unwrap();
    ca_builder.build()
}

fn gen_csr() -> x509::X509Req {
    let mut req_builder = x509::X509ReqBuilder::new().unwrap();
    let ctx = req_builder.x509v3_context(None);
    let key_usage = extension::KeyUsage::new()
        .non_repudiation()
        .digital_signature()
        .key_encipherment()
        .build()
        .unwrap();
    let sub_alt_names = extension::SubjectAlternativeName::new()
        .dns("github.com")
        .dns("www.github.com")
        .build(&ctx)
        .unwrap();

    let mut extensions = Stack::new().unwrap();
    extensions.push(key_usage).unwrap();
    extensions.push(sub_alt_names).unwrap();
    req_builder.add_extensions(&extensions).unwrap();

    let subj_name = subject_name("US", "CA", "SD", "ProxyCert", "ProxyCert");
    req_builder.set_subject_name(&subj_name).unwrap();

    let key = gen_key();
    req_builder.set_pubkey(&key).unwrap();

    req_builder.sign(&key, MessageDigest::sha512()).unwrap();
    req_builder.build()
}

fn sign_csr(csr: &x509::X509Req, ca: &x509::X509, ca_key: &PKey<Private>) -> x509::X509 {
    let mut builder = x509::X509Builder::new().unwrap();
    builder.set_subject_name(csr.subject_name()).unwrap();
    builder.set_pubkey(&csr.public_key().unwrap()).unwrap();

    match csr.extensions() {
        Ok(extensions) => extensions
            .iter()
            .map(|ext| builder.append_extension2(ext))
            .collect::<Result<Vec<_>, _>>()
            .map(|_| ()),
        _ => Ok(()),
    }
    .unwrap();

    let mut extended_key_usage = extension::ExtendedKeyUsage::new();
    let server_auth = extended_key_usage.server_auth().build().unwrap();
    builder.append_extension2(&server_auth).unwrap();

    // let pem = std::fs::read("./cert/ca.crt").unwrap();
    // let ca = x509::X509::from_pem(&pem).unwrap();

    let ctx = builder.x509v3_context(Some(ca.as_ref()), None);
    let sub_key_identifier = extension::SubjectKeyIdentifier::new().build(&ctx).unwrap();
    let auth_key_identifier = extension::AuthorityKeyIdentifier::new()
        .keyid(true)
        .issuer(true)
        .build(&ctx)
        .unwrap();

    builder.append_extension2(&sub_key_identifier).unwrap();
    builder.append_extension2(&auth_key_identifier).unwrap();

    let days = days(365);
    builder.set_not_before(&days.0).unwrap();
    builder.set_not_after(&days.1).unwrap();

    builder.sign(ca_key, MessageDigest::sha512()).unwrap();
    builder.build()
}

fn gen_key() -> PKey<Private> {
    let rsa = Rsa::generate(4096).unwrap();
    PKey::from_rsa(rsa).unwrap()
}

fn make_pem_req(req: &x509::X509Req) {
    let pem = req.to_pem().unwrap();
    let file = File::create("./req.pem").unwrap();
    file.write_all_at(&pem, 0).unwrap();
}

fn make_pem_ca(req: x509::X509) {
    let pem = req.to_pem().unwrap();
    let file = File::create("./cert.pem").unwrap();
    file.write_all_at(&pem, 0).unwrap();
}

fn make_pem_cert(cert: &x509::X509) {
    let pem = cert.to_pem().unwrap();
    let file = File::create("./cert.pem").unwrap();
    file.write_all_at(&pem, 0).unwrap();
}

fn subject_name(c: &str, st: &str, l: &str, o: &str, cn: &str) -> x509::X509Name {
    let mut subj_name_builder = x509::X509NameBuilder::new().unwrap();
    subj_name_builder.append_entry_by_text("C", c).unwrap();
    subj_name_builder.append_entry_by_text("ST", st).unwrap();
    subj_name_builder.append_entry_by_text("L", l).unwrap();
    subj_name_builder.append_entry_by_text("O", o).unwrap();
    subj_name_builder.append_entry_by_text("CN", cn).unwrap();
    subj_name_builder.build()
}

fn days(days: u32) -> (Asn1Time, Asn1Time) {
    (
        Asn1Time::days_from_now(0).unwrap(),
        Asn1Time::days_from_now(days).unwrap(),
    )
}

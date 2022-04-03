use std::fs::File;
use std::os::unix::prelude::FileExt;

use openssl::asn1::Asn1Time;
use openssl::bn::{BigNum, MsbOption};
use openssl::error::ErrorStack;
use openssl::hash::MessageDigest;
use openssl::pkey::{PKey, PKeyRef, Private};
use openssl::rsa::Rsa;
use openssl::x509;
use openssl::x509::extension;
use openssl::x509::X509;

fn main() {
    let (ca, ca_key) = gen_ca().unwrap();
    let (cert, _cert_key) = gen_cert(
        &ca,
        &ca_key,
        vec!["github.com".to_string(), "*.github.com".to_string()],
    )
    .unwrap();
    make_pem(&ca, "./ca.pem");
    make_pem(&cert, "./cert.pem");
}

pub fn gen_ca() -> Result<(X509, PKey<Private>), ErrorStack> {
    let rsa = Rsa::generate(2048)?;
    let key_pair = PKey::from_rsa(rsa)?;

    let x509_name = subject_name("US", "CA", "RIV", "Rudy", "test");

    let mut cert_builder = X509::builder()?;
    cert_builder.set_version(2)?;
    let serial_number = {
        let mut serial = BigNum::new()?;
        serial.rand(159, MsbOption::MAYBE_ZERO, false)?;
        serial.to_asn1_integer()?
    };
    cert_builder.set_serial_number(&serial_number)?;
    cert_builder.set_subject_name(&x509_name)?;
    cert_builder.set_issuer_name(&x509_name)?;
    cert_builder.set_pubkey(&key_pair)?;

    let days = days(365);
    cert_builder.set_not_before(&days.0)?;
    cert_builder.set_not_after(&days.1)?;

    cert_builder.append_extension(extension::BasicConstraints::new().critical().ca().build()?)?;
    cert_builder.append_extension(
        extension::KeyUsage::new()
            .critical()
            .key_cert_sign()
            .crl_sign()
            .build()?,
    )?;

    let subject_key_identifier =
        extension::SubjectKeyIdentifier::new().build(&cert_builder.x509v3_context(None, None))?;
    cert_builder.append_extension(subject_key_identifier)?;

    cert_builder.sign(&key_pair, MessageDigest::sha256())?;
    let cert = cert_builder.build();

    Ok((cert, key_pair))
}

fn gen_csr(key_pair: &PKey<Private>) -> Result<x509::X509Req, ErrorStack> {
    let mut req_builder = x509::X509ReqBuilder::new()?;
    req_builder.set_pubkey(key_pair)?;

    let x509_name = subject_name("US", "CA", "RIV", "Rudy", "test");
    req_builder.set_subject_name(&x509_name)?;

    req_builder.sign(key_pair, MessageDigest::sha256())?;
    let req = req_builder.build();
    Ok(req)
}

pub fn gen_cert(
    ca_cert: &x509::X509Ref,
    ca_key_pair: &PKeyRef<Private>,
    dns_names: Vec<String>,
) -> Result<(X509, PKey<Private>), ErrorStack> {
    let rsa = Rsa::generate(2048)?;
    let key_pair = PKey::from_rsa(rsa)?;

    let req = gen_csr(&key_pair)?;

    let mut cert_builder = X509::builder()?;
    cert_builder.set_version(2)?;
    let serial_number = {
        let mut serial = BigNum::new()?;
        serial.rand(159, MsbOption::MAYBE_ZERO, false)?;
        serial.to_asn1_integer()?
    };
    cert_builder.set_serial_number(&serial_number)?;
    cert_builder.set_subject_name(req.subject_name())?;
    cert_builder.set_issuer_name(ca_cert.subject_name())?;
    cert_builder.set_pubkey(&key_pair)?;
    let not_before = Asn1Time::days_from_now(0)?;
    cert_builder.set_not_before(&not_before)?;
    let not_after = Asn1Time::days_from_now(365)?;
    cert_builder.set_not_after(&not_after)?;

    cert_builder.append_extension(extension::BasicConstraints::new().build()?)?;

    cert_builder.append_extension(
        extension::KeyUsage::new()
            .critical()
            .non_repudiation()
            .digital_signature()
            .key_encipherment()
            .build()?,
    )?;

    let subject_key_identifier = extension::SubjectKeyIdentifier::new()
        .build(&cert_builder.x509v3_context(Some(ca_cert), None))?;
    cert_builder.append_extension(subject_key_identifier)?;

    let auth_key_identifier = extension::AuthorityKeyIdentifier::new()
        .keyid(false)
        .issuer(false)
        .build(&cert_builder.x509v3_context(Some(ca_cert), None))?;
    cert_builder.append_extension(auth_key_identifier)?;

    let mut subject_alt_name = extension::SubjectAlternativeName::new();
    for name in dns_names {
        subject_alt_name.dns(&name);
    }
    let san = subject_alt_name.build(&cert_builder.x509v3_context(Some(ca_cert), None))?;
    cert_builder.append_extension(san)?;

    cert_builder.sign(ca_key_pair, MessageDigest::sha256())?;
    let cert = cert_builder.build();

    Ok((cert, key_pair))
}

fn make_pem(cert: &X509, path: &str) {
    let pem = cert.to_pem().unwrap();
    let file = File::create(path).unwrap();
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

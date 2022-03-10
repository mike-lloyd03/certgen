use openssl::hash::{hash, MessageDigest};
use openssl::pkey::{PKey, Private};
use openssl::rsa::Rsa;
use openssl::stack::Stack;
use openssl::x509;
use openssl::x509::extension::{BasicConstraints, KeyUsage, SubjectAlternativeName};

fn main() {
    println!("Hello, world!");
}

fn gen_ca() {
    let mut req_builder = x509::X509ReqBuilder::new().unwrap();
    let key_usage = KeyUsage::new().crl_sign().key_cert_sign().build().unwrap();
    let basic_constraints = BasicConstraints::new().ca().build().unwrap();

    let mut extensions = Stack::new().unwrap();
    extensions.push(key_usage).unwrap();
    extensions.push(basic_constraints).unwrap();
    req_builder.add_extensions(&extensions).unwrap();

    let key = gen_key();

    req_builder.sign(&key, MessageDigest::sha512()).unwrap();
    let req = req_builder.build();
    // for e in req.extensions().unwrap() {
    //     println!("{:?}", e);
    // }
}

fn gen_csr() {
    let mut req_builder = x509::X509ReqBuilder::new().unwrap();
    let key_usage = KeyUsage::new()
        .non_repudiation()
        .digital_signature()
        .key_encipherment()
        .build()
        .unwrap();
    let sub_alt_names = SubjectAlternativeName::new();
    sub_alt_names
        .dns("github.com")
        .dns("www.github.com")
        .build()
        .unwrap();
}

fn gen_key() -> PKey<Private> {
    let rsa = Rsa::generate(4096).unwrap();
    PKey::from_rsa(rsa).unwrap()
}

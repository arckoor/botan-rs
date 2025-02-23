use crate::ffi_types::*;

use crate::pubkey::{botan_privkey_t, botan_pubkey_t};
use crate::rng::botan_rng_t;

pub enum botan_x509_cert_struct {}
pub type botan_x509_cert_t = *mut botan_x509_cert_struct;

pub enum botan_x509_crl_struct {}
pub type botan_x509_crl_t = *mut botan_x509_crl_struct;

#[repr(u32)]
#[allow(clippy::upper_case_acronyms)]
pub enum X509KeyConstraints {
    NO_CONSTRAINTS = 0,
    DIGITAL_SIGNATURE = 32768,
    NON_REPUDIATION = 16384,
    KEY_ENCIPHERMENT = 8192,
    DATA_ENCIPHERMENT = 4096,
    KEY_AGREEMENT = 2048,
    KEY_CERT_SIGN = 1024,
    CRL_SIGN = 512,
    ENCIPHER_ONLY = 256,
    DECIPHER_ONLY = 128,
}

extern "C" {
    pub fn botan_x509_cert_load(
        cert_obj: *mut botan_x509_cert_t,
        cert: *const u8,
        cert_len: usize,
    ) -> c_int;
    pub fn botan_x509_cert_dup(cert_obj: *mut botan_x509_cert_t, cert: botan_x509_cert_t) -> c_int;
    pub fn botan_x509_cert_load_file(
        cert_obj: *mut botan_x509_cert_t,
        filename: *const c_char,
    ) -> c_int;
    pub fn botan_x509_cert_destroy(cert: botan_x509_cert_t) -> c_int;
    pub fn botan_x509_cert_gen_selfsigned(
        cert: *mut botan_x509_cert_t,
        key: botan_privkey_t,
        rng: botan_rng_t,
        common_name: *const c_char,
        org_name: *const c_char,
    ) -> c_int;
    pub fn botan_x509_cert_get_time_starts(
        cert: botan_x509_cert_t,
        out: *mut c_char,
        out_len: *mut usize,
    ) -> c_int;
    pub fn botan_x509_cert_get_time_expires(
        cert: botan_x509_cert_t,
        out: *mut c_char,
        out_len: *mut usize,
    ) -> c_int;
    pub fn botan_x509_cert_not_before(cert: botan_x509_cert_t, timestamp: *mut u64) -> c_int;
    pub fn botan_x509_cert_not_after(cert: botan_x509_cert_t, timestamp: *mut u64) -> c_int;
    pub fn botan_x509_cert_get_fingerprint(
        cert: botan_x509_cert_t,
        hash: *const c_char,
        out: *mut u8,
        out_len: *mut usize,
    ) -> c_int;
    pub fn botan_x509_cert_get_serial_number(
        cert: botan_x509_cert_t,
        out: *mut u8,
        out_len: *mut usize,
    ) -> c_int;
    pub fn botan_x509_cert_get_authority_key_id(
        cert: botan_x509_cert_t,
        out: *mut u8,
        out_len: *mut usize,
    ) -> c_int;
    pub fn botan_x509_cert_get_subject_key_id(
        cert: botan_x509_cert_t,
        out: *mut u8,
        out_len: *mut usize,
    ) -> c_int;
    pub fn botan_x509_cert_get_public_key_bits(
        cert: botan_x509_cert_t,
        out: *mut u8,
        out_len: *mut usize,
    ) -> c_int;
    pub fn botan_x509_cert_get_public_key(
        cert: botan_x509_cert_t,
        key: *mut botan_pubkey_t,
    ) -> c_int;
    pub fn botan_x509_cert_get_issuer_dn(
        cert: botan_x509_cert_t,
        key: *const c_char,
        index: usize,
        out: *mut u8,
        out_len: *mut usize,
    ) -> c_int;
    pub fn botan_x509_cert_get_subject_dn(
        cert: botan_x509_cert_t,
        key: *const c_char,
        index: usize,
        out: *mut u8,
        out_len: *mut usize,
    ) -> c_int;
    pub fn botan_x509_cert_to_string(
        cert: botan_x509_cert_t,
        out: *mut c_char,
        out_len: *mut usize,
    ) -> c_int;

    pub fn botan_x509_cert_allowed_usage(cert: botan_x509_cert_t, key_usage: c_uint) -> c_int;
    pub fn botan_x509_cert_hostname_match(
        cert: botan_x509_cert_t,
        hostname: *const c_char,
    ) -> c_int;

    pub fn botan_x509_cert_verify(
        validation_result: *mut c_int,
        ee_cert: botan_x509_cert_t,
        intermediates: *const botan_x509_cert_t,
        intermediates_len: usize,
        trusted: *const botan_x509_cert_t,
        trusted_len: usize,
        trusted_path: *const c_char,
        required_key_strength: usize,
        hostname: *const c_char,
        reference_time: u64,
    ) -> c_int;

    pub fn botan_x509_cert_validation_status(code: c_int) -> *const c_char;

    #[cfg(feature = "botan3")]
    pub fn botan_x509_cert_view_public_key_bits(
        cert: botan_x509_cert_t,
        view_ctx: botan_view_ctx,
        view_fn: botan_view_bin_fn,
    ) -> c_int;

    #[cfg(feature = "botan3")]
    pub fn botan_x509_cert_view_as_string(
        cert: botan_x509_cert_t,
        view_ctx: botan_view_ctx,
        view_fn: botan_view_str_fn,
    ) -> c_int;

    pub fn botan_x509_crl_load_file(crl: *mut botan_x509_crl_t, file_path: *const c_char) -> c_int;

    pub fn botan_x509_crl_load(
        crl: *mut botan_x509_crl_t,
        data: *const u8,
        data_len: usize,
    ) -> c_int;

    pub fn botan_x509_crl_destroy(crl: botan_x509_crl_t) -> c_int;

    pub fn botan_x509_is_revoked(crl: botan_x509_crl_t, cert: botan_x509_cert_t) -> c_int;

    // TODO: botan_x509_cert_verify_with_crl

}

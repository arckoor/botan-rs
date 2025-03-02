use crate::ffi_types::{c_char, c_int};

extern "C" {

    pub fn botan_key_wrap3394(
        input: *const u8,
        input_len: usize,
        kek: *const u8,
        kek_len: usize,
        wrapped_key: *mut u8,
        wrapped_key_len: *mut usize,
    ) -> c_int;

    pub fn botan_key_unwrap3394(
        wrapped_key: *const u8,
        wrapped_key_len: usize,
        kek: *const u8,
        kek_len: usize,
        unwrapped_key: *mut u8,
        unwrapped_key_len: *mut usize,
    ) -> c_int;

    #[cfg(botan_ffi_20230403)]
    pub fn botan_nist_kw_enc(
        cipher_algo: *const c_char,
        padding: c_int,
        input: *const u8,
        input_len: usize,
        kek: *const u8,
        kek_len: usize,
        wrapped_key: *mut u8,
        wrapped_key_len: *mut usize,
    ) -> c_int;

    #[cfg(botan_ffi_20230403)]
    pub fn botan_nist_kw_dec(
        cipher_algo: *const c_char,
        padding: c_int,
        wrapped_key: *const u8,
        wrapped_key_len: usize,
        kek: *const u8,
        kek_len: usize,
        unwrapped_key: *mut u8,
        unwrapped_key_len: *mut usize,
    ) -> c_int;
}

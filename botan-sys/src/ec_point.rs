#[cfg(botan_ffi_20260505)]
use crate::ffi_types::{botan_view_bin_fn, botan_view_ctx, botan_view_str_fn, c_char, c_int};

#[cfg(botan_ffi_20260505)]
use crate::{botan_ec_group_t, botan_mp_t, botan_rng_t};
#[cfg(botan_ffi_20260505)]
pub enum botan_ec_scalar_struct {}
#[cfg(botan_ffi_20260505)]
pub type botan_ec_scalar_t = *mut botan_ec_scalar_struct;

#[cfg(botan_ffi_20260505)]
pub enum botan_ec_point_struct {}
#[cfg(botan_ffi_20260505)]
pub type botan_ec_point_t = *mut botan_ec_point_struct;

#[cfg(botan_ffi_20260505)]
extern "C" {
    pub fn botan_ec_scalar_destroy(ec_scalar: botan_ec_scalar_t) -> c_int;

    pub fn botan_ec_scalar_random(
        ec_scalar: *mut botan_ec_scalar_t,
        ec_group: botan_ec_group_t,
        rng: botan_rng_t,
    ) -> c_int;

    pub fn botan_ec_scalar_from_mp(
        ec_scalar: *mut botan_ec_scalar_t,
        ec_group: botan_ec_group_t,
        mp: botan_mp_t,
    ) -> c_int;

    pub fn botan_ec_point_destroy(ec_point: botan_ec_point_t) -> c_int;

    pub fn botan_ec_point_identity(
        ec_point: *mut botan_ec_point_t,
        ec_group: botan_ec_group_t,
    ) -> c_int;

    pub fn botan_ec_point_generator(
        ec_point: *mut botan_ec_point_t,
        ec_group: botan_ec_group_t,
    ) -> c_int;

    pub fn botan_ec_point_from_xy(
        ec_point: *mut botan_ec_point_t,
        ec_group: botan_ec_group_t,
        x: botan_mp_t,
        y: botan_mp_t,
    ) -> c_int;

    pub fn botan_ec_point_from_bytes(
        ec_point: *mut botan_ec_point_t,
        ec_group: botan_ec_group_t,
        bytes: *const u8,
        bytes_len: usize,
    ) -> c_int;

    pub fn botan_ec_point_view_x_bytes(
        ec_point: botan_ec_point_t,
        ctx: botan_view_ctx,
        view: botan_view_bin_fn,
    ) -> c_int;

    pub fn botan_ec_point_view_y_bytes(
        ec_point: botan_ec_point_t,
        ctx: botan_view_ctx,
        view: botan_view_bin_fn,
    ) -> c_int;

    pub fn botan_ec_point_view_xy_bytes(
        ec_point: botan_ec_point_t,
        ctx: botan_view_ctx,
        view: botan_view_bin_fn,
    ) -> c_int;

    pub fn botan_ec_point_view_uncompressed(
        ec_point: botan_ec_point_t,
        ctx: botan_view_ctx,
        view: botan_view_bin_fn,
    ) -> c_int;

    pub fn botan_ec_point_view_compressed(
        ec_point: botan_ec_point_t,
        ctx: botan_view_ctx,
        view: botan_view_bin_fn,
    ) -> c_int;

    pub fn botan_ec_point_is_identity(ec_point: botan_ec_point_t) -> c_int;

    pub fn botan_ec_point_equal(x: botan_ec_point_t, y: botan_ec_point_t) -> c_int;

    pub fn botan_ec_point_negate(
        result: *mut botan_ec_point_t,
        ec_point: botan_ec_point_t,
    ) -> c_int;

    pub fn botan_ec_point_add(
        result: *mut botan_ec_point_t,
        x: botan_ec_point_t,
        y: botan_ec_point_t,
    ) -> c_int;

    pub fn botan_ec_point_mul(
        result: *mut botan_ec_point_t,
        ec_point: botan_ec_point_t,
        ec_scalar: botan_ec_scalar_t,
        rng: botan_rng_t,
    ) -> c_int;

}

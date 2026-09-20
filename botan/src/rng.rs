use crate::utils::*;
use botan_sys::*;

#[cfg(not(feature = "std"))]
use alloc::boxed::Box;

/// A source of cryptographically secure random bytes for a custom Botan RNG.
///
/// The source must be seeded before it is passed to
/// [`RandomNumberGenerator::new_custom`]. Botan treats custom sources as always
/// seeded. Implementations must fill the entire output buffer on success.
///
/// Callback errors are reported by Botan as [`ErrorType::InvalidObjectState`];
/// the original error is not preserved. With `std` and unwinding enabled, a
/// callback panic is caught and disables subsequent callbacks for this RNG.
/// Without `std`, or with `panic = "abort"`, a callback panic aborts the process.
pub trait CustomRng: Send {
    /// The error returned by the random source.
    type Error;

    /// Fill the entire buffer with random bytes.
    fn fill(&mut self, output: &mut [u8]) -> core::result::Result<(), Self::Error>;

    /// Mix additional entropy into the source, if supported.
    ///
    /// The default implementation ignores the input.
    fn add_entropy(&mut self, _input: &[u8]) -> core::result::Result<(), Self::Error> {
        Ok(())
    }
}

struct CustomRngState<R> {
    rng: R,
    poisoned: bool,
}

// Own the allocation without keeping a live Box: moving a Box would invalidate
// the raw context pointer retained by Botan under Rust's aliasing rules.
struct CustomState {
    ptr: *mut c_void,
    drop_fn: unsafe fn(*mut c_void),
}

impl CustomState {
    fn new<R: CustomRng + 'static>(rng: R) -> Self {
        Self {
            ptr: Box::into_raw(Box::new(CustomRngState {
                rng,
                poisoned: false,
            }))
            .cast::<c_void>(),
            drop_fn: drop_custom_state::<R>,
        }
    }
}

unsafe fn drop_custom_state<R: CustomRng>(ptr: *mut c_void) {
    // SAFETY: CustomState pairs this function with the pointer returned by
    // Box::into_raw for CustomRngState<R>, reclaiming it exactly once.
    drop(unsafe { Box::from_raw(ptr.cast::<CustomRngState<R>>()) });
}

impl Drop for CustomState {
    fn drop(&mut self) {
        // SAFETY: this is the sole owner, and Botan can no longer invoke the
        // callbacks: initialization failed, or the RNG handle was destroyed.
        unsafe { (self.drop_fn)(self.ptr) };
    }
}

impl<R: CustomRng> CustomRngState<R> {
    fn call(&mut self, f: impl FnOnce(&mut R) -> core::result::Result<(), R::Error>) -> c_int {
        if self.poisoned {
            return BOTAN_FFI_ERROR_INVALID_OBJECT_STATE;
        }

        let invoke = || match f(&mut self.rng) {
            Ok(()) => BOTAN_FFI_SUCCESS,
            Err(_) => BOTAN_FFI_ERROR_SYSTEM_ERROR,
        };

        #[cfg(feature = "std")]
        {
            match std::panic::catch_unwind(std::panic::AssertUnwindSafe(invoke)) {
                Ok(rc) => rc,
                Err(payload) => {
                    self.poisoned = true;
                    // Dropping a user-supplied panic payload could itself panic.
                    // Keep that panic from escaping this C callback as well.
                    mem::forget(payload);
                    BOTAN_FFI_ERROR_INVALID_OBJECT_STATE
                }
            }
        }

        #[cfg(not(feature = "std"))]
        invoke()
    }
}

extern "C" fn custom_rng_get<R: CustomRng>(ctx: *mut c_void, out: *mut u8, len: usize) -> c_int {
    if ctx.is_null() || (len > 0 && out.is_null()) {
        return BOTAN_FFI_ERROR_NULL_POINTER;
    }
    if len > isize::MAX as usize {
        return BOTAN_FFI_ERROR_BAD_PARAMETER;
    }

    // SAFETY: new_custom supplies a stable pointer to this concrete state type,
    // owned by the RNG. Botan invokes callbacks synchronously while the safe
    // API holds exclusive access to the RNG.
    let state = unsafe { &mut *ctx.cast::<CustomRngState<R>>() };
    state.call(|rng| {
        let output = if len == 0 {
            &mut []
        } else {
            // SAFETY: Botan provides len writable bytes. Initialize them before
            // creating a Rust slice: the callback may read the buffer, and Botan
            // may have supplied uninitialized storage.
            unsafe {
                out.write_bytes(0, len);
                core::slice::from_raw_parts_mut(out, len)
            }
        };
        rng.fill(output)
    })
}

extern "C" fn custom_rng_add_entropy<R: CustomRng>(
    ctx: *mut c_void,
    input: *const u8,
    len: usize,
) -> c_int {
    if ctx.is_null() || (len > 0 && input.is_null()) {
        return BOTAN_FFI_ERROR_NULL_POINTER;
    }
    if len > isize::MAX as usize {
        return BOTAN_FFI_ERROR_BAD_PARAMETER;
    }

    // SAFETY: the state has the same ownership and access guarantees as in
    // custom_rng_get. Botan provides len initialized, readable input bytes.
    let state = unsafe { &mut *ctx.cast::<CustomRngState<R>>() };
    state.call(|rng| {
        let input = if len == 0 {
            &[]
        } else {
            unsafe { core::slice::from_raw_parts(input, len) }
        };
        rng.add_entropy(input)
    })
}

/// A cryptographic random number generator
pub struct RandomNumberGenerator {
    obj: botan_rng_t,
    // Rust owns the callback state, including on initialization failure. The
    // Drop implementation destroys the Botan handle before this field is freed.
    _custom: Option<CustomState>,
}

impl core::fmt::Debug for RandomNumberGenerator {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("RandomNumberGenerator")
            .field("obj", &self.obj)
            .finish_non_exhaustive()
    }
}

// Callbacks and all access to the Botan RNG require &mut self. A custom source
// only needs Send, since shared references never access it or invoke callbacks.
unsafe impl Sync for RandomNumberGenerator {}
unsafe impl Send for RandomNumberGenerator {}

botan_impl_drop!(RandomNumberGenerator, botan_rng_destroy);

impl RandomNumberGenerator {
    /// Create a new RNG object with a specific type, e.g. "esdm-full"
    ///
    /// # Examples
    /// ```
    /// // This is just for demonstration, use RandomNumberGenerator::new_userspace() instead.
    /// let specific_rng = botan::RandomNumberGenerator::new_of_type("user").unwrap();
    /// ```
    pub fn new_of_type<T: crate::RngTypeIdentifier>(typ: T) -> Result<RandomNumberGenerator> {
        let typ = typ.botan_name();
        let typ = make_cstr(&typ)?;
        let obj = botan_init!(botan_rng_init, typ.as_ptr())?;
        Ok(RandomNumberGenerator { obj, _custom: None })
    }

    /// Create a deterministic random bit generator from explicit seed material.
    ///
    /// For HMAC_DRBG, `seed` is the concatenation of the entropy, nonce, and
    /// optional personalization string. The caller must supply sufficient
    /// entropy for the chosen algorithm. This RNG has no automatic entropy
    /// source; use `add_entropy` or `reseed` when reseeding is needed.
    ///
    /// This requires Botan 3.12 or later; with older versions an error of type
    /// [`ErrorType::NotImplemented`] is returned.
    pub fn new_drbg<A: crate::DrbgAlgorithmIdentifier>(name: A, seed: &[u8]) -> Result<Self> {
        let name = name.botan_name();
        let obj = botan_init!(
            botan_rng_init_drbg,
            make_cstr(&name)?.as_ptr(),
            seed.as_ptr(),
            seed.len()
        )?;
        Ok(Self { obj, _custom: None })
    }

    /// Create an RNG backed by an owned Rust random source.
    ///
    /// The source is dropped when this RNG is dropped, or if creation fails.
    /// `name` is a diagnostic name for the source. See [`CustomRng`] for the
    /// source's requirements and callback error and panic behavior.
    ///
    /// This requires Botan 3.0 or later; with older versions an error of type
    /// [`ErrorType::NotImplemented`] is returned.
    pub fn new_custom<R: CustomRng + 'static>(name: &str, rng: R) -> Result<Self> {
        let name = make_cstr(name)?;
        let state = CustomState::new(rng);
        let obj = botan_init!(
            botan_rng_init_custom,
            name.as_ptr(),
            state.ptr,
            Some(custom_rng_get::<R>),
            Some(custom_rng_add_entropy::<R>),
            None
        )?;
        Ok(Self {
            obj,
            _custom: Some(state),
        })
    }

    /// Wrap an owned `rand_core` cryptographic RNG for use by Botan operations.
    ///
    /// The source must already be seeded. Additional entropy is ignored because
    /// `rand_core` has no reseeding interface. Callback errors and panics are
    /// handled as described in [`CustomRng`].
    ///
    /// This requires Botan 3.0 or later; with older versions an error of type
    /// [`ErrorType::NotImplemented`] is returned.
    #[cfg(feature = "rand")]
    pub fn from_rng<R: rand_core::TryCryptoRng + Send + 'static>(rng: R) -> Result<Self> {
        struct Adapter<R>(R);

        impl<R: rand_core::TryCryptoRng + Send> CustomRng for Adapter<R> {
            type Error = R::Error;

            fn fill(&mut self, output: &mut [u8]) -> core::result::Result<(), Self::Error> {
                self.0.try_fill_bytes(output)
            }
        }

        Self::new_custom(core::any::type_name::<R>(), Adapter(rng))
    }

    pub(crate) fn handle(&mut self) -> botan_rng_t {
        self.obj
    }

    /// Create a new userspace RNG object
    ///
    /// # Examples
    /// ```
    /// let userspace_rng = botan::RandomNumberGenerator::new_userspace().unwrap();
    /// ```
    pub fn new_userspace() -> Result<RandomNumberGenerator> {
        RandomNumberGenerator::new_of_type(crate::RngType::User)
    }

    /// Create a new reference to the system PRNG
    ///
    /// # Examples
    /// ```
    /// let system_rng = botan::RandomNumberGenerator::new_system().unwrap();
    /// ```
    pub fn new_system() -> Result<RandomNumberGenerator> {
        RandomNumberGenerator::new_of_type(crate::RngType::System)
    }

    /// Create a new reference to the ESDM PRNG (fully seeded)
    ///
    /// Availability of this RNG depends on botan being compiled
    /// with ESDM support.
    ///
    /// # Examples
    /// ```ignore
    /// let esdm_rng = botan::RandomNumberGenerator::new_esdm().unwrap();
    /// ```
    pub fn new_esdm() -> Result<RandomNumberGenerator> {
        RandomNumberGenerator::new_of_type(crate::RngType::EsdmFull)
    }

    /// Create a new reference to the ESDM PRNG (with prediction resistance)
    ///
    /// Availability of this RNG depends on botan being compiled
    /// with ESDM support.
    ///
    /// # Examples
    /// ```ignore
    /// let esdm_rng = botan::RandomNumberGenerator::new_esdm_pr().unwrap();
    /// ```
    pub fn new_esdm_pr() -> Result<RandomNumberGenerator> {
        RandomNumberGenerator::new_of_type(crate::RngType::EsdmPr)
    }

    /// Create a new reference to the Jitter RNG
    ///
    /// Availability of this RNG depends on botan being compiled
    /// with Jitter RNG support.
    ///
    /// # Examples
    /// ```ignore
    /// let jitter_rng = botan::RandomNumberGenerator::new_jitter().unwrap();
    /// ```
    pub fn new_jitter() -> Result<RandomNumberGenerator> {
        RandomNumberGenerator::new_of_type(crate::RngType::Jitter)
    }

    /// Create a new reference to an RNG of some arbitrary type
    ///
    /// # Examples
    /// ```
    /// let a_rng = botan::RandomNumberGenerator::new().unwrap();
    /// ```
    pub fn new() -> Result<RandomNumberGenerator> {
        RandomNumberGenerator::new_userspace()
    }

    /// Read bytes from an RNG
    ///
    /// # Examples
    /// ```
    /// let mut rng = botan::RandomNumberGenerator::new().unwrap();
    /// let output = rng.read(32).unwrap();
    /// assert_eq!(output.len(), 32);
    /// ```
    pub fn read(&mut self, len: usize) -> Result<Vec<u8>> {
        let mut result = vec![0; len];
        self.fill(&mut result)?;
        Ok(result)
    }

    /// Store bytes from the RNG into the passed slice
    ///
    /// # Examples
    /// ```
    /// let mut rng = botan::RandomNumberGenerator::new().unwrap();
    /// let mut output = vec![0; 32];
    /// rng.fill(&mut output).unwrap();
    /// ```
    pub fn fill(&mut self, out: &mut [u8]) -> Result<()> {
        botan_call!(botan_rng_get, self.obj, out.as_mut_ptr(), out.len())
    }

    /// Read random bytes, mixing in additional input before generation.
    ///
    /// Some RNGs, including the system RNG, ignore additional input.
    ///
    /// This requires Botan 3.12 or later; with older versions an error of type
    /// [`ErrorType::NotImplemented`] is returned.
    pub fn read_with_input(&mut self, len: usize, input: &[u8]) -> Result<Vec<u8>> {
        let mut output = vec![0; len];
        self.fill_with_input(&mut output, input)?;
        Ok(output)
    }

    /// Fill a buffer with random bytes, mixing in additional input first.
    ///
    /// Some RNGs, including the system RNG, ignore additional input.
    ///
    /// This requires Botan 3.12 or later; with older versions an error of type
    /// [`ErrorType::NotImplemented`] is returned.
    pub fn fill_with_input(&mut self, out: &mut [u8], input: &[u8]) -> Result<()> {
        botan_call!(
            botan_rng_generate_with_input,
            self.obj,
            out.as_mut_ptr(),
            out.len(),
            input.as_ptr(),
            input.len()
        )
    }

    /// Attempt to reseed the RNG by unspecified means
    ///
    /// # Examples
    /// ```
    /// let mut rng = botan::RandomNumberGenerator::new().unwrap();
    /// rng.reseed(256).unwrap();
    /// ```
    pub fn reseed(&mut self, bits: usize) -> Result<()> {
        botan_call!(botan_rng_reseed, self.obj, bits)
    }

    /// Attempt to reseed the RNG by getting data from source RNG
    ///
    /// # Examples
    /// ```
    /// let mut system_rng = botan::RandomNumberGenerator::new_system().unwrap();
    /// let mut rng = botan::RandomNumberGenerator::new_userspace().unwrap();
    /// rng.reseed_from_rng(&mut system_rng, 256).unwrap();
    /// ```
    pub fn reseed_from_rng(
        &mut self,
        source: &mut RandomNumberGenerator,
        bits: usize,
    ) -> Result<()> {
        botan_call!(botan_rng_reseed_from_rng, self.obj, source.handle(), bits)
    }

    /// Add some seed material to the RNG
    ///
    /// # Examples
    /// ```
    /// let mut rng = botan::RandomNumberGenerator::new_userspace().unwrap();
    /// let my_seed = vec![0x42, 0x6F, 0x62];
    /// rng.add_entropy(&my_seed);
    /// ```
    pub fn add_entropy(&mut self, seed: &[u8]) -> Result<()> {
        botan_call!(botan_rng_add_entropy, self.obj, seed.as_ptr(), seed.len())
    }
}

/// Fill a buffer directly from Botan's system RNG, without creating a handle.
///
/// This requires Botan 3.0 or later; with older versions an error of type
/// [`ErrorType::NotImplemented`] is returned.
pub fn system_rng_get(output: &mut [u8]) -> Result<()> {
    botan_call!(botan_system_rng_get, output.as_mut_ptr(), output.len())
}

#[cfg(feature = "rand")]
impl rand_core::TryRng for RandomNumberGenerator {
    type Error = Error;

    fn try_next_u32(&mut self) -> Result<u32> {
        let mut bytes: [u8; 4] = [0; 4];
        self.fill(&mut bytes)?;
        Ok(u32::from_be_bytes(bytes))
    }

    fn try_next_u64(&mut self) -> Result<u64> {
        let mut bytes: [u8; 8] = [0; 8];
        self.fill(&mut bytes)?;
        Ok(u64::from_be_bytes(bytes))
    }

    fn try_fill_bytes(&mut self, dst: &mut [u8]) -> Result<()> {
        self.fill(dst)?;
        Ok(())
    }
}

#[cfg(feature = "rand")]
impl rand_core::TryCryptoRng for RandomNumberGenerator {}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    struct TestSource {
        byte: u8,
        drops: Arc<AtomicUsize>,
    }

    impl CustomRng for TestSource {
        type Error = core::convert::Infallible;

        fn fill(&mut self, output: &mut [u8]) -> core::result::Result<(), Self::Error> {
            output.fill(self.byte);
            self.byte += 1;
            Ok(())
        }
    }

    impl Drop for TestSource {
        fn drop(&mut self) {
            self.drops.fetch_add(1, Ordering::SeqCst);
        }
    }

    // These tests never call Botan, so they can run under Miri with the
    // dynamic-loading feature (which avoids linking the native library).
    #[test]
    fn custom_state_callbacks_after_moves() {
        let drops = Arc::new(AtomicUsize::new(0));
        let state = CustomState::new(TestSource {
            byte: 42,
            drops: drops.clone(),
        });
        let ctx = state.ptr;
        let owner = Some(state);
        let mut output = [0; 4];
        assert_eq!(
            custom_rng_get::<TestSource>(ctx, output.as_mut_ptr(), output.len()),
            BOTAN_FFI_SUCCESS
        );
        assert_eq!(output, [42; 4]);

        let moved = Box::new(owner);
        assert_eq!(
            custom_rng_get::<TestSource>(ctx, output.as_mut_ptr(), output.len()),
            BOTAN_FFI_SUCCESS
        );
        assert_eq!(output, [43; 4]);
        assert_eq!(drops.load(Ordering::SeqCst), 0);
        drop(moved);
        assert_eq!(drops.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn custom_state_failed_init_cleanup() {
        fn fail_init(source: TestSource) -> core::result::Result<CustomState, ()> {
            let state = CustomState::new(source);
            // Simulate the FFI initialization error after allocating the state.
            Err::<(), _>(())?;
            Ok(state)
        }

        let drops = Arc::new(AtomicUsize::new(0));
        assert!(
            fail_init(TestSource {
                byte: 42,
                drops: drops.clone(),
            })
            .is_err()
        );
        assert_eq!(drops.load(Ordering::SeqCst), 1);
    }
}

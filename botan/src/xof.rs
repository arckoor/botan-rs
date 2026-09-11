use crate::utils::*;
use botan_sys::*;

/// An extendable-output function (XOF).
///
/// Add input with [`Self::update`], then read successive bytes of the output
/// stream with [`Self::output`] or [`Self::output_into`]. SHAKE and Ascon stop
/// accepting input once nonempty output has been requested. Call [`Self::clear`]
/// to reset the object for a new message.
///
/// Creating this object requires Botan 3.11 or later; with older versions an
/// error of type [`ErrorType::NotImplemented`](crate::ErrorType::NotImplemented)
/// is returned.
///
/// # Examples
///
/// ```no_run
/// # fn main() -> Result<(), botan::Error> {
/// let mut xof = botan::Xof::new(botan::XofAlgorithm::Shake128)?;
/// xof.update(b"message")?;
/// let first = xof.output(32)?;
/// let mut next = [0u8; 64];
/// xof.output_into(&mut next)?;
/// # Ok(())
/// # }
/// ```
#[derive(Debug)]
pub struct Xof {
    obj: botan_xof_t,
}

// The handle is exclusively owned; operations that mutate its state require
// &mut self. Shared access only queries or copies the state.
unsafe impl Sync for Xof {}
unsafe impl Send for Xof {}

botan_impl_drop!(Xof, botan_xof_destroy);

impl Clone for Xof {
    fn clone(&self) -> Self {
        self.duplicate().expect("copying XOF object state failed")
    }
}

impl Xof {
    /// Create an XOF using an algorithm identifier, such as `"SHAKE-128"`.
    ///
    /// Returns an error if the algorithm or the XOF interface is unavailable.
    pub fn new<A: crate::XofAlgorithmIdentifier>(name: A) -> Result<Self> {
        let name = name.botan_name();
        let obj = botan_init!(botan_xof_init, make_cstr(&name)?.as_ptr(), 0u32)?;
        Ok(Self { obj })
    }

    /// Return the algorithm name, which may differ from the name passed to `new`.
    pub fn algo_name(&self) -> Result<String> {
        call_botan_ffi_returning_string(32, &|out_buf, out_len| unsafe {
            botan_xof_name(self.obj, out_buf as *mut c_char, out_len)
        })
    }

    /// Return the internal block size in bytes.
    ///
    /// Input and output lengths need not be multiples of this size.
    pub fn block_size(&self) -> Result<usize> {
        botan_usize!(botan_xof_block_size, self.obj)
    }

    /// Return whether the XOF can accept more input in its current state.
    pub fn accepts_input(&self) -> Result<bool> {
        botan_bool_in_rc!(botan_xof_accepts_input, self.obj)
    }

    /// Add input to the XOF. This may be called repeatedly.
    ///
    /// Returns an error if the algorithm cannot accept further input.
    /// Empty input leaves the state unchanged, including during output.
    pub fn update(&mut self, data: &[u8]) -> Result<()> {
        botan_call!(botan_xof_update, self.obj, data.as_ptr(), data.len())
    }

    /// Return the next `len` bytes of the output stream.
    ///
    /// Successive calls continue the stream without resetting the object.
    /// Requesting zero bytes leaves the state unchanged.
    pub fn output(&mut self, len: usize) -> Result<Vec<u8>> {
        let mut output = vec![0; len];
        self.output_into(&mut output)?;
        Ok(output)
    }

    /// Fill the entire buffer with the next bytes of the output stream.
    ///
    /// Successive calls continue the stream without resetting the object.
    /// An empty buffer leaves the state unchanged.
    pub fn output_into(&mut self, output: &mut [u8]) -> Result<()> {
        botan_call!(
            botan_xof_output,
            self.obj,
            output.as_mut_ptr(),
            output.len()
        )
    }

    /// Reset the object to its initial state, ready to accept a new message.
    pub fn clear(&mut self) -> Result<()> {
        botan_call!(botan_xof_clear, self.obj)
    }

    /// Copy the complete state into an independent XOF object.
    ///
    /// During input, this allows messages to share a common prefix. During
    /// output, the copy continues from the same position in the output stream.
    /// This function is also called by `clone`.
    pub fn duplicate(&self) -> Result<Self> {
        let obj = botan_init!(botan_xof_copy_state, self.obj)?;
        Ok(Self { obj })
    }
}

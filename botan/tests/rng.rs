use botan::{CustomRng, DrbgAlgorithm, Error, ErrorType, HashAlgorithm, RandomNumberGenerator};
use std::cell::Cell;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

// Only skip the first use of an independent API/algorithm. Later errors must
// fail the test, including NotImplemented errors returned by callbacks.
macro_rules! skip_if_not_implemented {
    ($call:expr) => {
        match $call {
            Ok(value) => value,
            Err(e) if e.error_type() == ErrorType::NotImplemented => return Ok(()),
            Err(e) => return Err(e),
        }
    };
}

#[test]
fn seeded_drbg() -> Result<(), Error> {
    let algo = DrbgAlgorithm::Hmac(HashAlgorithm::Sha256);
    assert_eq!(algo.botan_name(), "HMAC_DRBG(SHA-256)");

    // Test the binding's argument forwarding, not the DRBG algorithm itself.
    let seed = [0x42; 48];
    let mut rng = skip_if_not_implemented!(RandomNumberGenerator::new_drbg(&algo, &seed));
    let mut reference = RandomNumberGenerator::new_drbg("HMAC_DRBG(SHA-256)", &seed)?;
    assert_eq!(rng.read(32)?, reference.read(32)?);

    let mut output = [0; 37];
    rng.fill_with_input(&mut output, b"additional input")?;
    assert_eq!(
        output.as_slice(),
        reference.read_with_input(37, b"additional input")?
    );
    assert_eq!(rng.read_with_input(32, &[])?, reference.read(32)?);
    rng.fill_with_input(&mut [], &[])?;

    assert!(RandomNumberGenerator::new_drbg("invalid DRBG", &seed).is_err());
    assert!(RandomNumberGenerator::new_drbg("HMAC_DRBG(SHA-256)\0", &seed).is_err());
    Ok(())
}

#[test]
fn system_rng_get() -> Result<(), Error> {
    let mut output = [0; 32];
    skip_if_not_implemented!(botan::system_rng_get(&mut output));
    botan::system_rng_get(&mut [])?;
    Ok(())
}

#[derive(Default)]
struct TestSource {
    next: Cell<u8>,
    entropy: Arc<Mutex<Vec<u8>>>,
    drops: Arc<AtomicUsize>,
    fail: bool,
}

impl CustomRng for TestSource {
    type Error = ();

    fn fill(&mut self, output: &mut [u8]) -> Result<(), Self::Error> {
        if self.fail {
            return Err(());
        }
        // Safe callbacks must be allowed to read even C++-allocated buffers.
        assert!(output.iter().all(|byte| *byte == 0));
        for byte in output {
            *byte = self.next.get();
            self.next.set(byte.wrapping_add(1));
        }
        Ok(())
    }

    fn add_entropy(&mut self, input: &[u8]) -> Result<(), Self::Error> {
        if self.fail {
            return Err(());
        }
        self.entropy.lock().unwrap().extend_from_slice(input);
        Ok(())
    }
}

impl Drop for TestSource {
    fn drop(&mut self) {
        self.drops.fetch_add(1, Ordering::SeqCst);
    }
}

#[test]
fn custom_rng_callbacks_and_ownership() -> Result<(), Error> {
    let source = TestSource::default();
    let entropy = source.entropy.clone();
    let drops = source.drops.clone();
    let mut rng = skip_if_not_implemented!(RandomNumberGenerator::new_custom("test", source));
    assert_eq!(drops.load(Ordering::SeqCst), 0);
    assert_eq!(rng.read(4)?, [0, 1, 2, 3]);
    let mut output = [0xFF; 3];
    rng.fill(&mut output)?;
    assert_eq!(output, [4, 5, 6]);
    rng.fill(&mut [])?;
    rng.add_entropy(&[])?;
    rng.add_entropy(b"entropy")?;
    assert_eq!(*entropy.lock().unwrap(), b"entropy");

    // Exercise the callback through a Botan operation, not just rng.fill().
    let mut mpi = botan::MPI::new()?;
    mpi.randomize(&mut rng, 128)?;

    // Moving the wrapper must keep the context alive at a stable address.
    std::thread::spawn(move || rng.read(16)).join().unwrap()?;
    assert_eq!(drops.load(Ordering::SeqCst), 1);
    Ok(())
}

#[test]
fn custom_rng_additional_input() -> Result<(), Error> {
    let source = TestSource::default();
    let entropy = source.entropy.clone();
    let mut rng = skip_if_not_implemented!(RandomNumberGenerator::new_custom("test", source));
    // Additional-input generation is independently available starting in 3.12.
    let output = skip_if_not_implemented!(rng.read_with_input(4, b"input"));
    assert_eq!(output, [0, 1, 2, 3]);
    assert_eq!(*entropy.lock().unwrap(), b"input");
    rng.fill_with_input(&mut [], b"more")?;
    assert_eq!(*entropy.lock().unwrap(), b"inputmore");
    Ok(())
}

#[test]
fn custom_rng_errors() -> Result<(), Error> {
    let source = TestSource {
        next: Cell::new(0),
        entropy: Arc::default(),
        drops: Arc::default(),
        fail: true,
    };
    let drops = source.drops.clone();
    let mut rng = skip_if_not_implemented!(RandomNumberGenerator::new_custom("test", source));
    assert_eq!(
        rng.read(1).unwrap_err().error_type(),
        ErrorType::InvalidObjectState
    );
    assert_eq!(
        rng.add_entropy(b"input").unwrap_err().error_type(),
        ErrorType::InvalidObjectState
    );
    drop(rng);
    assert_eq!(drops.load(Ordering::SeqCst), 1);
    Ok(())
}

#[test]
fn custom_rng_failed_init_drops_source() {
    let source = TestSource::default();
    let drops = source.drops.clone();
    assert!(RandomNumberGenerator::new_custom("invalid\0name", source).is_err());
    assert_eq!(drops.load(Ordering::SeqCst), 1);
}

#[cfg(all(feature = "std", panic = "unwind"))]
#[test]
fn custom_rng_panics_poison_callbacks() -> Result<(), Error> {
    struct PanickingSource {
        calls: Arc<AtomicUsize>,
    }

    impl CustomRng for PanickingSource {
        type Error = ();

        fn fill(&mut self, _output: &mut [u8]) -> Result<(), Self::Error> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            panic!("test callback panic");
        }

        fn add_entropy(&mut self, _input: &[u8]) -> Result<(), Self::Error> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            panic!("test entropy callback panic");
        }
    }

    for entropy_first in [false, true] {
        let calls = Arc::new(AtomicUsize::new(0));
        let source = PanickingSource {
            calls: calls.clone(),
        };
        let mut rng = skip_if_not_implemented!(RandomNumberGenerator::new_custom("test", source));
        let error = if entropy_first {
            rng.add_entropy(b"input").unwrap_err()
        } else {
            rng.fill(&mut [0; 1]).unwrap_err()
        };
        assert_eq!(error.error_type(), ErrorType::InvalidObjectState);
        assert_eq!(
            rng.read(1).unwrap_err().error_type(),
            ErrorType::InvalidObjectState
        );
        assert_eq!(
            rng.add_entropy(b"input").unwrap_err().error_type(),
            ErrorType::InvalidObjectState
        );
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }
    Ok(())
}

#[cfg(feature = "rand")]
#[test]
fn custom_rng_rand_core_adapter() -> Result<(), Error> {
    #[derive(Default)]
    struct State {
        requests: Vec<usize>,
        next: u8,
        fail: bool,
    }

    struct TestRng {
        state: Arc<Mutex<State>>,
    }

    impl rand_core::TryRng for TestRng {
        type Error = std::io::Error;

        fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
            panic!("the adapter should call try_fill_bytes");
        }

        fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
            panic!("the adapter should call try_fill_bytes");
        }

        fn try_fill_bytes(&mut self, output: &mut [u8]) -> Result<(), Self::Error> {
            let mut state = self.state.lock().unwrap();
            state.requests.push(output.len());
            if state.fail {
                return Err(std::io::Error::other("injected rand_core failure"));
            }
            for byte in output {
                *byte = state.next;
                state.next = state.next.wrapping_add(1);
            }
            Ok(())
        }
    }

    impl rand_core::TryCryptoRng for TestRng {}

    let state = Arc::new(Mutex::new(State::default()));
    let source = TestRng {
        state: state.clone(),
    };
    let mut rng = skip_if_not_implemented!(RandomNumberGenerator::from_rng(source));
    assert!(state.lock().unwrap().requests.is_empty());

    let mut output = [0xFF; 5];
    rng.fill(&mut output)?;
    assert_eq!(output, [0, 1, 2, 3, 4]);
    assert_eq!(state.lock().unwrap().requests, [5]);

    rng.add_entropy(b"ignored by rand_core sources")?;
    assert_eq!(state.lock().unwrap().requests, [5]);
    assert_eq!(rng.read(3)?, [5, 6, 7]);
    assert_eq!(state.lock().unwrap().requests, [5, 3]);

    state.lock().unwrap().fail = true;
    assert_eq!(
        rng.fill(&mut [0; 4]).unwrap_err().error_type(),
        ErrorType::InvalidObjectState
    );
    assert_eq!(state.lock().unwrap().requests, [5, 3, 4]);

    // An ordinary source error does not poison the adapter. Verify that a
    // subsequent Botan operation also reaches the rand_core implementation.
    state.lock().unwrap().fail = false;
    let mut mpi = botan::MPI::new()?;
    mpi.randomize(&mut rng, 128)?;
    assert!(state.lock().unwrap().requests.len() > 3);
    Ok(())
}

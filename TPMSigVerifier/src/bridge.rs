#[cxx::bridge]
mod ffi {
    unsafe extern "C++" {
        include!("TpmSignVerifierBridge.hxx");

        // Expose the C++ verification function to Rust
         fn VerifyFileWithTPM_Utf8(log_path: &CxxString, sig_path: &CxxString) -> i32;
    }
}

pub use ffi::*;
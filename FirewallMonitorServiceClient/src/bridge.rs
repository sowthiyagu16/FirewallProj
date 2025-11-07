#[cxx::bridge]
mod ffi {
    unsafe extern "C++" {
        include!("FirewallObserverBridge.hxx");
        fn start_service();       
    }
}

pub use ffi::*;


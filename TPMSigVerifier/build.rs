use std::path::PathBuf;

fn main() {
    let manifest_dir = PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").unwrap());
    let firewall_observer_dir = manifest_dir.parent().unwrap();

    cxx_build::bridge("src/bridge.rs")
        .file(firewall_observer_dir.join("TpmSignVerifierBridge.cc"))
        .file(firewall_observer_dir.join("TpmSignVerifier.cpp"))  
        .file(firewall_observer_dir.join("Logger.cpp"))           
        .include(firewall_observer_dir) 
        .flag_if_supported("/std:c++20")
        .compile("tpm_signature_bridge");

    println!("cargo:rerun-if-changed=src/bridge.rs");
    println!("cargo:rerun-if-changed={}", firewall_observer_dir.join("TpmSignVerifierBridge.cc").display());
    println!("cargo:rerun-if-changed={}", firewall_observer_dir.join("TpmSignVerifierBridge.hxx").display());
    println!("cargo:rerun-if-changed={}", firewall_observer_dir.join("TpmSignVerifier.cpp").display());
    println!("cargo:rerun-if-changed={}", firewall_observer_dir.join("Logger.cpp").display());    
}
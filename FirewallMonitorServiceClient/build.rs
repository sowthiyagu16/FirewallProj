use std::path::PathBuf;

fn main() {
    let manifest_dir = PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").unwrap());
    let firewall_observer_dir = manifest_dir.parent().unwrap();
    
    cxx_build::bridge("src/bridge.rs")
        .file(firewall_observer_dir.join("FirewallObserverBridge.cc"))
        .file(firewall_observer_dir.join("FilrewallService.cpp"))
        .file(firewall_observer_dir.join("Logger.cpp"))
        .file(firewall_observer_dir.join("TpmSigner.cpp"))
        .file(firewall_observer_dir.join("FirewallObserver.cpp"))
        .include(&firewall_observer_dir)
        .flag_if_supported("/std:c++20")
        .flag_if_supported("/EHsc")
        .compile("firewall_observer_bridge");

    // Link against Windows COM libraries
    println!("cargo:rustc-link-lib=ole32");
    println!("cargo:rustc-link-lib=oleaut32");
    
    // Link against Windows security and shell libraries
    println!("cargo:rustc-link-lib=advapi32");
    println!("cargo:rustc-link-lib=shell32");
    
    println!("cargo:rerun-if-changed=src/bridge.rs");
    println!("cargo:rerun-if-changed={}", firewall_observer_dir.join("FirewallObserverBridge.cc").display());
    println!("cargo:rerun-if-changed={}", firewall_observer_dir.join("FilrewallService.cpp").display());
    println!("cargo:rerun-if-changed={}", firewall_observer_dir.join("Logger.cpp").display());
    println!("cargo:rerun-if-changed={}", firewall_observer_dir.join("TpmSigner.cpp").display());
    println!("cargo:rerun-if-changed={}", firewall_observer_dir.join("FirewallObserver.cpp").display());
}

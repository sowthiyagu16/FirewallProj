mod bridge;

use cxx::let_cxx_string;
use bridge::VerifyFileWithTPM_Utf8;
use std::env;

fn main() {
    let args: Vec<String> = env::args().collect();

    let mut log_path_str: Option<String> = None;
    let mut sig_path_str: Option<String> = None;

    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "-l" | "-L" => {
                if i + 1 < args.len() {
                    log_path_str = Some(args[i + 1].clone());
                    i += 2;
                } else {
                    eprintln!("Error: -l requires a value");
                    std::process::exit(1);
                }
            }
            "-s" | "-S" => {
                if i + 1 < args.len() {
                    sig_path_str = Some(args[i + 1].clone());
                    i += 2;
                } else {
                    eprintln!("Error: -s requires a value");
                    std::process::exit(1);
                }
            }
            _ => {
                eprintln!("Error: Unknown argument '{}'", args[i]);
                eprintln!("Usage: {} -l <log_path> -s <sig_path>", args[0]);
                eprintln!("Example: {} -l C:\\Firewall_monitor_logs\\Report_2025-11-05.log -s C:\\Firewall_monitor_logs\\Report_2025-11-05.sig", args[0]);
                std::process::exit(1);
            }
        }
    }

    if log_path_str.is_none() || sig_path_str.is_none() {
        eprintln!("Usage: {} -l <log_path> -s <sig_path>", args[0]);
        eprintln!("Example: {} -l C:\\Firewall_monitor_logs\\Report_2025-11-05.log -s C:\\Firewall_monitor_logs\\Report_2025-11-05.sig", args[0]);
        std::process::exit(1);
    }

    let log_path_str = log_path_str.unwrap();
    let sig_path_str = sig_path_str.unwrap();

    let_cxx_string!(log_path = &log_path_str);
    let_cxx_string!(sig_path = &sig_path_str);

    let result = VerifyFileWithTPM_Utf8(&log_path, &sig_path);

    if result == 0 {
        println!("✅ Signature verification succeeded!");
    } else {
        println!("❌ Verification failed (code {})", result);
    }
}
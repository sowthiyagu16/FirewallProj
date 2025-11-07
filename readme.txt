# FirewallObserver

## Overview
FirewallObserver is a C++ application designed to verify the integrity of log files using TPM-based signature verification. It ensures that log files have not been tampered with by validating their signatures against a trusted TPM key.

## Features
- Uses TPM (Trusted Platform Module) for secure key storage and signature verification.
- Supports SHA-256 hashing for file integrity checks.
- Verifies signatures using PKCS#1 padding.

## Prerequisites
- Windows operating system with TPM support.
- Visual Studio 2022 or later.
- C++14 compiler.
- Windows Cryptography API (CNG).

## Build Instructions
1. Clone the repository:
Open the solution in Visual Studio.
3. Build the project in Debug or Release mode.

## Usage
1. Place the log file and its corresponding signature file in the desired directory.
2. Run the application with the following command:
fn main() {
    cxx_build::bridge("src/bridge.rs")
        .file("src/rust.cpp")
        .include("lib/include/SEAL-3.7")
        .flag_if_supported("-std=c++17")
        .compile("cxxbridge-seal");
    println!("cargo:rerun-if-changed=src/bridge.rs");
    println!("cargo:rerun-if-changed=src/rust.cpp");
    println!("cargo:rerun-if-changed=include/rust.h");
    println!("cargo:rustc-link-search=native=lib/lib");
    println!("cargo:rustc-link-lib=static=seal-3.7");
}

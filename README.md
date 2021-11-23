# SEAL-Rust
Realize BFV in Rust.
Call C++ code from Rust by cxx.
* install Microsoft SEAL3.7 to lib/
```bash
git clone https://github.com/microsoft/SEAL
cd SEAL
cmake -S . -B build -DCMAKE_INSTALL_PREFIX=./SEAL-Rust/lib
cmake --build build
cmake --install build
```
* cargo build

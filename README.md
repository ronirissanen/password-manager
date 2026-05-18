# Secure Programming Project – C++ Password Manager

A command-line password manager developed for a secure programming course project.

The project focuses on:
- authenticated encryption with Libsodium
- secure memory handling
- explicit zeroization
- reducing exposure to memory inspection attacks

## Dependencies

- CMake
- Libsodium
- Linux environment

## Build

```bash
mkdir build
cd build
cmake ..
make
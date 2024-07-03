# WASM Sequoia PGP Implementation

## Overview
This repository contains a WebAssembly implementation of Sequoia PGP.
It is designed to handle cryptographic operations such as encryption, decryption, hashing, and signing within web applications. 


## Prerequisites
- Rust and Cargo (latest stable version)
- wasm-pack
- Node.js and npm

## Building the Project

1. **Clone the Repository:**
```
git clone git@github.com:osvauld/crypto_primitives.git
cd crypto_primitives
```
2. **Build the WebAssembly Module:**
```
wasm-pack build --release --target web
```
This command compiles the Rust code into a WebAssembly module suitable for use in web environments.
3. **Copy the generated files:**
copy the generated files from pkg folder
crypto_primitives.js to scripts folder and crypto_primitives_bg.wasm to public folder


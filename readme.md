# MAC Address Lookup Tool

A CLI tool to look up vendor information for MAC addresses using the [macvendors.com](https://macvendors.com) API. 
Secures API keys with AES-256-CBC encryption.

## Features
- MAC address format validation (`XX:XX:XX:XX:XX:XX`)
- Encrypted API key storage using OpenSSL (`AES-256-CBC`)
- API requests via libcurl
- Test mode with predefined MAC addresses
- Error handling for invalid inputs/network issues

## Prerequisites
- C compiler (gcc/clang)
- libcurl (`brew install curl` on macOS)
- OpenSSL (`brew install openssl` on macOS)

## Installation
```bash
git clone https://github.com/fferikvalik/mac_look_up.git
cd mac_look_up
gcc main.c -o mac_lookup -lcurl -lssl -lcrypto
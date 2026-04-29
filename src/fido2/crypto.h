// =============================================================================
// fido2/crypto.h — ECDSA P-256 Cryptographic Operations via mbedTLS
// =============================================================================
#pragma once

#include <Arduino.h>

// Initialize the crypto engine (entropy, DRBG).
// Must be called once in setup() before any key operations.
bool cryptoInit();

// Generate a new ECDSA P-256 keypair.
// publicKey: output buffer, must be >= 65 bytes (uncompressed point)
// privateKey: output buffer, must be >= 32 bytes
// Returns true on success.
bool cryptoGenerateKeyPair(uint8_t* publicKey, size_t* pubKeyLen,
                           uint8_t* privateKey, size_t* privKeyLen);

// Sign a SHA-256 hash using an ECDSA P-256 private key.
// hash: 32-byte SHA-256 digest
// privateKey: 32-byte raw private key
// signature: output buffer for DER-encoded signature (max ~72 bytes)
// sigLen: in/out — on input, max buffer size; on output, actual signature length
// Returns true on success.
bool cryptoSign(const uint8_t* hash, size_t hashLen,
                const uint8_t* privateKey, size_t privKeyLen,
                uint8_t* signature, size_t* sigLen);

// Compute SHA-256 hash of data.
// data: input buffer
// dataLen: input length
// hash: output buffer, must be >= 32 bytes
// Returns true on success.
bool cryptoSHA256(const uint8_t* data, size_t dataLen, uint8_t* hash);

// Generate cryptographically random bytes.
bool cryptoRandom(uint8_t* buffer, size_t len);

// Cleanup crypto resources (call on shutdown if needed).
void cryptoFree();

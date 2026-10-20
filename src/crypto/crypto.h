// =============================================================================
// crypto/crypto.h — thin, checked wrappers over mbedTLS
// =============================================================================
#pragma once

#include <stdint.h>
#include <stddef.h>
#include <mbedtls/sha256.h>

namespace crypto {

bool init();

// Cryptographically secure random bytes (CTR-DRBG seeded from the hardware RNG).
void random(uint8_t* out, size_t len);

// Constant-time comparison.
bool equal(const uint8_t* a, const uint8_t* b, size_t len);

// Overwrite memory in a way the compiler cannot optimise away.
void wipe(void* p, size_t len);

// --- Hashes / MACs -----------------------------------------------------------

void sha256(const uint8_t* data, size_t len, uint8_t out[32]);

struct Sha256 {
    Sha256();
    ~Sha256();
    void update(const uint8_t* data, size_t len);
    void finish(uint8_t out[32]);
private:
    mbedtls_sha256_context m_ctx;
};

void hmacSha256(const uint8_t* key, size_t keyLen,
                const uint8_t* data, size_t dataLen, uint8_t out[32]);

// HMAC over the concatenation of up to three buffers (null/0 to omit).
void hmacSha256Multi(const uint8_t* key, size_t keyLen,
                     const uint8_t* d1, size_t l1,
                     const uint8_t* d2, size_t l2,
                     const uint8_t* d3, size_t l3, uint8_t out[32]);

// HMAC-SHA1 / SHA256 / SHA512 for TOTP. `algo`: 1, 256 or 512. Returns digest length.
size_t hmacTotp(int algo, const uint8_t* key, size_t keyLen,
                const uint8_t* data, size_t dataLen, uint8_t out[64]);

// RFC 5869 HKDF-SHA256. An empty salt means HashLen zero bytes.
void hkdfSha256(const uint8_t* ikm, size_t ikmLen,
                const uint8_t* salt, size_t saltLen,
                const uint8_t* info, size_t infoLen,
                uint8_t* out, size_t outLen);

// --- Symmetric ---------------------------------------------------------------

void aes256EcbEncrypt(const uint8_t key[32], const uint8_t in[16], uint8_t out[16]);

// AES-256-GCM, 16-byte tag appended to the ciphertext.
bool aesGcmSeal(const uint8_t key[32], const uint8_t nonce[12],
                const uint8_t* aad, size_t aadLen,
                const uint8_t* pt, size_t ptLen, uint8_t* out /* ptLen + 16 */);
bool aesGcmOpen(const uint8_t key[32], const uint8_t nonce[12],
                const uint8_t* aad, size_t aadLen,
                const uint8_t* ct, size_t ctLen /* incl. tag */, uint8_t* out);

// --- P-256 -------------------------------------------------------------------

// True if `priv` is a valid scalar in [1, n-1].
bool p256ValidPrivate(const uint8_t priv[32]);
// Uncompressed public key (0x04 || X || Y) for a private scalar.
bool p256Public(const uint8_t priv[32], uint8_t pub[65]);
bool p256Generate(uint8_t priv[32], uint8_t pub[65]);
// ECDSA-SHA256 over a precomputed 32-byte digest. DER signature (max 72 bytes).
bool p256Sign(const uint8_t priv[32], const uint8_t hash[32], uint8_t* sig, size_t* sigLen);
// ECDH: x-coordinate of priv * peer. Validates that `peer` is on the curve.
bool p256Ecdh(const uint8_t priv[32], const uint8_t peer[65], uint8_t shared[32]);
// Expand a 33-byte compressed point to 65-byte uncompressed form (validated).
bool p256Decompress(const uint8_t in[33], uint8_t out[65]);

}  // namespace crypto

// =============================================================================
// fido2/crypto.cpp — ECDSA P-256 Cryptographic Operations via mbedTLS
// ESP32 Arduino uses mbedTLS v2.x — struct members are directly accessible.
// =============================================================================

#include "crypto.h"

#include <mbedtls/ecdsa.h>
#include <mbedtls/ecp.h>
#include <mbedtls/entropy.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/sha256.h>
#include <string.h>

// =============================================================================
// GLOBAL CONTEXTS (persistent for the lifetime of the application)
// =============================================================================

static mbedtls_entropy_context  s_entropy;
static mbedtls_ctr_drbg_context s_ctrDrbg;
static bool s_initialized = false;

static const char* DRBG_PERS = "AuthKey-ESP32-FIDO2";

// =============================================================================
// INITIALIZATION
// =============================================================================

bool cryptoInit() {
    if (s_initialized) return true;

    mbedtls_entropy_init(&s_entropy);
    mbedtls_ctr_drbg_init(&s_ctrDrbg);

    int ret = mbedtls_ctr_drbg_seed(&s_ctrDrbg, mbedtls_entropy_func, &s_entropy,
                                     (const uint8_t*)DRBG_PERS, strlen(DRBG_PERS));
    if (ret != 0) {
        Serial.printf("[CRYPTO] DRBG seed failed: -0x%04X\n", -ret);
        return false;
    }

    s_initialized = true;
    Serial.println("[CRYPTO] Engine initialized (ECDSA P-256 via mbedTLS).");
    return true;
}

// =============================================================================
// KEY GENERATION
// =============================================================================

bool cryptoGenerateKeyPair(uint8_t* publicKey, size_t* pubKeyLen,
                           uint8_t* privateKey, size_t* privKeyLen) {
    if (!s_initialized) return false;

    mbedtls_ecp_keypair keypair;
    mbedtls_ecp_keypair_init(&keypair);

    int ret;

    // Load the P-256 curve (mbedTLS v2.x: direct member access)
    ret = mbedtls_ecp_group_load(&keypair.grp, MBEDTLS_ECP_DP_SECP256R1);
    if (ret != 0) {
        Serial.printf("[CRYPTO] Group load failed: -0x%04X\n", -ret);
        mbedtls_ecp_keypair_free(&keypair);
        return false;
    }

    // Generate the keypair
    ret = mbedtls_ecp_gen_keypair(&keypair.grp, &keypair.d, &keypair.Q,
                                   mbedtls_ctr_drbg_random, &s_ctrDrbg);
    if (ret != 0) {
        Serial.printf("[CRYPTO] Keypair gen failed: -0x%04X\n", -ret);
        mbedtls_ecp_keypair_free(&keypair);
        return false;
    }

    // Export public key (uncompressed: 0x04 || X || Y = 65 bytes)
    size_t olen = 0;
    ret = mbedtls_ecp_point_write_binary(&keypair.grp, &keypair.Q,
                                          MBEDTLS_ECP_PF_UNCOMPRESSED,
                                          &olen, publicKey, *pubKeyLen);
    if (ret != 0) {
        Serial.printf("[CRYPTO] PubKey export failed: -0x%04X\n", -ret);
        mbedtls_ecp_keypair_free(&keypair);
        return false;
    }
    *pubKeyLen = olen;

    // Export private key (raw 32-byte big-endian scalar)
    ret = mbedtls_mpi_write_binary(&keypair.d, privateKey, 32);
    if (ret != 0) {
        Serial.printf("[CRYPTO] PrivKey export failed: -0x%04X\n", -ret);
        mbedtls_ecp_keypair_free(&keypair);
        return false;
    }
    *privKeyLen = 32;

    mbedtls_ecp_keypair_free(&keypair);
    Serial.println("[CRYPTO] Generated ECDSA P-256 keypair.");
    return true;
}

// =============================================================================
// SIGNING
// =============================================================================

bool cryptoSign(const uint8_t* hash, size_t hashLen,
                const uint8_t* privateKey, size_t privKeyLen,
                uint8_t* signature, size_t* sigLen) {
    if (!s_initialized) return false;

    mbedtls_ecdsa_context ctx;
    mbedtls_ecdsa_init(&ctx);

    int ret;

    // Load the P-256 curve
    ret = mbedtls_ecp_group_load(&ctx.grp, MBEDTLS_ECP_DP_SECP256R1);
    if (ret != 0) {
        mbedtls_ecdsa_free(&ctx);
        return false;
    }

    // Import private key
    ret = mbedtls_mpi_read_binary(&ctx.d, privateKey, privKeyLen);
    if (ret != 0) {
        mbedtls_ecdsa_free(&ctx);
        return false;
    }

    // Sign the hash (mbedTLS v2.x signature)
    ret = mbedtls_ecdsa_write_signature(&ctx, MBEDTLS_MD_SHA256,
                                         hash, hashLen,
                                         signature, sigLen,
                                         mbedtls_ctr_drbg_random, &s_ctrDrbg);
    if (ret != 0) {
        Serial.printf("[CRYPTO] Sign failed: -0x%04X\n", -ret);
        mbedtls_ecdsa_free(&ctx);
        return false;
    }

    mbedtls_ecdsa_free(&ctx);
    return true;
}

// =============================================================================
// SHA-256
// =============================================================================

bool cryptoSHA256(const uint8_t* data, size_t dataLen, uint8_t* hash) {
    // mbedTLS v2.x: mbedtls_sha256_ret() returns int, mbedtls_sha256() is void
    int ret = mbedtls_sha256_ret(data, dataLen, hash, 0);  // 0 = SHA-256
    return (ret == 0);
}

// =============================================================================
// RANDOM NUMBER GENERATION
// =============================================================================

bool cryptoRandom(uint8_t* buffer, size_t len) {
    if (!s_initialized) return false;
    int ret = mbedtls_ctr_drbg_random(&s_ctrDrbg, buffer, len);
    return (ret == 0);
}

// =============================================================================
// CLEANUP
// =============================================================================

void cryptoFree() {
    mbedtls_ctr_drbg_free(&s_ctrDrbg);
    mbedtls_entropy_free(&s_entropy);
    s_initialized = false;
}

// =============================================================================
// fido2/cable_tunnel.cpp — caBLE v2 WebSocket Tunnel + Noise_KNpsk0 Handshake
// =============================================================================

#include "cable_tunnel.h"
#include "ble_transport.h"
#include "ctap2.h"
#include "../ntp_sync.h"
#include "../config.h"

#include <WiFiClientSecure.h>
#include <WebSocketsClient.h>
#include <mbedtls/md.h>
#include <mbedtls/sha256.h>
#include <mbedtls/gcm.h>
#include <mbedtls/ecp.h>
#include <mbedtls/ecdh.h>
#include <mbedtls/bignum.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/entropy.h>

// =============================================================================
// NOISE PROTOCOL STATE
// =============================================================================

struct NoiseState {
    uint8_t h[32];    // handshake hash
    uint8_t ck[32];   // chaining key
    uint8_t k[32];    // symmetric key
    bool    hasKey;
    uint32_t n;       // nonce counter
};

// =============================================================================
// MODULE STATE
// =============================================================================

static WebSocketsClient s_ws;
static bool s_tunnelActive = false;
static bool s_wsConnected = false;
static bool s_handshakeDone = false;

// Saved from provisioning
static uint8_t s_qrSecret[16];
static uint8_t s_peerIdentity[65];  // decompressed uncompressed pubkey
static uint8_t s_psk[32];

// Post-handshake traffic keys
static uint8_t s_readKey[32];
static uint8_t s_writeKey[32];
static uint32_t s_readSeq = 0;
static uint32_t s_writeSeq = 0;

// Forward declarations
static void onWebSocketEvent(WStype_t type, uint8_t* payload, size_t length);
static bool handleNoiseHandshake(const uint8_t* msg, size_t len);
static void handleEncryptedCtap(const uint8_t* data, size_t len);

// =============================================================================
// CRYPTO HELPERS
// =============================================================================

static void hmac_sha256(const uint8_t* key, size_t klen,
                        const uint8_t* data, size_t dlen,
                        uint8_t out[32]) {
    mbedtls_md_hmac(mbedtls_md_info_from_type(MBEDTLS_MD_SHA256),
                    key, klen, data, dlen, out);
}

// Standard HKDF-SHA256 (manual implementation — ESP32 mbedTLS lacks mbedtls_hkdf)
static void cable_hkdf(const uint8_t* ikm, size_t ikm_len,
                       const uint8_t* salt, size_t salt_len,
                       const uint8_t* info, size_t info_len,
                       uint8_t* okm, size_t okm_len) {
    // Extract: PRK = HMAC-SHA256(salt=zeros if null, IKM)
    uint8_t prk[32];
    uint8_t default_salt[32] = {0};
    const uint8_t* actual_salt = (salt != nullptr && salt_len > 0) ? salt : default_salt;
    size_t actual_salt_len = (salt != nullptr && salt_len > 0) ? salt_len : 32;
    
    hmac_sha256(actual_salt, actual_salt_len, ikm, ikm_len, prk);
    
    // Expand
    uint8_t t[32];
    size_t offset = 0;
    uint8_t counter = 1;
    mbedtls_md_context_t ctx;
    mbedtls_md_init(&ctx);
    mbedtls_md_setup(&ctx, mbedtls_md_info_from_type(MBEDTLS_MD_SHA256), 1);
    while (offset < okm_len) {
        mbedtls_md_hmac_starts(&ctx, prk, 32);
        if (counter > 1) mbedtls_md_hmac_update(&ctx, t, 32);
        mbedtls_md_hmac_update(&ctx, info, info_len);
        mbedtls_md_hmac_update(&ctx, &counter, 1);
        mbedtls_md_hmac_finish(&ctx, t);
        size_t to_copy = (okm_len - offset) > 32 ? 32 : (okm_len - offset);
        memcpy(okm + offset, t, to_copy);
        offset += to_copy;
        counter++;
    }
    mbedtls_md_free(&ctx);
}

// Noise HKDF (different from standard HKDF!)
// Returns 2 or 3 32-byte outputs
static void noise_hkdf(const uint8_t ck[32], const uint8_t* ikm, size_t ikm_len,
                       uint8_t out1[32], uint8_t out2[32], uint8_t* out3) {
    uint8_t temp_key[32];
    hmac_sha256(ck, 32, ikm, ikm_len, temp_key);
    
    uint8_t one = 0x01;
    hmac_sha256(temp_key, 32, &one, 1, out1);
    
    uint8_t buf2[33];
    memcpy(buf2, out1, 32);
    buf2[32] = 0x02;
    hmac_sha256(temp_key, 32, buf2, 33, out2);
    
    if (out3) {
        uint8_t buf3[33];
        memcpy(buf3, out2, 32);
        buf3[32] = 0x03;
        hmac_sha256(temp_key, 32, buf3, 33, out3);
    }
}

// Decompress P-256 compressed pubkey (33 bytes) to uncompressed (65 bytes)
// ESP32's mbedTLS lacks compressed point support, so we do it manually.
static bool decompressP256(const uint8_t compressed[33], uint8_t uncompressed[65]) {
    if (compressed[0] != 0x02 && compressed[0] != 0x03) return false;
    
    mbedtls_mpi x, y, p, a, b, rhs, exp, ax;
    mbedtls_mpi_init(&x); mbedtls_mpi_init(&y);
    mbedtls_mpi_init(&p); mbedtls_mpi_init(&a);
    mbedtls_mpi_init(&b); mbedtls_mpi_init(&rhs);
    mbedtls_mpi_init(&exp); mbedtls_mpi_init(&ax);
    
    // P-256 curve parameters
    mbedtls_mpi_read_string(&p, 16,
        "FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF");
    mbedtls_mpi_read_string(&a, 16,
        "FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFC");
    mbedtls_mpi_read_string(&b, 16,
        "5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B");
    
    mbedtls_mpi_read_binary(&x, compressed + 1, 32);
    
    // rhs = x^3 + a*x + b mod p
    mbedtls_mpi_mul_mpi(&rhs, &x, &x);
    mbedtls_mpi_mod_mpi(&rhs, &rhs, &p);
    mbedtls_mpi_mul_mpi(&rhs, &rhs, &x);
    mbedtls_mpi_mod_mpi(&rhs, &rhs, &p);
    mbedtls_mpi_mul_mpi(&ax, &a, &x);
    mbedtls_mpi_mod_mpi(&ax, &ax, &p);
    mbedtls_mpi_add_mpi(&rhs, &rhs, &ax);
    mbedtls_mpi_mod_mpi(&rhs, &rhs, &p);
    mbedtls_mpi_add_mpi(&rhs, &rhs, &b);
    mbedtls_mpi_mod_mpi(&rhs, &rhs, &p);
    
    // y = rhs^((p+1)/4) mod p  (valid because p ≡ 3 mod 4 for P-256)
    mbedtls_mpi_add_int(&exp, &p, 1);
    mbedtls_mpi_shift_r(&exp, 2);
    mbedtls_mpi_exp_mod(&y, &rhs, &exp, &p, NULL);
    
    // Choose correct y parity: 0x02 = even y, 0x03 = odd y
    if ((mbedtls_mpi_get_bit(&y, 0) != 0) != (compressed[0] == 0x03)) {
        mbedtls_mpi_sub_mpi(&y, &p, &y);
    }
    
    uncompressed[0] = 0x04;
    mbedtls_mpi_write_binary(&x, uncompressed + 1, 32);
    mbedtls_mpi_write_binary(&y, uncompressed + 33, 32);
    
    mbedtls_mpi_free(&x); mbedtls_mpi_free(&y);
    mbedtls_mpi_free(&p); mbedtls_mpi_free(&a);
    mbedtls_mpi_free(&b); mbedtls_mpi_free(&rhs);
    mbedtls_mpi_free(&exp); mbedtls_mpi_free(&ax);
    return true;
}

// =============================================================================
// NOISE STATE MACHINE
// =============================================================================

static NoiseState s_noise;

static void noiseInit() {
    // Protocol name: "Noise_NKpsk0_P256_AESGCM_SHA256" (31 chars, padded to 32)
    const char* name = "Noise_NKpsk0_P256_AESGCM_SHA256";
    memset(s_noise.h, 0, 32);
    memcpy(s_noise.h, name, 31);
    memcpy(s_noise.ck, s_noise.h, 32);
    s_noise.hasKey = false;
    s_noise.n = 0;
}

static void noiseMixHash(const uint8_t* data, size_t len) {
    // h = SHA256(h || data)
    mbedtls_sha256_context ctx;
    mbedtls_sha256_init(&ctx);
    mbedtls_sha256_starts(&ctx, 0);
    mbedtls_sha256_update(&ctx, s_noise.h, 32);
    mbedtls_sha256_update(&ctx, data, len);
    mbedtls_sha256_finish(&ctx, s_noise.h);
    mbedtls_sha256_free(&ctx);
}

static void noiseMixKey(const uint8_t* ikm, size_t ikm_len) {
    uint8_t new_ck[32];
    noise_hkdf(s_noise.ck, ikm, ikm_len, new_ck, s_noise.k, NULL);
    memcpy(s_noise.ck, new_ck, 32);
    s_noise.hasKey = true;
    s_noise.n = 0;
}

static void noiseMixKeyAndHash(const uint8_t* ikm, size_t ikm_len) {
    uint8_t new_ck[32], temp_h[32];
    noise_hkdf(s_noise.ck, ikm, ikm_len, new_ck, temp_h, s_noise.k);
    memcpy(s_noise.ck, new_ck, 32);
    noiseMixHash(temp_h, 32);
    s_noise.hasKey = true;
    s_noise.n = 0;
}

// Build 12-byte nonce: 4 zeros + big-endian uint64(n)
static void noiseNonce(uint32_t counter, uint8_t nonce[12]) {
    memset(nonce, 0, 12);
    // Last 4 bytes = big-endian counter (matching Chromium's ConstructNonce)
    nonce[8]  = (counter >> 24) & 0xFF;
    nonce[9]  = (counter >> 16) & 0xFF;
    nonce[10] = (counter >> 8)  & 0xFF;
    nonce[11] = counter & 0xFF;
}

// Encrypt and hash (returns ciphertext length, or -1 on error)
static int noiseEncryptAndHash(const uint8_t* pt, size_t pt_len,
                               uint8_t* ct, size_t ct_max) {
    if (!s_noise.hasKey) {
        // No key yet — just hash the plaintext
        noiseMixHash(pt, pt_len);
        memcpy(ct, pt, pt_len);
        return pt_len;
    }
    
    size_t ct_len = pt_len + 16; // GCM tag
    if (ct_max < ct_len) return -1;
    
    uint8_t nonce[12];
    noiseNonce(s_noise.n, nonce);
    
    mbedtls_gcm_context gcm;
    mbedtls_gcm_init(&gcm);
    mbedtls_gcm_setkey(&gcm, MBEDTLS_CIPHER_ID_AES, s_noise.k, 256);
    
    uint8_t tag[16];
    mbedtls_gcm_crypt_and_tag(&gcm, MBEDTLS_GCM_ENCRYPT,
                               pt_len, nonce, 12,
                               s_noise.h, 32,  // AAD = h
                               pt, ct, 16, tag);
    memcpy(ct + pt_len, tag, 16);
    mbedtls_gcm_free(&gcm);
    
    noiseMixHash(ct, ct_len);
    s_noise.n++;
    return ct_len;
}

// Decrypt and hash (returns plaintext length, or -1 on error)
static int noiseDecryptAndHash(const uint8_t* ct, size_t ct_len,
                               uint8_t* pt, size_t pt_max) {
    if (!s_noise.hasKey) {
        noiseMixHash(ct, ct_len);
        memcpy(pt, ct, ct_len);
        return ct_len;
    }
    
    if (ct_len < 16) return -1;
    size_t pt_len = ct_len - 16;
    if (pt_max < pt_len) return -1;
    
    uint8_t nonce[12];
    noiseNonce(s_noise.n, nonce);
    
    mbedtls_gcm_context gcm;
    mbedtls_gcm_init(&gcm);
    mbedtls_gcm_setkey(&gcm, MBEDTLS_CIPHER_ID_AES, s_noise.k, 256);
    
    int ret = mbedtls_gcm_auth_decrypt(&gcm, pt_len, nonce, 12,
                                        s_noise.h, 32,  // AAD = h
                                        ct + pt_len, 16, // tag
                                        ct, pt);
    mbedtls_gcm_free(&gcm);
    
    if (ret != 0) {
        Serial.printf("[NOISE] Decrypt failed: %d\n", ret);
        return -1;
    }
    
    noiseMixHash(ct, ct_len);
    s_noise.n++;
    return pt_len;
}

// Split chaining key into traffic keys
static void noiseSplit(uint8_t k1[32], uint8_t k2[32]) {
    noise_hkdf(s_noise.ck, (const uint8_t*)"", 0, k1, k2, NULL);
}

// =============================================================================
// NOISE HANDSHAKE — KNpsk0 RESPONDER
// =============================================================================

static bool handleNoiseHandshake(const uint8_t* msg, size_t len) {
    // Initiator message: ephemeral_pubkey(65) + ciphertext(16) = 81 bytes
    if (len < 81) {
        Serial.printf("[NOISE] Handshake msg too short: %d\n", len);
        return false;
    }
    
    const uint8_t* peer_e_pub = msg;        // 65 bytes
    const uint8_t* ciphertext = msg + 65;   // 16 bytes
    
    // --- Initialize Noise state ---
    noiseInit();
    
    // KNpsk0 prologue
    uint8_t prologue = 0x01;
    noiseMixHash(&prologue, 1);
    
    // "K" = peer's static identity is Known to us
    noiseMixHash(s_peerIdentity, 65);
    
    // psk0 — mix PSK at the start
    noiseMixKeyAndHash(s_psk, 32);
    
    // Process initiator's ephemeral key
    noiseMixHash(peer_e_pub, 65);
    noiseMixKey(peer_e_pub, 65);
    
    // Decrypt initiator's ciphertext (should be empty plaintext)
    uint8_t pt[64];
    int pt_len = noiseDecryptAndHash(ciphertext, 16, pt, sizeof(pt));
    if (pt_len < 0 || pt_len != 0) {
        Serial.println("[NOISE] Failed to decrypt initiator ciphertext");
        return false;
    }
    
    // --- Generate our ephemeral keypair ---
    mbedtls_ecp_group grp;
    mbedtls_ecp_point peer_e_point;
    mbedtls_mpi my_e_priv;
    mbedtls_ecp_point my_e_pub_pt;
    
    mbedtls_ecp_group_init(&grp);
    mbedtls_ecp_point_init(&peer_e_point);
    mbedtls_mpi_init(&my_e_priv);
    mbedtls_ecp_point_init(&my_e_pub_pt);
    mbedtls_ecp_group_load(&grp, MBEDTLS_ECP_DP_SECP256R1);
    
    // Parse peer's ephemeral point
    if (mbedtls_ecp_point_read_binary(&grp, &peer_e_point, peer_e_pub, 65) != 0) {
        Serial.println("[NOISE] Invalid peer ephemeral key");
        goto fail;
    }
    
    // Generate our ephemeral key
    {
        mbedtls_entropy_context entropy;
        mbedtls_ctr_drbg_context ctr_drbg;
        mbedtls_entropy_init(&entropy);
        mbedtls_ctr_drbg_init(&ctr_drbg);
        mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy,
                               (const uint8_t*)"cable", 5);
        
        if (mbedtls_ecp_gen_keypair(&grp, &my_e_priv, &my_e_pub_pt,
                                     mbedtls_ctr_drbg_random, &ctr_drbg) != 0) {
            Serial.println("[NOISE] Keygen failed");
            mbedtls_entropy_free(&entropy);
            mbedtls_ctr_drbg_free(&ctr_drbg);
            goto fail;
        }
        mbedtls_entropy_free(&entropy);
        mbedtls_ctr_drbg_free(&ctr_drbg);
    }
    
    // Serialize our ephemeral public key
    {
        uint8_t my_e_pub[65];
        size_t olen;
        mbedtls_ecp_point_write_binary(&grp, &my_e_pub_pt,
                                        MBEDTLS_ECP_PF_UNCOMPRESSED,
                                        &olen, my_e_pub, 65);
        
        noiseMixHash(my_e_pub, 65);
        noiseMixKey(my_e_pub, 65);
        
        // ECDH: shared_key_ee = ECDH(my_ephemeral, peer_ephemeral)
        mbedtls_mpi shared;
        mbedtls_mpi_init(&shared);
        if (mbedtls_ecdh_compute_shared(&grp, &shared, &peer_e_point,
                                         &my_e_priv, NULL, NULL) != 0) {
            Serial.println("[NOISE] ECDH ee failed");
            mbedtls_mpi_free(&shared);
            goto fail;
        }
        uint8_t shared_ee[32];
        mbedtls_mpi_write_binary(&shared, shared_ee, 32);
        mbedtls_mpi_free(&shared);
        noiseMixKey(shared_ee, 32);
        
        // ECDH: shared_key_se = ECDH(my_ephemeral, peer_identity)
        // Parse peer identity point
        mbedtls_ecp_point peer_id_point;
        mbedtls_ecp_point_init(&peer_id_point);
        mbedtls_ecp_point_read_binary(&grp, &peer_id_point, s_peerIdentity, 65);
        
        mbedtls_mpi shared_se_mpi;
        mbedtls_mpi_init(&shared_se_mpi);
        if (mbedtls_ecdh_compute_shared(&grp, &shared_se_mpi, &peer_id_point,
                                         &my_e_priv, NULL, NULL) != 0) {
            Serial.println("[NOISE] ECDH se failed");
            mbedtls_mpi_free(&shared_se_mpi);
            mbedtls_ecp_point_free(&peer_id_point);
            goto fail;
        }
        uint8_t shared_se[32];
        mbedtls_mpi_write_binary(&shared_se_mpi, shared_se, 32);
        mbedtls_mpi_free(&shared_se_mpi);
        mbedtls_ecp_point_free(&peer_id_point);
        noiseMixKey(shared_se, 32);
        
        // Encrypt empty payload for response
        uint8_t resp_ct[16];
        int resp_ct_len = noiseEncryptAndHash(NULL, 0, resp_ct, sizeof(resp_ct));
        if (resp_ct_len < 0) {
            Serial.println("[NOISE] Encrypt response failed");
            goto fail;
        }
        
        // Build response: my_ephemeral_pub(65) + ciphertext(16) = 81 bytes
        uint8_t response[81];
        memcpy(response, my_e_pub, 65);
        memcpy(response + 65, resp_ct, 16);
        
        // Derive traffic keys
        noiseSplit(s_readKey, s_writeKey);
        s_readSeq = 0;
        s_writeSeq = 0;
        
        // Send response through WebSocket
        s_ws.sendBIN(response, 81);
        Serial.println("[NOISE] Handshake response sent!");
        
        // Cleanup
        mbedtls_ecp_point_free(&peer_e_point);
        mbedtls_ecp_point_free(&my_e_pub_pt);
        mbedtls_mpi_free(&my_e_priv);
        mbedtls_ecp_group_free(&grp);
        
        s_handshakeDone = true;
        Serial.println("[TUNNEL] Noise handshake complete! Tunnel is live.");
        return true;
    }

fail:
    mbedtls_ecp_point_free(&peer_e_point);
    mbedtls_ecp_point_free(&my_e_pub_pt);
    mbedtls_mpi_free(&my_e_priv);
    mbedtls_ecp_group_free(&grp);
    return false;
}

// =============================================================================
// POST-HANDSHAKE ENCRYPTED CTAP2
// =============================================================================

static bool trafficDecrypt(const uint8_t* ct, size_t ct_len,
                           uint8_t* pt, size_t* pt_len) {
    if (ct_len < 16) return false;
    *pt_len = ct_len - 16;
    
    uint8_t nonce[12];
    memset(nonce, 0, 8);
    nonce[8]  = (s_readSeq >> 24) & 0xFF;
    nonce[9]  = (s_readSeq >> 16) & 0xFF;
    nonce[10] = (s_readSeq >> 8)  & 0xFF;
    nonce[11] = s_readSeq & 0xFF;
    
    mbedtls_gcm_context gcm;
    mbedtls_gcm_init(&gcm);
    mbedtls_gcm_setkey(&gcm, MBEDTLS_CIPHER_ID_AES, s_readKey, 256);
    
    int ret = mbedtls_gcm_auth_decrypt(&gcm, *pt_len, nonce, 12,
                                        NULL, 0,   // no AAD for traffic
                                        ct + *pt_len, 16,
                                        ct, pt);
    mbedtls_gcm_free(&gcm);
    s_readSeq++;
    return (ret == 0);
}

static bool __attribute__((unused)) trafficEncrypt(const uint8_t* pt, size_t pt_len,
                           uint8_t* ct, size_t* ct_len) {
    *ct_len = pt_len + 16;
    
    uint8_t nonce[12];
    memset(nonce, 0, 8);
    nonce[8]  = (s_writeSeq >> 24) & 0xFF;
    nonce[9]  = (s_writeSeq >> 16) & 0xFF;
    nonce[10] = (s_writeSeq >> 8)  & 0xFF;
    nonce[11] = s_writeSeq & 0xFF;
    
    mbedtls_gcm_context gcm;
    mbedtls_gcm_init(&gcm);
    mbedtls_gcm_setkey(&gcm, MBEDTLS_CIPHER_ID_AES, s_writeKey, 256);
    
    uint8_t tag[16];
    mbedtls_gcm_crypt_and_tag(&gcm, MBEDTLS_GCM_ENCRYPT,
                               pt_len, nonce, 12,
                               NULL, 0,   // no AAD for traffic
                               pt, ct, 16, tag);
    memcpy(ct + pt_len, tag, 16);
    mbedtls_gcm_free(&gcm);
    s_writeSeq++;
    return true;
}

// Remove caBLE padding from decrypted message
static size_t removePadding(uint8_t* data, size_t len) {
    if (len == 0) return 0;
    uint8_t pad_len = data[len - 1];
    if (pad_len + 1 > len) return 0;
    return len - pad_len - 1;
}

// Add caBLE padding (round up to 32 bytes)
static size_t __attribute__((unused)) addPadding(const uint8_t* in, size_t in_len,
                         uint8_t* out, size_t out_max) {
    size_t padded = ((in_len + 1 + 31) / 32) * 32;
    if (padded > out_max) return 0;
    memcpy(out, in, in_len);
    memset(out + in_len, 0, padded - in_len);
    out[padded - 1] = (uint8_t)(padded - in_len - 1);
    return padded;
}

static void handleEncryptedCtap(const uint8_t* data, size_t len) {
    uint8_t plaintext[512];
    size_t pt_len;
    
    if (!trafficDecrypt(data, len, plaintext, &pt_len)) {
        Serial.println("[TUNNEL] Traffic decryption failed!");
        return;
    }
    
    // Remove padding
    pt_len = removePadding(plaintext, pt_len);
    if (pt_len == 0) {
        Serial.println("[TUNNEL] Empty message after unpadding");
        return;
    }
    
    Serial.printf("[TUNNEL] CTAP2 request (%d bytes)\n", pt_len);
    
    // Forward to CTAP2 handler
    // TODO: Route CTAP2 response back through the tunnel
    ctap2ProcessCommand(plaintext, pt_len);
}

// =============================================================================
// WEBSOCKET EVENT HANDLER
// =============================================================================

static void onWebSocketEvent(WStype_t type, uint8_t* payload, size_t length) {
    switch (type) {
        case WStype_CONNECTED: {
            s_wsConnected = true;
            String payloadStr = payload ? (char*)payload : "";
            Serial.printf("[TUNNEL] WebSocket connected! Payload: %s\n", payloadStr.c_str());
            
            // Extract routing_id from payload (format: URL|routing_id)
            uint8_t routingId[3] = {0, 0, 0};
            int pipeIdx = payloadStr.indexOf('|');
            if (pipeIdx > 0) {
                String rIdHex = payloadStr.substring(pipeIdx + 1);
                if (rIdHex.length() >= 6) {
                    for (int i = 0; i < 3; i++) {
                        String byteStr = rIdHex.substring(i*2, i*2 + 2);
                        routingId[i] = (uint8_t) strtol(byteStr.c_str(), NULL, 16);
                    }
                    Serial.printf("[TUNNEL] Parsed routing_id: %02X %02X %02X\n", routingId[0], routingId[1], routingId[2]);
                }
            } else {
                Serial.println("[TUNNEL] WARNING: No routing_id found in connection payload!");
            }
            
            // Start EID advertising now that we have the routing_id
            uint8_t plaintextEid[16];
            bleTransportStartAdvertisingEID(s_qrSecret, routingId, plaintextEid);
            
            // Derive PSK from QR secret: HKDF(secret, salt=plaintext_eid, info=uint32(2), len=32)
            uint32_t psk_type = 2; // kPSK = 2
            cable_hkdf(s_qrSecret, 16, plaintextEid, 16, (const uint8_t*)&psk_type, 4, s_psk, 32);
            break;
        }
            
        case WStype_DISCONNECTED:
            s_wsConnected = false;
            s_handshakeDone = false;
            Serial.printf("[TUNNEL] WebSocket disconnected (len=%d)\n", length);
            if (payload && length > 0) {
                Serial.printf("[TUNNEL] Disconnect info: %.*s\n", (int)length, payload);
            }
            break;
            
        case WStype_BIN:
            Serial.printf("[TUNNEL] Received %d bytes\n", length);
            if (!s_handshakeDone) {
                handleNoiseHandshake(payload, length);
            } else {
                handleEncryptedCtap(payload, length);
            }
            break;
            
        case WStype_ERROR:
            Serial.printf("[TUNNEL] WebSocket ERROR (len=%d)\n", length);
            if (payload && length > 0) {
                Serial.printf("[TUNNEL] Error data: %.*s\n", (int)length, payload);
            }
            break;
        
        case WStype_TEXT:
            Serial.printf("[TUNNEL] Text: %.*s\n", (int)length, payload);
            break;
            
        default:
            Serial.printf("[TUNNEL] WS event type=%d len=%d\n", type, length);
            break;
    }
}

// =============================================================================
// PUBLIC API
// =============================================================================

void cableTunnelStart(const uint8_t* qrSecret, const uint8_t* peerIdentity) {
    Serial.println("[TUNNEL] Starting caBLE v2 tunnel...");
    
    // Save QR secret
    memcpy(s_qrSecret, qrSecret, 16);
    
    // Decompress peer identity public key (33 → 65 bytes)
    if (!decompressP256(peerIdentity, s_peerIdentity)) {
        Serial.println("[TUNNEL] Failed to decompress peer identity key!");
        return;
    }
    Serial.println("[TUNNEL] Peer identity key decompressed OK");
    
    // Derive tunnel ID: HKDF(secret, salt=null, info=uint32(0), len=16)
    uint8_t tunnelId[16];
    uint32_t tid_type = 0; // kTunnelID = 0
    cable_hkdf(qrSecret, 16, nullptr, 0, (const uint8_t*)&tid_type, 4, tunnelId, 16);
    
    // Hex-encode tunnel ID (confirmed from Chromium: GetNewTunnelURL uses base::HexEncode)
    char tunnelIdHex[33];
    for (int i = 0; i < 16; i++) {
        sprintf(tunnelIdHex + i*2, "%02x", tunnelId[i]);
    }
    
    char path[80];
    snprintf(path, sizeof(path), "/cable/new/%s", tunnelIdHex);
    Serial.printf("[TUNNEL] Path: %s\n", path);
    
    // 1. (EID advertising is delayed until WebSocket connects and we get the routing_id)
    
    // 2. Reconnect WiFi for tunnel
    if (!wifiReconnect()) {
        Serial.println("[TUNNEL] WiFi reconnect failed");
        return;
    }
    
    // 3. Connect WebSocket to tunnel server (WSS)
    s_ws.beginSslWithCA("cable.ua5v.com", 443, path, NULL, "fido.cable");
    s_ws.setExtraHeaders("Origin: wss://cable.ua5v.com");
    s_ws.onEvent(onWebSocketEvent);
    s_ws.setReconnectInterval(5000);
    
    s_tunnelActive = true;
    s_handshakeDone = false;
    s_wsConnected = false;
    
    Serial.println("[TUNNEL] Tunnel initiated — waiting for Chrome...");
}

void cableTunnelLoop() {
    if (s_tunnelActive) {
        s_ws.loop();
    }
}

bool cableTunnelIsActive() {
    return s_tunnelActive && s_wsConnected;
}

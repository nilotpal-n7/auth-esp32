#include "crypto/crypto.h"
#include "core/log.h"

#include <string.h>
#include <esp_system.h>
#include <freertos/FreeRTOS.h>
#include <freertos/semphr.h>
#include <mbedtls/aes.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/ecdh.h>
#include <mbedtls/ecdsa.h>
#include <mbedtls/ecp.h>
#include <mbedtls/gcm.h>
#include <mbedtls/md.h>

namespace crypto {

static mbedtls_ctr_drbg_context s_drbg;
static mbedtls_ecp_group        s_p256;
static SemaphoreHandle_t        s_lock = nullptr;
static bool                     s_ready = false;

// Entropy callback for CTR-DRBG: the ESP32 hardware RNG. It is a true RNG
// whenever WiFi or Bluetooth is running and is seeded from bootloader noise
// before that.
static int hwEntropy(void*, unsigned char* out, size_t len) {
    esp_fill_random(out, len);
    return 0;
}

static int rngCb(void*, unsigned char* out, size_t len) {
    random(out, len);
    return 0;
}

bool init() {
    if (s_ready) return true;
    s_lock = xSemaphoreCreateMutex();
    mbedtls_ctr_drbg_init(&s_drbg);
    static const char pers[] = "AuthKey-ESP32 DRBG";
    int rc = mbedtls_ctr_drbg_seed(&s_drbg, hwEntropy, nullptr,
                                   (const unsigned char*)pers, sizeof(pers) - 1);
    if (rc != 0) {
        logf("CRYPTO", "DRBG seed failed: -0x%04X", -rc);
        return false;
    }
    mbedtls_ctr_drbg_set_prediction_resistance(&s_drbg, MBEDTLS_CTR_DRBG_PR_ON);
    mbedtls_ecp_group_init(&s_p256);
    rc = mbedtls_ecp_group_load(&s_p256, MBEDTLS_ECP_DP_SECP256R1);
    if (rc != 0) {
        logf("CRYPTO", "P-256 load failed: -0x%04X", -rc);
        return false;
    }
    s_ready = true;
    return true;
}

void random(uint8_t* out, size_t len) {
    xSemaphoreTake(s_lock, portMAX_DELAY);
    while (len) {
        size_t n = len > MBEDTLS_CTR_DRBG_MAX_REQUEST ? MBEDTLS_CTR_DRBG_MAX_REQUEST : len;
        if (mbedtls_ctr_drbg_random(&s_drbg, out, n) != 0) {
            // Should never happen; fall back to the raw hardware RNG rather
            // than returning predictable output.
            esp_fill_random(out, n);
        }
        out += n;
        len -= n;
    }
    xSemaphoreGive(s_lock);
}

bool equal(const uint8_t* a, const uint8_t* b, size_t len) {
    uint8_t d = 0;
    for (size_t i = 0; i < len; i++) d |= a[i] ^ b[i];
    return d == 0;
}

void wipe(void* p, size_t len) {
    volatile uint8_t* v = (volatile uint8_t*)p;
    while (len--) *v++ = 0;
}

// --- Hashes ------------------------------------------------------------------

void sha256(const uint8_t* data, size_t len, uint8_t out[32]) {
    mbedtls_sha256_ret(data, len, out, 0);
}

Sha256::Sha256()  { mbedtls_sha256_init(&m_ctx); mbedtls_sha256_starts_ret(&m_ctx, 0); }
Sha256::~Sha256() { mbedtls_sha256_free(&m_ctx); }
void Sha256::update(const uint8_t* d, size_t n) { mbedtls_sha256_update_ret(&m_ctx, d, n); }
void Sha256::finish(uint8_t out[32]) { mbedtls_sha256_finish_ret(&m_ctx, out); }

static void hmacMulti(mbedtls_md_type_t type, const uint8_t* key, size_t keyLen,
                      const uint8_t* d1, size_t l1, const uint8_t* d2, size_t l2,
                      const uint8_t* d3, size_t l3, uint8_t* out) {
    mbedtls_md_context_t ctx;
    mbedtls_md_init(&ctx);
    mbedtls_md_setup(&ctx, mbedtls_md_info_from_type(type), 1);
    mbedtls_md_hmac_starts(&ctx, key, keyLen);
    if (l1) mbedtls_md_hmac_update(&ctx, d1, l1);
    if (l2) mbedtls_md_hmac_update(&ctx, d2, l2);
    if (l3) mbedtls_md_hmac_update(&ctx, d3, l3);
    mbedtls_md_hmac_finish(&ctx, out);
    mbedtls_md_free(&ctx);
}

void hmacSha256(const uint8_t* key, size_t keyLen, const uint8_t* data, size_t dataLen,
                uint8_t out[32]) {
    hmacMulti(MBEDTLS_MD_SHA256, key, keyLen, data, dataLen, nullptr, 0, nullptr, 0, out);
}

void hmacSha256Multi(const uint8_t* key, size_t keyLen,
                     const uint8_t* d1, size_t l1, const uint8_t* d2, size_t l2,
                     const uint8_t* d3, size_t l3, uint8_t out[32]) {
    hmacMulti(MBEDTLS_MD_SHA256, key, keyLen, d1, l1, d2, l2, d3, l3, out);
}

size_t hmacTotp(int algo, const uint8_t* key, size_t keyLen,
                const uint8_t* data, size_t dataLen, uint8_t out[64]) {
    mbedtls_md_type_t t = MBEDTLS_MD_SHA1;
    size_t n = 20;
    if (algo == 256) { t = MBEDTLS_MD_SHA256; n = 32; }
    if (algo == 512) { t = MBEDTLS_MD_SHA512; n = 64; }
    hmacMulti(t, key, keyLen, data, dataLen, nullptr, 0, nullptr, 0, out);
    return n;
}

void hkdfSha256(const uint8_t* ikm, size_t ikmLen, const uint8_t* salt, size_t saltLen,
                const uint8_t* info, size_t infoLen, uint8_t* out, size_t outLen) {
    static const uint8_t zeros[32] = {0};
    if (saltLen == 0) { salt = zeros; saltLen = sizeof(zeros); }
    uint8_t prk[32];
    hmacSha256(salt, saltLen, ikm, ikmLen, prk);

    uint8_t t[32];
    size_t tLen = 0;
    for (uint8_t counter = 1; outLen > 0; counter++) {
        hmacMulti(MBEDTLS_MD_SHA256, prk, sizeof(prk), t, tLen, info, infoLen, &counter, 1, t);
        tLen = 32;
        size_t n = outLen < 32 ? outLen : 32;
        memcpy(out, t, n);
        out += n;
        outLen -= n;
    }
    wipe(prk, sizeof(prk));
    wipe(t, sizeof(t));
}

// --- Symmetric ---------------------------------------------------------------

void aes256EcbEncrypt(const uint8_t key[32], const uint8_t in[16], uint8_t out[16]) {
    mbedtls_aes_context aes;
    mbedtls_aes_init(&aes);
    mbedtls_aes_setkey_enc(&aes, key, 256);
    mbedtls_aes_crypt_ecb(&aes, MBEDTLS_AES_ENCRYPT, in, out);
    mbedtls_aes_free(&aes);
}

bool aesGcmSeal(const uint8_t key[32], const uint8_t nonce[12], const uint8_t* aad, size_t aadLen,
                const uint8_t* pt, size_t ptLen, uint8_t* out) {
    static const uint8_t empty[1] = {0};
    if (!pt) pt = empty;   // the hardware GCM path rejects NULL input
    mbedtls_gcm_context gcm;
    mbedtls_gcm_init(&gcm);
    int rc = mbedtls_gcm_setkey(&gcm, MBEDTLS_CIPHER_ID_AES, key, 256);
    if (rc == 0) {
        rc = mbedtls_gcm_crypt_and_tag(&gcm, MBEDTLS_GCM_ENCRYPT, ptLen, nonce, 12,
                                       aad, aadLen, pt, out, 16, out + ptLen);
    }
    mbedtls_gcm_free(&gcm);
    if (rc != 0) logf("CRYPTO", "GCM seal failed: -0x%04X", -rc);
    return rc == 0;
}

bool aesGcmOpen(const uint8_t key[32], const uint8_t nonce[12], const uint8_t* aad, size_t aadLen,
                const uint8_t* ct, size_t ctLen, uint8_t* out) {
    if (ctLen < 16) return false;
    mbedtls_gcm_context gcm;
    mbedtls_gcm_init(&gcm);
    int rc = mbedtls_gcm_setkey(&gcm, MBEDTLS_CIPHER_ID_AES, key, 256);
    if (rc == 0) {
        rc = mbedtls_gcm_auth_decrypt(&gcm, ctLen - 16, nonce, 12, aad, aadLen,
                                      ct + ctLen - 16, 16, ct, out);
    }
    mbedtls_gcm_free(&gcm);
    return rc == 0;
}

// --- P-256 -------------------------------------------------------------------

struct Mpi {
    mbedtls_mpi v;
    Mpi() { mbedtls_mpi_init(&v); }
    ~Mpi() { mbedtls_mpi_free(&v); }
};
struct Point {
    mbedtls_ecp_point v;
    Point() { mbedtls_ecp_point_init(&v); }
    ~Point() { mbedtls_ecp_point_free(&v); }
};

static bool loadPrivate(const uint8_t priv[32], Mpi& d) {
    return mbedtls_mpi_read_binary(&d.v, priv, 32) == 0 &&
           mbedtls_ecp_check_privkey(&s_p256, &d.v) == 0;
}

static bool loadPublic(const uint8_t pub[65], Point& q) {
    return mbedtls_ecp_point_read_binary(&s_p256, &q.v, pub, 65) == 0 &&
           mbedtls_ecp_check_pubkey(&s_p256, &q.v) == 0;
}

bool p256ValidPrivate(const uint8_t priv[32]) {
    Mpi d;
    return loadPrivate(priv, d);
}

bool p256Public(const uint8_t priv[32], uint8_t pub[65]) {
    Mpi d;
    Point q;
    if (!loadPrivate(priv, d)) return false;
    if (mbedtls_ecp_mul(&s_p256, &q.v, &d.v, &s_p256.G, rngCb, nullptr) != 0) return false;
    size_t olen = 0;
    return mbedtls_ecp_point_write_binary(&s_p256, &q.v, MBEDTLS_ECP_PF_UNCOMPRESSED,
                                          &olen, pub, 65) == 0 && olen == 65;
}

bool p256Generate(uint8_t priv[32], uint8_t pub[65]) {
    for (int attempt = 0; attempt < 8; attempt++) {
        random(priv, 32);
        if (p256Public(priv, pub)) return true;
    }
    return false;
}

bool p256Sign(const uint8_t priv[32], const uint8_t hash[32], uint8_t* sig, size_t* sigLen) {
    mbedtls_ecdsa_context ctx;
    mbedtls_ecdsa_init(&ctx);
    bool ok = mbedtls_ecp_group_load(&ctx.grp, MBEDTLS_ECP_DP_SECP256R1) == 0 &&
              mbedtls_mpi_read_binary(&ctx.d, priv, 32) == 0 &&
              mbedtls_ecdsa_write_signature(&ctx, MBEDTLS_MD_SHA256, hash, 32, sig, sigLen,
                                            rngCb, nullptr) == 0;
    mbedtls_ecdsa_free(&ctx);
    return ok;
}

bool p256Ecdh(const uint8_t priv[32], const uint8_t peer[65], uint8_t shared[32]) {
    Mpi d, z;
    Point q;
    if (!loadPrivate(priv, d) || !loadPublic(peer, q)) return false;
    if (mbedtls_ecdh_compute_shared(&s_p256, &z.v, &q.v, &d.v, rngCb, nullptr) != 0) return false;
    return mbedtls_mpi_write_binary(&z.v, shared, 32) == 0;
}

bool p256Decompress(const uint8_t in[33], uint8_t out[65]) {
    if (in[0] != 0x02 && in[0] != 0x03) return false;
    Mpi x, rhs, t, y, e;
    const mbedtls_mpi* p = &s_p256.P;
    bool ok = mbedtls_mpi_read_binary(&x.v, in + 1, 32) == 0 &&
              mbedtls_mpi_cmp_mpi(&x.v, p) < 0 &&
              // rhs = x^3 + a*x + b  (a = -3 for P-256, stored in grp.A)
              mbedtls_mpi_mul_mpi(&rhs.v, &x.v, &x.v) == 0 &&
              mbedtls_mpi_mod_mpi(&rhs.v, &rhs.v, p) == 0 &&
              mbedtls_mpi_mul_mpi(&rhs.v, &rhs.v, &x.v) == 0 &&
              mbedtls_mpi_mod_mpi(&rhs.v, &rhs.v, p) == 0 &&
              mbedtls_mpi_mul_int(&t.v, &x.v, 3) == 0 &&
              mbedtls_mpi_sub_mpi(&rhs.v, &rhs.v, &t.v) == 0 &&
              mbedtls_mpi_add_mpi(&rhs.v, &rhs.v, &s_p256.B) == 0 &&
              mbedtls_mpi_mod_mpi(&rhs.v, &rhs.v, p) == 0 &&
              // y = rhs^((p+1)/4) mod p   (p ≡ 3 mod 4)
              mbedtls_mpi_add_int(&e.v, p, 1) == 0 &&
              mbedtls_mpi_shift_r(&e.v, 2) == 0 &&
              mbedtls_mpi_exp_mod(&y.v, &rhs.v, &e.v, p, nullptr) == 0;
    if (!ok) return false;
    if (mbedtls_mpi_get_bit(&y.v, 0) != (in[0] & 1)) {
        if (mbedtls_mpi_sub_mpi(&y.v, p, &y.v) != 0) return false;
    }
    out[0] = 0x04;
    memcpy(out + 1, in + 1, 32);
    if (mbedtls_mpi_write_binary(&y.v, out + 33, 32) != 0) return false;
    // Rejects x values with no square root (point not on the curve).
    Point q;
    return loadPublic(out, q);
}

}  // namespace crypto

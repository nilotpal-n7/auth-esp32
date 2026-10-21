#include "core/backup.h"
#include "config.h"
#include "core/approval.h"
#include "core/log.h"
#include "core/settings.h"
#include "crypto/crypto.h"
#include "fido/credentials.h"
#include "totp/totp.h"
#include "unlock/unlock.h"
#include "util/codec.h"

namespace backup {

// Plaintext layout (little-endian), sealed with AES-256-GCM:
//   "AKB1" | u16 version | u16 sizeof(ResidentCredential) | u16 sizeof(TotpAccount)
//   | u16 sizeof(PcEntry) | master key (32) | u32 sign counter
//   | u8 n + n passkey records (oldest first) | u8 n + n TOTP accounts | u8 n + n PCs
// The record sizes tie a backup to this firmware's storage format.
static const char    AAD[] = "AuthKey backup v1";
static const uint8_t MAGIC[4] = {'A', 'K', 'B', '1'};
static const uint16_t VERSION = 1;
static const size_t  MAX_PLAIN = 12 + 32 + 4 + 3 + FIDO_MAX_RESIDENT * sizeof(ResidentCredential) +
                                 TOTP_MAX_ACCOUNTS * sizeof(TotpAccount) +
                                 UNLOCK_MAX_PCS * sizeof(unlock::PcEntry);
static const size_t  LINE_BYTES = 128;   // per "BACKUP data" line

static uint8_t  s_key[32];
static uint8_t  s_nonce[12];
static uint8_t* s_buf = nullptr;     // restore: ciphertext, then plaintext
static size_t   s_len = 0, s_have = 0;

struct Writer {
    uint8_t* p; size_t n, cap; bool ok = true;
    void put(const void* d, size_t l) {
        if (n + l > cap) { ok = false; return; }
        memcpy(p + n, d, l);
        n += l;
    }
    void u8(uint8_t v) { put(&v, 1); }
    void u16(uint16_t v) { uint8_t b[2] = {(uint8_t)v, (uint8_t)(v >> 8)}; put(b, 2); }
    void u32(uint32_t v) { uint8_t b[4] = {(uint8_t)v, (uint8_t)(v >> 8), (uint8_t)(v >> 16), (uint8_t)(v >> 24)}; put(b, 4); }
};

struct Reader {
    const uint8_t* p; size_t n, pos = 0; bool ok = true;
    const uint8_t* take(size_t l) {
        if (pos + l > n) { ok = false; return nullptr; }
        const uint8_t* r = p + pos;
        pos += l;
        return r;
    }
    uint8_t u8() { const uint8_t* b = take(1); return b ? b[0] : 0; }
    uint16_t u16() { const uint8_t* b = take(2); return b ? (uint16_t)(b[0] | b[1] << 8) : 0; }
    uint32_t u32() {
        const uint8_t* b = take(4);
        return b ? (uint32_t)b[0] | (uint32_t)b[1] << 8 | (uint32_t)b[2] << 16 | (uint32_t)b[3] << 24 : 0;
    }
};

static void freeBuf() {
    if (s_buf) {
        crypto::wipe(s_buf, s_len);
        free(s_buf);
    }
    s_buf = nullptr;
    s_len = s_have = 0;
}

static void wipeKey() { crypto::wipe(s_key, sizeof(s_key)); }

static void summary(int passkeys, int totps, int pcs, char* out, size_t cap) {
    snprintf(out, cap, "%d passkey%s, %d TOTP, %d PC", passkeys, passkeys == 1 ? "" : "s", totps, pcs);
}

// --- Export ------------------------------------------------------------------

static size_t buildPlain(uint8_t* out, size_t cap) {
    Writer w{out, 0, cap};
    w.put(MAGIC, 4);
    w.u16(VERSION);
    w.u16(sizeof(ResidentCredential));
    w.u16(sizeof(TotpAccount));
    w.u16(sizeof(unlock::PcEntry));
    w.put(settings::masterKey(), 32);
    w.u32(settings::signCount());

    // Passkeys oldest first, so a restore keeps the same "newest = default" order.
    int slots[FIDO_MAX_RESIDENT], created[FIDO_MAX_RESIDENT], n = 0;
    ResidentCredential c;
    for (int i = 0; i < creds::residentCapacity(); i++) {
        if (!creds::residentGet(i, &c)) continue;
        int j = n++;
        for (; j > 0 && created[j - 1] > (int)c.created; j--) {
            slots[j] = slots[j - 1];
            created[j] = created[j - 1];
        }
        slots[j] = i;
        created[j] = (int)c.created;
    }
    w.u8((uint8_t)n);
    for (int i = 0; i < n; i++) {
        creds::residentGet(slots[i], &c);
        w.put(&c, sizeof(c));
    }
    crypto::wipe(&c, sizeof(c));

    TotpAccount a;
    w.u8((uint8_t)totp::count());
    for (int i = 0; i < totp::count(); i++) {
        if (!totp::get(i, &a)) memset(&a, 0, sizeof(a));
        w.put(&a, sizeof(a));
    }
    crypto::wipe(&a, sizeof(a));

    unlock::PcEntry pc;
    w.u8((uint8_t)unlock::count());
    for (int i = 0; i < UNLOCK_MAX_PCS; i++) {
        if (unlock::getEntry(i, &pc)) w.put(&pc, sizeof(pc));
    }
    crypto::wipe(&pc, sizeof(pc));
    return w.ok ? w.n : 0;
}

static void onExport(bool approved, void*) {
    if (!approved) {
        wipeKey();
        consoleWrite("ERR denied on the device\n");
        return;
    }
    uint8_t* plain = (uint8_t*)malloc(MAX_PLAIN);
    uint8_t* sealed = (uint8_t*)malloc(MAX_PLAIN + 16);
    size_t n = plain && sealed ? buildPlain(plain, MAX_PLAIN) : 0;
    bool ok = n > 0;
    if (ok) {
        crypto::random(s_nonce, sizeof(s_nonce));
        ok = crypto::aesGcmSeal(s_key, s_nonce, (const uint8_t*)AAD, sizeof(AAD) - 1, plain, n, sealed);
    }
    if (plain) { crypto::wipe(plain, MAX_PLAIN); free(plain); }
    wipeKey();
    if (!ok) {
        if (sealed) free(sealed);
        consoleWrite("ERR backup failed (out of memory?)\n");
        return;
    }
    // Whole lines through consoleWrite: consolef's buffer is shorter than a data line.
    static const char PREFIX[] = "BACKUP data ";
    char line[sizeof(PREFIX) + 2 * LINE_BYTES + 2];
    char hex[2 * LINE_BYTES + 1];
    hexEncode(s_nonce, sizeof(s_nonce), hex);
    consolef("BACKUP nonce %s\n", hex);
    size_t total = n + 16;
    for (size_t off = 0; off < total; off += LINE_BYTES) {
        size_t len = total - off < LINE_BYTES ? total - off : LINE_BYTES;
        hexEncode(sealed + off, len, hex);
        snprintf(line, sizeof(line), "%s%s\n", PREFIX, hex);
        consoleWrite(line);
    }
    free(sealed);
    consolef("OK backup %u bytes\n", (unsigned)total);
    logEvent("Backup exported");
}

void exportStart(const uint8_t key[32]) {
    memcpy(s_key, key, 32);
    char detail[40];
    summary(creds::residentCount(), totp::count(), unlock::count(), detail, sizeof(detail));
    if (!approval::ask("EXPORT BACKUP?", detail, "to the USB console", true, onExport, nullptr)) {
        wipeKey();
        consoleWrite("ERR device busy\n");
        return;
    }
    consoleWrite("WAIT confirm on the device\n");
}

// --- Restore -----------------------------------------------------------------

void restoreBegin(const uint8_t key[32], const uint8_t nonce[12], size_t len) {
    freeBuf();
    if (len < 16 + 12 || len > MAX_PLAIN + 16) { consoleWrite("ERR bad size\n"); return; }
    s_buf = (uint8_t*)malloc(len);
    if (!s_buf) { consoleWrite("ERR out of memory\n"); return; }
    memcpy(s_key, key, 32);
    memcpy(s_nonce, nonce, 12);
    s_len = len;
    consoleWrite("OK\n");
}

void restoreData(const char* hex) {
    if (!s_buf) { consoleWrite("ERR no restore in progress\n"); return; }
    int n = hexDecode(hex, strlen(hex), s_buf + s_have, s_len - s_have);
    if (n < 0) { freeBuf(); wipeKey(); consoleWrite("ERR bad data\n"); return; }
    s_have += n;
    consoleWrite("OK\n");
}

// Parses a decrypted backup. With `apply` false it only validates and counts.
static bool parse(const uint8_t* p, size_t n, bool apply, int* passkeys, int* totps, int* pcs) {
    Reader r{p, n};
    const uint8_t* magic = r.take(4);
    if (!magic || memcmp(magic, MAGIC, 4) || r.u16() != VERSION) return false;
    if (r.u16() != sizeof(ResidentCredential) || r.u16() != sizeof(TotpAccount) ||
        r.u16() != sizeof(unlock::PcEntry)) return false;
    const uint8_t* master = r.take(32);
    uint32_t counter = r.u32();

    int nc = r.u8();
    const uint8_t* credRecs = r.take(nc * sizeof(ResidentCredential));
    int nt = r.u8();
    const uint8_t* totpRecs = r.take(nt * sizeof(TotpAccount));
    int np = r.u8();
    const uint8_t* pcRecs = r.take(np * sizeof(unlock::PcEntry));
    if (!r.ok || r.pos != n || nc > FIDO_MAX_RESIDENT || nt > TOTP_MAX_ACCOUNTS || np > UNLOCK_MAX_PCS)
        return false;
    *passkeys = nc; *totps = nt; *pcs = np;
    if (!apply) return true;

    settings::restoreFido(master, counter);
    creds::residentWipe();
    for (int i = 0; i < nc; i++) {
        ResidentCredential c;
        memcpy(&c, credRecs + i * sizeof(c), sizeof(c));
        creds::residentPut(c);
        crypto::wipe(&c, sizeof(c));
    }
    totp::clear();
    for (int i = 0; i < nt; i++) {
        TotpAccount a;
        memcpy(&a, totpRecs + i * sizeof(a), sizeof(a));
        totp::add(a);
        crypto::wipe(&a, sizeof(a));
    }
    unlock::PcEntry pcList[UNLOCK_MAX_PCS];
    memcpy(pcList, pcRecs, np * sizeof(unlock::PcEntry));
    unlock::replaceAll(pcList, np);
    crypto::wipe(pcList, sizeof(pcList));
    return true;
}

static void onRestore(bool approved, void*) {
    if (!approved) {
        freeBuf();
        consoleWrite("ERR denied on the device\n");
        return;
    }
    int nc, nt, np;
    bool ok = parse(s_buf, s_len - 16, true, &nc, &nt, &np);
    freeBuf();
    if (!ok) { consoleWrite("ERR restore failed\n"); return; }
    logEvent("Backup restored");
    logFlush();
    consolef("OK restored %d passkeys, %d TOTP, %d PCs; rebooting\n", nc, nt, np);
    delay(300);
    ESP.restart();   // reload every module from the new storage
}

void restoreEnd() {
    if (!s_buf || s_have != s_len) { freeBuf(); wipeKey(); consoleWrite("ERR incomplete data\n"); return; }
    uint8_t* plain = (uint8_t*)malloc(s_len);
    bool ok = plain && crypto::aesGcmOpen(s_key, s_nonce, (const uint8_t*)AAD, sizeof(AAD) - 1, s_buf, s_len, plain);
    wipeKey();
    free(s_buf);                 // ciphertext only; keep the plaintext in s_buf
    s_buf = plain;
    int nc = 0, nt = 0, np = 0;
    if (!ok) { freeBuf(); consoleWrite("ERR wrong passphrase or damaged backup\n"); return; }
    if (!parse(s_buf, s_len - 16, false, &nc, &nt, &np)) {
        freeBuf();
        consoleWrite("ERR backup is from an incompatible firmware\n");
        return;
    }
    char detail[40];
    summary(nc, nt, np, detail, sizeof(detail));
    if (!approval::ask("RESTORE BACKUP?", detail, "REPLACES everything", true, onRestore, nullptr)) {
        freeBuf();
        consoleWrite("ERR device busy\n");
        return;
    }
    consoleWrite("WAIT confirm on the device\n");
}

}  // namespace backup

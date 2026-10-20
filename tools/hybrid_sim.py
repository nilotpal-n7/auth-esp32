#!/usr/bin/env python3
"""Hybrid (caBLE v2) end-to-end test: this script plays the *desktop browser*.

1. Builds a FIDO:/ QR payload exactly like Chromium (v2_handshake.cc).
2. Hands it to the device over USB serial (`hybrid FIDO:/...`), standing in
   for the phone app that would normally scan the QR.
3. Scans Bluetooth for the device's encrypted EID advert (UUID 0xFFF9) and
   decrypts it to learn the tunnel routing ID.
4. Connects to Google's tunnel server, runs the Noise KNpsk0 handshake as
   initiator, reads the post-handshake getInfo, and performs a WebAuthn
   registration + sign-in through the encrypted tunnel, verified by
   python-fido2's relying-party server.

Requires the *test* firmware build (prompts are approved over serial) and a
PC with Bluetooth LE.

    .venv/Scripts/python tools/hybrid_sim.py [--port COMx] [--no-ble]
"""
from __future__ import annotations

import argparse
import asyncio
import hashlib
import hmac
import os
import struct
import sys
import threading
import time

import cbor2
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
import websockets

sys.path.insert(0, os.path.dirname(__file__))
from authkey import AuthKeySerial  # noqa: E402

TUNNEL = "cable.ua5v.com"
K_EID_KEY, K_TUNNEL_ID, K_PSK = 1, 2, 3


def hkdf(ikm: bytes, salt: bytes | None, info: bytes, n: int) -> bytes:
    return HKDF(hashes.SHA256(), n, salt or None, info).derive(ikm)


def derive(secret: bytes, salt: bytes, typ: int, n: int) -> bytes:
    return hkdf(secret, salt, struct.pack("<I", typ), n)


def bytes_to_digits(data: bytes) -> str:
    widths = [0, 3, 5, 8, 10, 13, 15, 17]
    out = ""
    for i in range(0, len(data), 7):
        chunk = data[i:i + 7]
        v = int.from_bytes(chunk + bytes(8 - len(chunk)), "little")
        out += str(v).zfill(widths[len(chunk)])
    return out


def pub_bytes(key, compressed=False) -> bytes:
    fmt = serialization.PublicFormat.CompressedPoint if compressed else serialization.PublicFormat.UncompressedPoint
    return key.public_key().public_bytes(serialization.Encoding.X962, fmt)


def ecdh(priv, peer_bytes: bytes) -> bytes:
    peer = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), peer_bytes)
    return priv.exchange(ec.ECDH(), peer)


class Noise:
    def __init__(self, name: bytes):
        self.ck = name.ljust(32, b"\0")
        self.h = self.ck
        self.k = None
        self.n = 0

    def mix_hash(self, d: bytes):
        self.h = hashlib.sha256(self.h + d).digest()

    def mix_key(self, ikm: bytes):
        out = hkdf(ikm, self.ck, b"", 64)
        self.ck, self.k, self.n = out[:32], out[32:], 0

    def mix_key_and_hash(self, ikm: bytes):
        out = hkdf(ikm, self.ck, b"", 96)
        self.ck = out[:32]
        self.mix_hash(out[32:64])
        self.k, self.n = out[64:], 0

    def _nonce(self):
        nonce = struct.pack(">I", self.n) + bytes(8)
        self.n += 1
        return nonce

    def encrypt_and_hash(self, pt: bytes) -> bytes:
        ct = AESGCM(self.k).encrypt(self._nonce(), pt, self.h)
        self.mix_hash(ct)
        return ct

    def decrypt_and_hash(self, ct: bytes) -> bytes:
        pt = AESGCM(self.k).decrypt(self._nonce(), ct, self.h)
        self.mix_hash(ct)
        return pt


class Crypter:
    def __init__(self, read_key, write_key):
        self.rk, self.wk, self.rs, self.ws = read_key, write_key, 0, 0

    @staticmethod
    def _nonce(seq):
        return bytes(8) + struct.pack(">I", seq)

    def encrypt(self, msg: bytes) -> bytes:
        padded_len = (len(msg) + 1 + 31) & ~31
        padded = msg + bytes(padded_len - len(msg) - 1) + bytes([padded_len - len(msg) - 1])
        ct = AESGCM(self.wk).encrypt(self._nonce(self.ws), padded, None)
        self.ws += 1
        return ct

    def decrypt(self, ct: bytes) -> bytes:
        pt = AESGCM(self.rk).decrypt(self._nonce(self.rs), ct, None)
        self.rs += 1
        return pt[:len(pt) - pt[-1] - 1]


def decrypt_eid(advert: bytes, eid_key: bytes) -> bytes | None:
    if len(advert) != 20:
        return None
    tag = hmac.new(eid_key[32:], advert[:16], hashlib.sha256).digest()[:4]
    if not hmac.compare_digest(tag, advert[16:]):
        return None
    dec = Cipher(algorithms.AES(eid_key[:32]), modes.ECB()).decryptor()
    pt = dec.update(advert[:16]) + dec.finalize()
    return pt if pt[0] == 0 else None


async def scan_for_eid(eid_key: bytes, timeout: float) -> bytes:
    from bleak import BleakScanner
    found: asyncio.Future = asyncio.get_running_loop().create_future()
    uuid = "0000fff9-0000-1000-8000-00805f9b34fb"

    def on_adv(device, adv):
        data = adv.service_data.get(uuid)
        if data and not found.done():
            pt = decrypt_eid(bytes(data), eid_key)
            if pt:
                print(f"  BLE advert from {device.address} (RSSI {adv.rssi}) decrypted OK")
                found.set_result(pt)

    async with BleakScanner(on_adv):
        return await asyncio.wait_for(found, timeout)


def run_device_approver(dev: AuthKeySerial, stop: threading.Event):
    """Approve prompts as they appear (stands in for pressing OK)."""
    while not stop.is_set():
        line = dev.readline(0.2)
        if line and "[CTAP] cmd 0x01" in line or line and "[CTAP] cmd 0x02" in line:
            time.sleep(0.5)
            dev.send("approve")
        if line and ("[HYBRID]" in line or "[WS]" in line):
            print("   device:", line)


async def main_async(args):
    from fido2.server import Fido2Server
    from fido2.webauthn import (AttestationObject, AuthenticatorData, CollectedClientData,
                                PublicKeyCredentialRpEntity, PublicKeyCredentialUserEntity)

    identity = ec.generate_private_key(ec.SECP256R1())
    secret = os.urandom(16)
    qr = cbor2.dumps({0: pub_bytes(identity, True), 1: secret, 2: 2, 3: int(time.time()), 4: False, 5: "mc"},
                     canonical=True)
    qr_text = "FIDO:/" + bytes_to_digits(qr)
    print(f"QR: {qr_text[:40]}... ({len(qr_text)} chars)")

    dev = AuthKeySerial(args.port)
    dev.wait_ready()
    resp = dev.command(f"hybrid {qr_text}")
    assert resp and resp[-1].startswith("OK"), resp
    stop = threading.Event()
    threading.Thread(target=run_device_approver, args=(dev, stop), daemon=True).start()

    eid_key = derive(secret, b"", K_EID_KEY, 64)
    tunnel_id = derive(secret, b"", K_TUNNEL_ID, 16)
    if args.no_ble:
        raise SystemExit("--no-ble is not supported: the routing ID is only available in the BLE advert")
    print("Scanning Bluetooth for the device's caBLE advert...")
    eid = await scan_for_eid(eid_key, 45)
    routing_id, domain = eid[11:14], struct.unpack("<H", eid[14:16])[0]
    assert domain == 0, domain
    psk = derive(secret, eid, K_PSK, 32)

    url = f"wss://{TUNNEL}/cable/connect/{routing_id.hex().upper()}/{tunnel_id.hex().upper()}"
    print("Connecting", url)
    async with websockets.connect(url, subprotocols=["fido.cable"], open_timeout=20) as ws:
        # Initiator (desktop) side of Noise KNpsk0.
        noise = Noise(b"Noise_KNpsk0_P256_AESGCM_SHA256")
        noise.mix_hash(b"\x01")
        noise.mix_hash(pub_bytes(identity))
        noise.mix_key_and_hash(psk)
        eph = ec.generate_private_key(ec.SECP256R1())
        noise.mix_hash(pub_bytes(eph))
        noise.mix_key(pub_bytes(eph))
        await ws.send(pub_bytes(eph) + noise.encrypt_and_hash(b""))

        resp = await asyncio.wait_for(ws.recv(), 30)
        assert len(resp) == 81, len(resp)
        peer = resp[:65]
        noise.mix_hash(peer)
        noise.mix_key(peer)
        noise.mix_key(ecdh(eph, peer))
        noise.mix_key(ecdh(identity, peer))
        assert noise.decrypt_and_hash(resp[65:]) == b""
        keys = hkdf(b"", noise.ck, b"", 64)
        crypter = Crypter(read_key=keys[32:], write_key=keys[:32])
        print("Noise handshake OK")

        post = crypter.decrypt(await asyncio.wait_for(ws.recv(), 10))
        msg = cbor2.loads(post)
        info = cbor2.loads(msg[1])
        assert "ctap" in msg.get(3, ["ctap"]), msg
        print("Post-handshake getInfo:", {k: v for k, v in info.items() if k in (1, 4, 9)})

        async def ctap(payload: bytes) -> bytes:
            await ws.send(crypter.encrypt(b"\x01" + payload))
            rsp = crypter.decrypt(await asyncio.wait_for(ws.recv(), 40))
            assert rsp[0] == 1, rsp[:4]
            return rsp[1:]

        rp = PublicKeyCredentialRpEntity(id="example.com", name="Example")
        server = Fido2Server(rp, attestation="direct")
        user = PublicKeyCredentialUserEntity(id=os.urandom(16), name="hybrid", display_name="Hybrid")
        options, state = server.register_begin(user)
        cd = CollectedClientData.create(type="webauthn.create", origin="https://example.com",
                                        challenge=options.public_key.challenge)
        req = b"\x01" + cbor2.dumps({1: cd.hash, 2: {"id": "example.com", "name": "Example"},
                                     3: {"id": user.id, "name": user.name}, 4: [{"alg": -7, "type": "public-key"}]},
                                    canonical=True)
        rsp = await ctap(req)
        assert rsp[0] == 0, f"makeCredential status {rsp[0]:#x}"
        att = cbor2.loads(rsp[1:])
        att_obj = AttestationObject.create(att[1], AuthenticatorData(att[2]), att[3])
        from fido2.webauthn import AuthenticatorAttestationResponse, RegistrationResponse
        reg = RegistrationResponse(raw_id=att_obj.auth_data.credential_data.credential_id,
                                   response=AuthenticatorAttestationResponse(client_data=cd,
                                                                             attestation_object=att_obj))
        auth_data = server.register_complete(state, reg)
        cred = auth_data.credential_data
        print("Registration over hybrid verified by RP server")

        options, state = server.authenticate_begin([cred])
        cd = CollectedClientData.create(type="webauthn.get", origin="https://example.com",
                                        challenge=options.public_key.challenge)
        req = b"\x02" + cbor2.dumps({1: "example.com", 2: cd.hash,
                                     3: [{"type": "public-key", "id": cred.credential_id}]}, canonical=True)
        rsp = await ctap(req)
        assert rsp[0] == 0, f"getAssertion status {rsp[0]:#x}"
        a = cbor2.loads(rsp[1:])
        from fido2.webauthn import AuthenticationResponse, AuthenticatorAssertionResponse
        server.authenticate_complete(state, [cred], AuthenticationResponse(
            raw_id=cred.credential_id,
            response=AuthenticatorAssertionResponse(client_data=cd, authenticator_data=AuthenticatorData(a[2]),
                                                    signature=a[3])))
        print("Sign-in over hybrid verified by RP server")
        await ws.send(crypter.encrypt(b"\x00"))   # shutdown
    stop.set()
    time.sleep(0.5)
    print("\nHYBRID END-TO-END: PASS")


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--port")
    ap.add_argument("--no-ble", action="store_true")
    asyncio.run(main_async(ap.parse_args()))


if __name__ == "__main__":
    main()

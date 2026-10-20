#!/usr/bin/env python3
"""End-to-end tests against a connected AuthKey-ESP32 running the *test* build.

    pio run -e test -t upload
    .venv/Scripts/python tools/test_device.py [--port COMx]

Uses python-fido2's WebAuthn client and relying-party server, so every
attestation and assertion the device produces is verified exactly as a real
website would verify it. Prompts are answered through the test-build console
hooks instead of the OK button.
"""
from __future__ import annotations

import argparse
import os
import sys
import time
import traceback

import pyotp
from fido2.client import ClientError, DefaultClientDataCollector, Fido2Client
from fido2.ctap import CtapError
from fido2.ctap2 import Ctap2
from fido2.server import Fido2Server
from fido2.webauthn import (
    AttestationObject,
    PublicKeyCredentialRpEntity,
    PublicKeyCredentialUserEntity,
    ResidentKeyRequirement,
    UserVerificationRequirement,
)

sys.path.insert(0, os.path.dirname(__file__))
from authkey import AuthKeySerial, SerialCtapDevice  # noqa: E402

RP = PublicKeyCredentialRpEntity(id="example.com", name="Example")
ORIGIN = "https://example.com"
RESULTS: list[tuple[str, bool, str]] = []


def test(fn):
    def run(ctx):
        name = fn.__name__
        try:
            fn(ctx)
            RESULTS.append((name, True, ""))
            print(f"PASS  {name}")
        except Exception as e:  # noqa: BLE001
            RESULTS.append((name, False, f"{type(e).__name__}: {e}"))
            print(f"FAIL  {name}: {type(e).__name__}: {e}")
            traceback.print_exc()
    run.__name__ = fn.__name__
    return run


class Ctx:
    def __init__(self, port):
        self.serial = AuthKeySerial(port)
        self.serial.wait_ready()
        self.serial.command("auto off")        # tests expect manual approval
        self.serial.command("clearpin")
        self.wipe_test_passkeys()
        self.device = SerialCtapDevice(self.serial, approve="auto")
        self.ctap = Ctap2(self.device)
        self.server = Fido2Server(RP, attestation="direct")
        self.client = Fido2Client(self.device, DefaultClientDataCollector(ORIGIN))

    def wipe_test_passkeys(self):
        """Remove discoverable credentials left by earlier runs (rp example.com)."""
        for line in self.serial.command("passkeys", until=None, timeout=1.5):
            parts = line.strip().split()
            if len(parts) >= 2 and parts[1] == "example.com":
                self.serial.command(f"passkey del {parts[0].rstrip(':')}")

    def user(self, name):
        return PublicKeyCredentialUserEntity(id=os.urandom(16), name=name, display_name=name.title())


def register(ctx, user, rk=ResidentKeyRequirement.DISCOURAGED, uv=UserVerificationRequirement.DISCOURAGED,
             exclude=None):
    options, state = ctx.server.register_begin(user, credentials=exclude, resident_key_requirement=rk,
                                               user_verification=uv)
    result = ctx.client.make_credential(options.public_key)
    auth_data = ctx.server.register_complete(state, result)
    return auth_data


def login(ctx, creds, uv=UserVerificationRequirement.DISCOURAGED, discoverable=False):
    options, state = ctx.server.authenticate_begin(None if discoverable else creds, user_verification=uv)
    selection = ctx.client.get_assertion(options.public_key)
    responses = [selection.get_response(i) for i in range(len(selection.get_assertions()))]
    known = {bytes(c.credential_id) for c in creds}
    for r in responses:
        if discoverable and bytes(r.raw_id) not in known:
            continue   # passkey left over from an earlier run
        ctx.server.authenticate_complete(state, creds, r)
    return selection, responses


# --- Tests -------------------------------------------------------------------

@test
def get_info(ctx):
    info = ctx.ctap.get_info()
    assert "FIDO_2_0" in info.versions, info.versions
    assert info.options.get("rk") is True
    assert info.options.get("up") is True
    assert info.options.get("plat") is False
    assert len(info.aaguid) == 16 and bytes(info.aaguid) != bytes(16)
    assert info.max_msg_size == 1024


@test
def totp_rfc6238_vectors(ctx):
    s = ctx.serial
    vectors = [  # RFC 6238 Appendix B
        ("SHA1", "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ",
         {59: "94287082", 1111111109: "07081804", 1234567890: "89005924", 2000000000: "69279037"}),
        ("SHA256", "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZA",
         {59: "46119246", 1111111111: "67062674", 2000000000: "90698825"}),
        ("SHA512", "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNA",
         {59: "90693936", 1111111111: "99943326", 2000000000: "38618901"}),
    ]
    for algo, secret, cases in vectors:
        out = s.command(f"totp uri otpauth://totp/RFC-{algo}?secret={secret}&digits=8&algorithm={algo}")
        assert out and out[-1].startswith("OK added #"), out
        idx = int(out[-1].split("#")[1])
        try:
            for t, want in cases.items():
                got = s.command(f"totp code {idx} {t}")[-1]
                assert got == f"CODE {want}", (algo, t, got, want)
        finally:
            s.command(f"totp del {idx}")


@test
def totp_matches_pyotp_now(ctx):
    s = ctx.serial
    secret = pyotp.random_base32()
    out = s.command(f'totp add "pyotp check" {secret}')
    idx = int(out[-1].split("#")[1])
    try:
        now = int(time.time())
        s.command(f"time set {now}")
        got = s.command(f"totp code {idx} {now}")[-1].split()[1]
        assert got == pyotp.TOTP(secret).at(now), (got, pyotp.TOTP(secret).at(now))
        # Device clock must be UTC: code at device "now" equals pyotp now.
        got_now = s.command(f"totp code {idx}")[-1].split()[1]
        assert got_now in {pyotp.TOTP(secret).at(now + d) for d in (0, 30, -30)}
    finally:
        s.command(f"totp del {idx}")


@test
def register_and_login(ctx):
    user = ctx.user("alice")
    auth_data = register(ctx, user)
    cred = auth_data.credential_data
    assert auth_data.is_user_present()
    assert len(cred.credential_id) == 33
    ctx.alice = cred
    selection, responses = login(ctx, [cred])
    assert len(responses) == 1
    assert responses[0].response.authenticator_data.is_user_present()


@test
def packed_self_attestation(ctx):
    options, state = ctx.server.register_begin(ctx.user("att"))
    result = ctx.client.make_credential(options.public_key)
    att = AttestationObject(result.response.attestation_object)
    assert att.fmt == "packed", att.fmt
    assert att.att_stmt["alg"] == -7 and "x5c" not in att.att_stmt
    ctx.server.register_complete(state, result)   # verifies the self-signature


@test
def sign_counter_increases(ctx):
    _, r1 = login(ctx, [ctx.alice])
    _, r2 = login(ctx, [ctx.alice])
    c1 = r1[0].response.authenticator_data.counter
    c2 = r2[0].response.authenticator_data.counter
    assert c2 > c1 > 0, (c1, c2)


@test
def foreign_credential_rejected(ctx):
    from fido2.webauthn import AttestedCredentialData
    fake = AttestedCredentialData.create(bytes(16), bytes([0xA1]) + os.urandom(32), ctx.alice.public_key)
    try:
        login(ctx, [fake])
    except ClientError as e:
        assert e.code == ClientError.ERR.DEVICE_INELIGIBLE or "NO_CREDENTIALS" in str(e), e
        return
    raise AssertionError("assertion with a forged credential ID succeeded")


@test
def credential_bound_to_rp(ctx):
    # Same credential ID presented for another RP must not work.
    cdh = os.urandom(32)
    try:
        ctx.ctap.get_assertion("evil.com", cdh,
                               allow_list=[{"type": "public-key", "id": ctx.alice.credential_id}])
    except CtapError as e:
        assert e.code == CtapError.ERR.NO_CREDENTIALS, e
        return
    raise AssertionError("credential worked for a different RP")


@test
def exclude_list(ctx):
    try:
        register(ctx, ctx.user("alice2"), exclude=[ctx.alice])
    except ClientError as e:
        assert e.code == ClientError.ERR.DEVICE_INELIGIBLE, e
        return
    raise AssertionError("registration was not excluded")


@test
def discoverable_credentials(ctx):
    ctx.serial.command("passkeys")
    u1, u2 = ctx.user("dave"), ctx.user("erin")
    c1 = register(ctx, u1, rk=ResidentKeyRequirement.REQUIRED).credential_data
    c2 = register(ctx, u2, rk=ResidentKeyRequirement.REQUIRED).credential_data
    selection, responses = login(ctx, [c1, c2], discoverable=True)
    handles = {bytes(r.response.user_handle) for r in responses}
    assert handles >= {bytes(u1.id), bytes(u2.id)}, handles
    # Re-registering the same user replaces the old discoverable credential.
    count = lambda: len([l for l in ctx.serial.command("passkeys", until=None, timeout=1.5) if "example.com" in l])
    before = count()
    register(ctx, u1, rk=ResidentKeyRequirement.REQUIRED)
    assert count() == before, "re-registration added a duplicate passkey"


@test
def silent_probe_has_no_up(ctx):
    resp = ctx.ctap.get_assertion("example.com", os.urandom(32),
                                  allow_list=[{"type": "public-key", "id": ctx.alice.credential_id}],
                                  options={"up": False})
    assert not resp.auth_data.is_user_present()


@test
def user_denies(ctx):
    ctx.device.approve = "deny"
    try:
        login(ctx, [ctx.alice])
    except ClientError as e:
        assert e.code in (ClientError.ERR.DEVICE_INELIGIBLE, ClientError.ERR.OTHER_ERROR,
                          ClientError.ERR.TIMEOUT, ClientError.ERR.BAD_REQUEST), e
        return
    finally:
        ctx.device.approve = "auto"
    raise AssertionError("denied request succeeded")


@test
def builtin_user_verification(ctx):
    # CTAP 2.0 built-in UV: the platform sends options.uv=true and the user
    # enters the PIN on the device (python-fido2's high-level client only
    # does UV through a PIN protocol, so use raw CTAP here, like Chrome).
    s = ctx.serial
    assert "uv" not in ctx.ctap.get_info().options      # not advertised without a PIN
    assert s.command("setpin 2468")[-1] == "OK"
    try:
        assert ctx.ctap.get_info().options.get("uv") is True
        ctx.device.pin = "2468"
        rp = {"id": "example.com", "name": "Example"}
        user = {"id": os.urandom(16), "name": "frank"}
        att = ctx.ctap.make_credential(os.urandom(32), rp, user, [{"type": "public-key", "alg": -7}],
                                       options={"uv": True})
        assert att.auth_data.is_user_verified() and att.auth_data.is_user_present()
        cred_id = att.auth_data.credential_data.credential_id
        allow = [{"type": "public-key", "id": cred_id}]
        a = ctx.ctap.get_assertion("example.com", os.urandom(32), allow, options={"uv": True})
        assert a.auth_data.is_user_verified()
        # Wrong PIN: rejected, then the user cancels.
        ctx.device.pin = None
        ctx.device.approve = ["uvpin 0000", "deny"]
        try:
            ctx.ctap.get_assertion("example.com", os.urandom(32), allow, options={"uv": True})
        except CtapError as e:
            assert e.code == CtapError.ERR.OPERATION_DENIED, e
        else:
            raise AssertionError("wrong PIN accepted")
    finally:
        ctx.device.pin = None
        ctx.device.approve = "auto"
        s.command("clearpin")


@test
def malformed_requests(ctx):
    for payload in [b"\x01", b"\x01\xa1", b"\x02\xff\xff", b"\x01" + os.urandom(64), b"\x02\xa2\x01\x60",
                    b"\x01\xbf", b"\x42", b"\x01\xa1\x01\x5a\xff\xff\xff\xff"]:
        rsp = ctx.device.call(SerialCtapDevice.CTAPHID_CBOR, payload)
        assert rsp and rsp[0] != 0, (payload.hex(), rsp.hex())
    ctx.ctap.get_info()   # still alive


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--port")
    args = ap.parse_args()
    ctx = Ctx(args.port)
    tests = [get_info, totp_rfc6238_vectors, totp_matches_pyotp_now, register_and_login,
             packed_self_attestation, sign_counter_increases, foreign_credential_rejected,
             credential_bound_to_rp, exclude_list, discoverable_credentials, silent_probe_has_no_up,
             user_denies, builtin_user_verification, malformed_requests]
    for t in tests:
        t(ctx)
    ctx.wipe_test_passkeys()
    passed = sum(ok for _, ok, _ in RESULTS)
    print(f"\n{passed}/{len(RESULTS)} passed")
    sys.exit(0 if passed == len(RESULTS) else 1)


if __name__ == "__main__":
    main()

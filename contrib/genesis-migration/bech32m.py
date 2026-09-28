# Copyright (c) 2017, 2021 Pieter Wuille
# Copyright (c) 2026 Soqucoin Labs Inc.
# Distributed under the MIT software license.
#
# BIP-173/BIP-350 reference implementation, trimmed to what the snapshot tool
# needs: decoding a bech32m witness-v1 address into its 32-byte program.
# Deliberately dependency-free; determinism beats convenience.

CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
BECH32M_CONST = 0x2BC830A3


def bech32_polymod(values):
    generator = [0x3B6A57B2, 0x26508E6D, 0x1EA119FA, 0x3D4233DD, 0x2A1462B3]
    chk = 1
    for value in values:
        top = chk >> 25
        chk = (chk & 0x1FFFFFF) << 5 ^ value
        for i in range(5):
            chk ^= generator[i] if ((top >> i) & 1) else 0
    return chk


def bech32_hrp_expand(hrp):
    return [ord(x) >> 5 for x in hrp] + [0] + [ord(x) & 31 for x in hrp]


def bech32m_verify_checksum(hrp, data):
    return bech32_polymod(bech32_hrp_expand(hrp) + data) == BECH32M_CONST


def bech32m_decode(bech):
    """Validate a bech32m string and return (hrp, data-without-checksum), or
    (None, None) on any defect. Mixed case is invalid per BIP-173."""
    if any(ord(x) < 33 or ord(x) > 126 for x in bech):
        return (None, None)
    if bech.lower() != bech and bech.upper() != bech:
        return (None, None)
    bech = bech.lower()
    pos = bech.rfind("1")
    if pos < 1 or pos + 7 > len(bech) or len(bech) > 90:
        return (None, None)
    if not all(x in CHARSET for x in bech[pos + 1:]):
        return (None, None)
    hrp = bech[:pos]
    data = [CHARSET.find(x) for x in bech[pos + 1:]]
    if not bech32m_verify_checksum(hrp, data):
        return (None, None)
    return (hrp, data[:-6])


def convertbits(data, frombits, tobits, pad=True):
    acc = 0
    bits = 0
    ret = []
    maxv = (1 << tobits) - 1
    max_acc = (1 << (frombits + tobits - 1)) - 1
    for value in data:
        if value < 0 or (value >> frombits):
            return None
        acc = ((acc << frombits) | value) & max_acc
        bits += frombits
        while bits >= tobits:
            bits -= tobits
            ret.append((acc >> bits) & maxv)
    if pad:
        if bits:
            ret.append((acc << (tobits - bits)) & maxv)
    elif bits >= frombits or ((acc << (tobits - bits)) & maxv):
        return None
    return ret


def bech32m_create_checksum(hrp, data):
    values = bech32_hrp_expand(hrp) + data
    polymod = bech32_polymod(values + [0, 0, 0, 0, 0, 0]) ^ BECH32M_CONST
    return [(polymod >> 5 * (5 - i)) & 31 for i in range(6)]


def encode_v1_address(hrp, program):
    """Encode a 32-byte witness-v1 program as a bech32m address. Used by the
    tests to build fixtures; decode_v1_address is the normative direction."""
    assert len(program) == 32
    data = [1] + convertbits(list(program), 8, 5)
    combined = data + bech32m_create_checksum(hrp, data)
    return hrp + "1" + "".join(CHARSET[d] for d in combined)


def decode_v1_address(hrp, addr):
    """Decode a witness-v1, 32-byte-program bech32m address for the given HRP.
    Returns the 32-byte program, or None if the address is anything else.
    Witness v0 (bech32 checksum) and other versions/lengths are rejected:
    migration allocations are v1 Dilithium outputs only."""
    hrpgot, data = bech32m_decode(addr)
    if hrpgot != hrp or not data:
        return None
    if data[0] != 1:
        return None
    decoded = convertbits(data[1:], 5, 8, False)
    if decoded is None or len(decoded) != 32:
        return None
    return bytes(decoded)

# Copyright (c) 2026 Soqucoin Labs Inc.
# Distributed under the MIT software license.
#
# The consensus-facing half of the snapshot tool: turning an ordered
# allocation list into the exact bytes ConnectBlock hashes, and the exact
# constants compiled into chainparams.
#
# Must stay byte-identical to the C++ side forever:
#   - CTxOut serialization: int64 LE value + var-length script
#     (primitives/transaction.h, standard Bitcoin encoding — the Phase 4
#     byte-less CTxOut, no extension bytes)
#   - vector serialization: CompactSize count + elements
#   - hashMigrationOutputs = SHA256d over that byte string
#     (validation.cpp, CHashWriter SER_GETHASH)
#   - display form: reversed-byte hex, the form uint256S() consumes, so
#     commitment.txt can be pasted into chainparams verbatim
# The arm phase of dryrun/regtest_dryrun.py checks this equivalence through a
# live node: the node logs the hash it computes from -migrationoutputs at
# startup (init.cpp), and the driver asserts it equals commitment.txt.

import hashlib
import struct

# The utxo-cost floor (consensus/consensus.h UTXO_COST_PER_BYTE), enforced
# per output where DEPLOYMENT_UTXO_COST is active. Allocations must clear it
# unconditionally: a sub-floor allocation compiled into the constants would
# make the migration height unmineable under an active UTXO_COST.
UTXO_COST_PER_BYTE = 6500

# MAX_MONEY (amount.h): 20B SOQ, a per-transaction ceiling. The coinbase that
# carries the allocations is one transaction.
MAX_MONEY = 20_000_000_000 * 100_000_000

# MAX_BLOCK_BASE_SIZE (consensus/consensus.h): the serialized size of a block
# without witness data, enforced by CheckBlock ("bad-blk-length"). The
# committed outputs are non-witness bytes of the block 1 coinbase, so their
# serialized vector must fit inside it with room for the rest of the block.
MAX_BLOCK_BASE_SIZE = 1_000_000

# Allocation cap (SPEC.md). A witness-v1 output serializes to 43
# bytes, so 20,000 outputs are 860,003 bytes with the CompactSize count. The
# cap keeps block 1 under MAX_BLOCK_BASE_SIZE with margin; the byte bound is
# the assertion behind it, so a future script shape cannot silently exceed the
# block limit. Block 1 of a fresh chain can carry no other transaction (no
# spendable coin exists yet), so the coinbase is the whole block.
MAX_ALLOCATION_OUTPUTS = 20_000
MAX_OUTPUTS_SERIALIZED_BYTES = 900_000


def compact_size(n):
    if n < 253:
        return struct.pack("B", n)
    if n <= 0xFFFF:
        return b"\xfd" + struct.pack("<H", n)
    if n <= 0xFFFFFFFF:
        return b"\xfe" + struct.pack("<I", n)
    return b"\xff" + struct.pack("<Q", n)


def v1_script(program):
    """OP_1 <32-byte program> — the witness-v1 scriptPubKey of an allocation."""
    assert len(program) == 32
    return b"\x51\x20" + program


def ser_txout(value_sats, script):
    return struct.pack("<q", value_sats) + compact_size(len(script)) + script


def ser_txout_vector(outputs):
    """outputs: list of (value_sats, script_bytes), already in committed
    order. Returns the exact bytes ConnectBlock hashes."""
    r = compact_size(len(outputs))
    for value_sats, script in outputs:
        r += ser_txout(value_sats, script)
    return r


def sha256d(data):
    return hashlib.sha256(hashlib.sha256(data).digest()).digest()


def hash_migration_outputs(outputs):
    """The consensus constant, in uint256S() display form (reversed-byte hex)."""
    return sha256d(ser_txout_vector(outputs))[::-1].hex()


def txout_serialized_size(script):
    return 8 + len(compact_size(len(script))) + len(script)


def utxo_cost_floor(script):
    return UTXO_COST_PER_BYTE * txout_serialized_size(script)


def is_block_commitment_shape(script):
    """True if this scriptPubKey parses as one of the coinbase block-commitment
    shapes ConnectBlock walks back over before hashing the committed range
    (validation.cpp, the migration block's isBlockCommitmentOutput lambda):

      SegWit witness commitment: >= 38 bytes, OP_RETURN 0x24 aa 21 a9 ed
      PAT attestation:           exactly 36 bytes, OP_RETURN 0x22 'P' 'A'
      LatticeFold accumulator:   exactly 36 bytes, OP_RETURN 0x22 'L' 'F'

    A committed vector must never END in one of these: the walk-back would
    strip it, shrink the range, and reject every miner's block at the
    migration height. Allocation outputs are OP_1 <32 bytes> so the shape cannot arise
    from a valid address, but the refusal is asserted rather than assumed."""
    if len(script) >= 38 and script[0] == 0x6A and script[1] == 0x24 \
            and script[2:6] == b"\xaa\x21\xa9\xed":
        return True
    if len(script) == 36 and script[0] == 0x6A and script[1] == 0x22 \
            and script[2:4] in (b"PA", b"LF"):
        return True
    return False

#!/usr/bin/env python3
# Copyright (c) 2026 Soqucoin Labs Inc.
# Distributed under the MIT software license.
#
# Unit tests + the determinism fixture for the genesis-migration snapshot
# tool. Run: python3 test_snapshot.py
#
# Regenerate the committed corpus fixture after a DELIBERATE behavior change:
#   python3 test_snapshot.py --regen
# then explain in the commit why the expected commitment moved, the same
# discipline as the consensus digest tests.

import contextlib
import hashlib
import io
import json
import os
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import unittest
import unittest.mock

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from bech32m import (BECH32M_CONST, CHARSET, bech32_hrp_expand, bech32_polymod,
                     bech32m_decode, convertbits, decode_v1_address, encode_v1_address)
from serialize import (MAX_ALLOCATION_OUTPUTS, MAX_BLOCK_BASE_SIZE, MAX_BLOCK_SUBSIDY,
                       MAX_MONEY, MAX_OUTPUTS_SERIALIZED_BYTES, compact_size,
                       hash_migration_outputs, is_block_commitment_shape, ser_txout_vector,
                       utxo_cost_floor, v1_script)
import compare_runs
import sdn_extract
import snapshot

# The module object is patched in tests; these names are the same objects.
WITHHELD = snapshot.WITHHELD
RpcClient = snapshot.RpcClient
apply_allocation_cap = snapshot.apply_allocation_cap
build_outputs = snapshot.build_outputs
build_screening_record = snapshot.build_screening_record
classify_tx = snapshot.classify_tx
load_address_file = snapshot.load_address_file
record_path_is_outside = snapshot.record_path_is_outside
run_snapshot = snapshot.run_snapshot

HERE = os.path.dirname(os.path.abspath(__file__))
FIXTURES = os.path.join(HERE, "fixtures")

MINT = "6NX2MWBuJM2Fn63K4hUgMPivLXHV8pwsU1yTdmjKpump"
TOKEN22 = "TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb"
SPL = "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA"
MEMO2 = "MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr"
MEMO1 = "Memo1UhkJRfHyvLMcVucJwxXeuD728EqVDDwQDxFMNo"

ADDR_A = encode_v1_address("sq", bytes([0xAA] * 32))
ADDR_B = encode_v1_address("sq", bytes([0x0B] * 32))
SDN_AUTHORITY = "SanctionedAuthority1111111111111111111111111"
PROJECT_AUTHORITY = "ProjectTreasury11111111111111111111111111111"


# ---------------------------------------------------------------------------
# Fake jsonParsed transaction builders
# ---------------------------------------------------------------------------

def burn_ins(base_units, authority="HolderAuthority", program=TOKEN22,
             mint=MINT, kind="burnChecked"):
    info = {"mint": mint, "authority": authority}
    if kind == "burnChecked":
        info["tokenAmount"] = {"amount": str(base_units), "decimals": 6}
    else:
        info["amount"] = str(base_units)
    return {"programId": program, "parsed": {"type": kind, "info": info}}


def memo_ins(payload):
    return {"programId": MEMO2, "parsed": payload}


def tx(instructions, inner=None, err=None):
    return {
        "transaction": {"message": {"instructions": instructions}},
        "meta": {"err": err,
                 "innerInstructions": ([{"index": 0, "instructions": inner}]
                                       if inner else [])},
    }


# ---------------------------------------------------------------------------
# bech32m
# ---------------------------------------------------------------------------

def encode_with_checksum(hrp, data, const):
    """A bech32-family string over 5-bit `data` with the checksum for `const`:
    BECH32M_CONST is bech32m (BIP-350), 1 is bech32 (BIP-173). Builds the
    well-formed strings the decoder must still reject: the wrong checksum
    constant, another witness version, another program length."""
    polymod = bech32_polymod(bech32_hrp_expand(hrp) + data + [0] * 6) ^ const
    checksum = [(polymod >> 5 * (5 - i)) & 31 for i in range(6)]
    return hrp + "1" + "".join(CHARSET[d] for d in data + checksum)


class Bech32mTests(unittest.TestCase):
    def test_roundtrip(self):
        for seed in (0x00, 0x5A, 0xFF):
            program = bytes([seed] * 32)
            addr = encode_v1_address("sq", program)
            self.assertEqual(decode_v1_address("sq", addr), program)

    def test_case_insensitive_but_not_mixed(self):
        self.assertIsNotNone(decode_v1_address("sq", ADDR_A.upper()))
        mixed = ADDR_A[:-4] + ADDR_A[-4:].upper()
        self.assertIsNone(decode_v1_address("sq", mixed))

    def test_rejects(self):
        # wrong HRP, corrupted checksum, truncation, v0, wrong length
        self.assertIsNone(decode_v1_address("ssq", ADDR_A))
        corrupted = ADDR_A[:-1] + ("q" if ADDR_A[-1] != "q" else "p")
        self.assertIsNone(decode_v1_address("sq", corrupted))
        self.assertIsNone(decode_v1_address("sq", ADDR_A[:-8]))
        self.assertIsNone(decode_v1_address("sq", ""))
        self.assertIsNone(decode_v1_address("sq", "sq1qqqqqq"))

    def test_bip350_vector(self):
        # BIP-350 test vector: valid bech32m, but HRP/segwit shape "bc"
        self.assertIsNone(
            decode_v1_address("sq",
                              "bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqzk5jj0"))

    def test_well_formed_strings_the_node_also_rejects(self):
        # Each string carries a valid checksum for its constant and differs
        # from a v1 32-byte bech32m address in exactly one respect. The
        # decoder returns None for each, and a memo naming it is
        # invalid-address.
        data32 = convertbits(list(bytes([0xAA] * 32)), 8, 5)
        self.assertEqual(encode_with_checksum("sq", [1] + data32, BECH32M_CONST), ADDR_A)
        cases = {
            "bech32 checksum on a v1 program":
                encode_with_checksum("sq", [1] + data32, 1),
            "witness version 0, bech32m checksum":
                encode_with_checksum("sq", [0] + data32, BECH32M_CONST),
            "witness version 0, bech32 checksum":
                encode_with_checksum("sq", [0] + data32, 1),
            "witness version 2":
                encode_with_checksum("sq", [2] + data32, BECH32M_CONST),
            "20-byte program":
                encode_with_checksum("sq", [1] + convertbits(list(bytes([0xAA] * 20)), 8, 5),
                                     BECH32M_CONST),
            "over 90 characters":
                encode_with_checksum("sq", [1] + convertbits(list(bytes([0xAA] * 60)), 8, 5),
                                     BECH32M_CONST),
        }
        for label, addr in cases.items():
            self.assertIsNone(decode_v1_address("sq", addr), label)
            self.assertEqual(classify_tx(tx([burn_ins(2_000_000), memo_ins("SOQMIG1:" + addr)]),
                                         MINT, set()),
                             ("excluded", "invalid-address"), label)
        # The version and length cases pass the checksum stage, so the
        # rejection is the version or the program length itself.
        self.assertEqual(bech32m_decode(cases["witness version 0, bech32m checksum"]),
                         ("sq", [0] + data32))
        self.assertEqual(bech32m_decode(cases["witness version 2"]), ("sq", [2] + data32))
        self.assertEqual(bech32m_decode(cases["20-byte program"])[0], "sq")
        # The bech32 checksum fails at the checksum stage.
        self.assertEqual(bech32m_decode(cases["bech32 checksum on a v1 program"]), (None, None))
        # A string over 90 characters is rejected before its checksum is read.
        self.assertGreater(len(cases["over 90 characters"]), 90)
        self.assertEqual(bech32m_decode(cases["over 90 characters"]), (None, None))


# ---------------------------------------------------------------------------
# serialization / consensus constants
# ---------------------------------------------------------------------------

class SerializeTests(unittest.TestCase):
    def test_compact_size(self):
        self.assertEqual(compact_size(0), b"\x00")
        self.assertEqual(compact_size(252), b"\xfc")
        self.assertEqual(compact_size(253), b"\xfd\xfd\x00")
        self.assertEqual(compact_size(0x10000), b"\xfe\x00\x00\x01\x00")

    def test_txout_vector_bytes(self):
        # One output, 1 SOQ to program 0xAA*32: layout must be exactly
        # count || int64le || pushlen || 0x51 0x20 || program.
        outputs = [(100_000_000, v1_script(bytes([0xAA] * 32)))]
        raw = ser_txout_vector(outputs)
        self.assertEqual(raw[:1], b"\x01")
        self.assertEqual(raw[1:9], (100_000_000).to_bytes(8, "little"))
        self.assertEqual(raw[9:12], b"\x22\x51\x20")
        self.assertEqual(raw[12:], bytes([0xAA] * 32))
        self.assertEqual(len(raw), 1 + 8 + 1 + 34)

    def test_hash_kat(self):
        # Frozen KAT: the same vector as the functional test
        # qa/rpc-tests/genesis-migration.py (10 SOQ -> 0xA1*32, 20 SOQ ->
        # 0xA2*32, 0.5 SOQ -> 0xA3*32). This test freezes the Python side
        # against drift; the check against a live node's own hash is the arm
        # phase of dryrun/regtest_dryrun.py.
        outputs = [
            (10 * 100_000_000, v1_script(bytes([0xA1] * 32))),
            (20 * 100_000_000, v1_script(bytes([0xA2] * 32))),
            (50_000_000, v1_script(bytes([0xA3] * 32))),
        ]
        self.assertEqual(
            hash_migration_outputs(outputs),
            "9cb91f97d65255991ba89329dbb5b77df8c18bf701d94402e4f2c445a4a1ddb5")

    def test_decimals_kats(self):
        # x100 KATs, integer math boundary vectors.
        cases = [
            (1_000_000, 100_000_000),            # 1 pSOQ -> 1 SOQ (dust floor)
            (1, 100),                            # smallest base unit
            (999_999_999_999, 99_999_999_999_900),
            (10 ** 15, 10 ** 17),                # 1B pSOQ, whale bound
        ]
        for base_units, sats in cases:
            self.assertEqual(base_units * snapshot.BASE_UNITS_TO_SATS, sats)
        self.assertEqual(MAX_MONEY, 20_000_000_000 * 100_000_000)

    def test_utxo_cost_floor(self):
        self.assertEqual(utxo_cost_floor(v1_script(bytes(32))), 6500 * 43)

    def test_block_commitment_shapes(self):
        # The three shapes ConnectBlock walks back over (validation.cpp).
        segwit = b"\x6a\x24\xaa\x21\xa9\xed" + bytes(32)
        pat = b"\x6a\x22PA" + bytes(32)
        lf = b"\x6a\x22LF" + bytes(32)
        for shape in (segwit, segwit + b"\x00", pat, lf):
            self.assertTrue(is_block_commitment_shape(shape), shape[:4])
        # Near misses and the real allocation shape.
        self.assertFalse(is_block_commitment_shape(v1_script(bytes(32))))
        self.assertFalse(is_block_commitment_shape(b"\x6a\x22PB" + bytes(32)))
        self.assertFalse(is_block_commitment_shape(b"\x6a\x22PA" + bytes(33)))
        self.assertFalse(is_block_commitment_shape(segwit[:37]))


# ---------------------------------------------------------------------------
# eligibility classification
# ---------------------------------------------------------------------------

class ClassifyTests(unittest.TestCase):
    def eligible(self, t):
        verdict = classify_tx(t, MINT, set(), {PROJECT_AUTHORITY})
        self.assertEqual(verdict[0], "eligible", verdict)
        return verdict

    def excluded(self, t, reason, sdn=(), project=(PROJECT_AUTHORITY,)):
        verdict = classify_tx(t, MINT, set(sdn), set(project))
        self.assertEqual(verdict, ("excluded", reason))

    def test_project_address_excluded_regardless_of_memo(self):
        # A project-address burn: a valid memo, no memo, a malformed memo, and a second
        # holder burn in the same tx all land on 'project-address'.
        good = memo_ins("SOQMIG1:" + ADDR_A)
        self.excluded(tx([burn_ins(50_000_000, authority=PROJECT_AUTHORITY), good]),
                      "project-address")
        self.excluded(tx([burn_ins(50_000_000, authority=PROJECT_AUTHORITY)]),
                      "project-address")
        self.excluded(tx([burn_ins(50_000_000, authority=PROJECT_AUTHORITY),
                          memo_ins("hello")]), "project-address")
        self.excluded(tx([burn_ins(2_000_000), good,
                          burn_ins(50_000_000, authority=PROJECT_AUTHORITY)]),
                      "project-address")
        # A project address that is also on the SDN file: project-address wins the label.
        self.excluded(tx([burn_ins(50_000_000, authority=PROJECT_AUTHORITY), good]),
                      "project-address", sdn=[PROJECT_AUTHORITY])
        # With an empty project set the same burn is an ordinary holder burn.
        verdict = classify_tx(tx([burn_ins(50_000_000, authority=PROJECT_AUTHORITY),
                                  good]), MINT, set(), set())
        self.assertEqual(verdict[0], "eligible")

    def test_eligible_and_sum(self):
        t = tx([burn_ins(2_000_000), burn_ins(500_000, program=SPL),
                memo_ins("SOQMIG1:" + ADDR_A)])
        _, address, sats, _ = self.eligible(t)
        self.assertEqual(address, ADDR_A.lower())
        self.assertEqual(sats, 2_500_000 * 100)

    def test_inner_memo_counts(self):
        t = tx([burn_ins(2_000_000), memo_ins("SOQMIG1:" + ADDR_A)],
               inner=[memo_ins("SOQMIG1:" + ADDR_B)])
        self.excluded(t, "multiple-memos")

    def test_exclusion_reasons(self):
        self.excluded(tx([burn_ins(2_000_000)]), "no-memo")
        self.excluded(tx([burn_ins(2_000_000), memo_ins("hello")]),
                      "malformed-memo")
        self.excluded(tx([burn_ins(2_000_000),
                          memo_ins("SOQMIG1:" + ADDR_A + " ")]),
                      "invalid-address")
        self.excluded(tx([burn_ins(2_000_000),
                          memo_ins("SOQMIG1:ssq1notanaddress")]),
                      "invalid-address")
        self.excluded(tx([burn_ins(999_999), memo_ins("SOQMIG1:" + ADDR_A)]),
                      "below-dust-floor")
        self.excluded(tx([burn_ins(2_000_000, kind="burn"),
                          memo_ins("SOQMIG1:" + ADDR_A)]),
                      "unchecked-burn")
        self.excluded(tx([burn_ins(2_000_000),
                          burn_ins(2_000_000, kind="burn"),
                          memo_ins("SOQMIG1:" + ADDR_A)]),
                      "unchecked-burn")
        self.excluded(tx([memo_ins("SOQMIG1:" + ADDR_A)]), "no-burn")
        self.excluded(tx([burn_ins(2_000_000), memo_ins("SOQMIG1:" + ADDR_A)],
                         err={"InstructionError": [0, "Custom"]}),
                      "tx-failed")

    def test_wrong_mint_or_decimals_is_no_burn(self):
        self.excluded(tx([burn_ins(2_000_000, mint="OtherMint"),
                          memo_ins("SOQMIG1:" + ADDR_A)]), "no-burn")
        bad = burn_ins(2_000_000)
        bad["parsed"]["info"]["tokenAmount"]["decimals"] = 9
        self.excluded(tx([bad, memo_ins("SOQMIG1:" + ADDR_A)]), "no-burn")

    def test_burn_checked_under_another_program_is_no_burn(self):
        # The same parsed shape from a program that is neither token program.
        other = burn_ins(2_000_000, program="NotATokenProgram111111111111111111111111111")
        self.assertIsNone(snapshot.parse_burn(other, MINT))
        self.excluded(tx([other, memo_ins("SOQMIG1:" + ADDR_A)]), "no-burn")

    def test_memo_v1_program_is_accepted(self):
        memo_v1 = {"programId": MEMO1, "parsed": "SOQMIG1:" + ADDR_A}
        self.assertEqual(snapshot.parse_memo(memo_v1), "SOQMIG1:" + ADDR_A)
        _, address, sats, _ = self.eligible(tx([burn_ins(2_000_000), memo_v1]))
        self.assertEqual((address, sats), (ADDR_A.lower(), 200_000_000))
        # One memo under each program is two memos.
        self.excluded(tx([burn_ins(2_000_000), memo_v1, memo_ins("SOQMIG1:" + ADDR_A)]),
                      "multiple-memos")

    def test_memo_shaped_data_from_another_program_is_not_a_memo(self):
        lookalike = {"programId": "NotTheMemoProgram11111111111111111111111111",
                     "parsed": "SOQMIG1:" + ADDR_B}
        self.assertIsNone(snapshot.parse_memo(lookalike))
        self.excluded(tx([burn_ins(2_000_000), lookalike]), "no-memo")
        # Beside a real memo it is not a second memo, and it names nothing.
        _, address, _, _ = self.eligible(tx([burn_ins(2_000_000), lookalike,
                                             memo_ins("SOQMIG1:" + ADDR_A)]))
        self.assertEqual(address, ADDR_A.lower())

    def test_memo_prefix_is_case_sensitive(self):
        self.excluded(tx([burn_ins(2_000_000), memo_ins("soqmig1:" + ADDR_A)]),
                      "malformed-memo")
        self.excluded(tx([burn_ins(2_000_000), memo_ins("SoqMig1:" + ADDR_A)]),
                      "malformed-memo")
        self.excluded(tx([burn_ins(2_000_000), memo_ins("SOQMIG1" + ADDR_A)]),
                      "malformed-memo")

    def test_dust_floor_boundary(self):
        self.assertEqual(snapshot.DUST_FLOOR_BASE_UNITS, 1_000_000)
        memo = memo_ins("SOQMIG1:" + ADDR_A)
        _, _, sats, _ = self.eligible(tx([burn_ins(1_000_000), memo]))
        self.assertEqual(sats, 100_000_000)
        self.excluded(tx([burn_ins(999_999), memo]), "below-dust-floor")
        # The floor applies to the transaction's sum of burns.
        _, _, sats, _ = self.eligible(tx([burn_ins(600_000), burn_ins(400_000), memo]))
        self.assertEqual(sats, 100_000_000)
        self.excluded(tx([burn_ins(600_000), burn_ins(399_999), memo]), "below-dust-floor")


# ---------------------------------------------------------------------------
# output construction guards
# ---------------------------------------------------------------------------

class BuildOutputsTests(unittest.TestCase):
    def test_lexicographic_order(self):
        allocations = {
            ADDR_A.lower(): {"sats": 500_000_000, "txids": ["t1"]},
            ADDR_B.lower(): {"sats": 300_000_000, "txids": ["t2"]},
        }
        outputs, total = build_outputs(allocations)
        self.assertEqual(total, 800_000_000)
        ordered = sorted([ADDR_A.lower(), ADDR_B.lower()])
        self.assertEqual(outputs[0][1],
                         v1_script(decode_v1_address("sq", ordered[0])))

    def test_floor_refusal(self):
        allocations = {ADDR_A.lower(): {"sats": 279_499, "txids": ["t1"]}}
        with self.assertRaises(SystemExit):
            build_outputs(allocations)

    def test_block_commitment_shape_refusal(self):
        # A valid address can never produce the shape; force the predicate to
        # prove the refusal path exists.
        allocations = {ADDR_A.lower(): {"sats": 500_000_000, "txids": ["t1"]}}
        original = snapshot.is_block_commitment_shape
        snapshot.is_block_commitment_shape = lambda script: True
        try:
            with self.assertRaises(SystemExit):
                build_outputs(allocations)
        finally:
            snapshot.is_block_commitment_shape = original

    def test_max_money_refusal(self):
        allocations = {ADDR_A.lower(): {"sats": MAX_MONEY + 1, "txids": ["t1"]}}
        with self.assertRaises(SystemExit):
            build_outputs(allocations)

    def test_aggregate_leaves_room_for_the_block_subsidy(self):
        # The coinbase that carries the allocations also pays the miner, and
        # CheckTransaction bounds the sum of its outputs by MAX_MONEY. A vector
        # inside MAX_MONEY but over MAX_MONEY less the subsidy is refused.
        bound = MAX_MONEY - MAX_BLOCK_SUBSIDY
        for total in (bound + 1, MAX_MONEY):
            allocations = {ADDR_A.lower(): {"sats": total - 100_000_000, "txids": ["t1"]},
                           ADDR_B.lower(): {"sats": 100_000_000, "txids": ["t2"]}}
            with self.assertRaises(SystemExit, msg=total) as refused:
                build_outputs(allocations)
            self.assertIn("block subsidy", str(refused.exception))
        allocations = {ADDR_A.lower(): {"sats": bound - 100_000_000, "txids": ["t1"]},
                       ADDR_B.lower(): {"sats": 100_000_000, "txids": ["t2"]}}
        self.assertEqual(build_outputs(allocations)[1], bound)

    def test_subsidy_reserve_is_the_largest_initial_subsidy_in_chainparams(self):
        # Read against the C++ side at run time: nInitialSubsidy of every
        # network, the first-epoch subsidy GetSoqucoinBlockSubsidy pays.
        path = os.path.join(HERE, "..", "..", "src", "chainparams.cpp")
        if not os.path.exists(path):
            self.skipTest("not inside a soqucoin checkout")
        with open(path) as f:
            values = [int(v) for v in
                      re.findall(r"consensus\.nInitialSubsidy = (\d+);", f.read())]
        self.assertEqual(len(values), 4)   # main, test, regtest, stagenet
        self.assertEqual(MAX_BLOCK_SUBSIDY, max(values) * 100_000_000)
        self.assertEqual(MAX_BLOCK_SUBSIDY, 500_000 * 100_000_000)


# ---------------------------------------------------------------------------
# destination-side exclusion and address case
# ---------------------------------------------------------------------------

class DestinationRulesTests(unittest.TestCase):
    def test_memo_naming_a_project_destination_is_not_credited(self):
        t = tx([burn_ins(5_000_000), memo_ins("SOQMIG1:" + ADDR_A)])
        self.assertEqual(classify_tx(t, MINT, set(), set(), {ADDR_A.lower()}),
                         ("excluded", "project-destination"))
        # The same burn to a non-project destination is eligible.
        self.assertEqual(classify_tx(t, MINT, set(), set(), {ADDR_B.lower()})[0],
                         "eligible")

    def test_project_destination_list_is_case_insensitive(self):
        t = tx([burn_ins(5_000_000), memo_ins("SOQMIG1:" + ADDR_A.upper())])
        self.assertEqual(classify_tx(t, MINT, set(), set(), {ADDR_A.lower()}),
                         ("excluded", "project-destination"))

    def test_all_uppercase_address_is_the_same_destination(self):
        lower = classify_tx(tx([burn_ins(5_000_000), memo_ins("SOQMIG1:" + ADDR_A)]),
                            MINT, set())
        upper = classify_tx(tx([burn_ins(5_000_000), memo_ins("SOQMIG1:" + ADDR_A.upper())]),
                            MINT, set())
        self.assertEqual(lower[0], "eligible")
        self.assertEqual(upper, lower)

    def test_mixed_case_address_is_invalid(self):
        mixed = ADDR_A[:6] + ADDR_A[6:].upper()
        self.assertNotEqual(mixed, mixed.lower())
        self.assertNotEqual(mixed, mixed.upper())
        self.assertEqual(classify_tx(tx([burn_ins(5_000_000), memo_ins("SOQMIG1:" + mixed)]),
                                     MINT, set()),
                         ("excluded", "invalid-address"))


# ---------------------------------------------------------------------------
# the persistent getTransaction cache: a second run over the same window
# fetches no transaction it has already seen, and produces the same result
# ---------------------------------------------------------------------------

class TransactionCacheTests(unittest.TestCase):
    def test_second_run_is_served_from_cache(self):
        import tempfile
        corpus = build_fixture_corpus()
        with tempfile.TemporaryDirectory() as d:
            cache_path = os.path.join(d, "txcache.json")
            first = RpcClient(None, corpus=corpus, cache_path=cache_path)
            a1, e1, w1 = run_snapshot(first, MINT, WINDOW_OPEN, FREEZE,
                                      {SDN_AUTHORITY}, {PROJECT_AUTHORITY})
            first.write_dump()
            self.assertTrue(os.path.exists(cache_path))
            # A corpus with every getTransaction response removed: only the
            # signature pages remain. Without the cache this run must fail.
            pages_only = {k: v for k, v in corpus.items() if isinstance(v, list)}
            with self.assertRaises(SystemExit):
                run_snapshot(RpcClient(None, corpus=pages_only), MINT, WINDOW_OPEN,
                             FREEZE, {SDN_AUTHORITY}, {PROJECT_AUTHORITY})
            second = RpcClient(None, corpus=pages_only, cache_path=cache_path)
            a2, e2, w2 = run_snapshot(second, MINT, WINDOW_OPEN, FREEZE,
                                      {SDN_AUTHORITY}, {PROJECT_AUTHORITY})
            self.assertEqual((a1, e1, w1), (a2, e2, w2))
            self.assertEqual(hash_migration_outputs(build_outputs(a1)[0]),
                             hash_migration_outputs(build_outputs(a2)[0]))

    def test_signature_pages_are_never_cached(self):
        import tempfile
        corpus = build_fixture_corpus()
        with tempfile.TemporaryDirectory() as d:
            cache_path = os.path.join(d, "txcache.json")
            rpc = RpcClient(None, corpus=corpus, cache_path=cache_path)
            run_snapshot(rpc, MINT, WINDOW_OPEN, FREEZE, {SDN_AUTHORITY}, {PROJECT_AUTHORITY})
            rpc.write_dump()
            with open(cache_path) as f:
                cached = json.load(f)
            self.assertTrue(cached)
            self.assertTrue(all(isinstance(v, dict) and "transaction" in v
                                for v in cached.values()))


# ---------------------------------------------------------------------------
# the allocation cap: block 1 has a fixed maximum size, so
# the committed vector has a fixed maximum length, and the rule that trims it
# is deterministic and published
# ---------------------------------------------------------------------------

def many_allocations(count, sats=100_000_000, prefix=b"flood"):
    """`count` distinct valid destinations, each with one minimum burn."""
    import hashlib
    allocations = {}
    for i in range(count):
        program = hashlib.sha256(prefix + i.to_bytes(4, "big")).digest()
        address = encode_v1_address("sq", program).lower()
        allocations[address] = {"sats": sats, "txids": ["flood-%d" % i]}
    return allocations


class AllocationCapTests(unittest.TestCase):
    def test_cap_is_twenty_thousand(self):
        # The figure SPEC.md states; the tool reads it through the same binding.
        self.assertEqual(MAX_ALLOCATION_OUTPUTS, 20_000)
        self.assertEqual(snapshot.MAX_ALLOCATION_OUTPUTS, 20_000)

    def test_constants_are_consistent_with_the_block_limit(self):
        # 43 bytes per witness-v1 output, plus the CompactSize count.
        vector_bytes = MAX_ALLOCATION_OUTPUTS * 43 + len(compact_size(MAX_ALLOCATION_OUTPUTS))
        self.assertLessEqual(vector_bytes, MAX_OUTPUTS_SERIALIZED_BYTES)
        self.assertLess(MAX_OUTPUTS_SERIALIZED_BYTES, MAX_BLOCK_BASE_SIZE)

    def test_flood_of_minimum_burns_is_bounded_not_a_veto(self):
        # THE ATTACK: one 1-pSOQ burn to each of 23,300 fresh addresses is a
        # vector no valid block 1 can carry. Without the cap the tool would
        # either commit it (block 1 invalid) or refuse (migration vetoed).
        flood = many_allocations(23_300)
        raw = [(e["sats"], v1_script(decode_v1_address("sq", a)))
               for a, e in sorted(flood.items())]
        self.assertGreater(len(ser_txout_vector(raw)), MAX_BLOCK_BASE_SIZE)
        with self.assertRaises(SystemExit):
            build_outputs(flood)          # the uncapped vector is refused
        committed, over_cap = apply_allocation_cap(flood)
        self.assertEqual(len(committed), MAX_ALLOCATION_OUTPUTS)
        self.assertEqual(len(over_cap), 23_300 - MAX_ALLOCATION_OUTPUTS)
        self.assertTrue(all(e["reason"] == "over-cap" for e in over_cap))
        outputs, total = build_outputs(committed)
        self.assertEqual(len(outputs), MAX_ALLOCATION_OUTPUTS)
        self.assertLessEqual(len(ser_txout_vector(outputs)), MAX_OUTPUTS_SERIALIZED_BYTES)
        self.assertEqual(total, MAX_ALLOCATION_OUTPUTS * 100_000_000)

    def test_cap_keeps_largest_and_breaks_ties_by_address(self):
        addr_c = encode_v1_address("sq", bytes([0xCC] * 32)).lower()
        allocations = {
            ADDR_A.lower(): {"sats": 300_000_000, "txids": ["tA1", "tA2"]},
            ADDR_B.lower(): {"sats": 300_000_000, "txids": ["tB"]},
            addr_c:         {"sats": 500_000_000, "txids": ["tC"]},
        }
        committed, over_cap = apply_allocation_cap(allocations, cap=2)
        # Largest first, then the tie at 3 SOQ goes to the lower address.
        lower, higher = sorted([ADDR_A.lower(), ADDR_B.lower()])
        self.assertEqual(set(committed), {addr_c, lower})
        self.assertEqual([e["txid"] for e in over_cap],
                         allocations[higher]["txids"])
        self.assertEqual(over_cap[0]["address"], higher)
        self.assertEqual(over_cap[0]["sats"], 300_000_000)
        self.assertEqual(over_cap[0]["reason"], "over-cap")

    def test_at_or_below_cap_changes_nothing(self):
        allocations = many_allocations(3)
        self.assertEqual(apply_allocation_cap(allocations, cap=3),
                         (allocations, []))
        self.assertEqual(apply_allocation_cap(allocations, cap=4),
                         (allocations, []))

    def test_cap_is_deterministic_across_input_order(self):
        allocations = many_allocations(50, sats=100_000_000)
        reversed_input = dict(reversed(list(allocations.items())))
        a, ea = apply_allocation_cap(allocations, cap=20)
        b, eb = apply_allocation_cap(reversed_input, cap=20)
        self.assertEqual(sorted(a), sorted(b))
        self.assertEqual(sorted(e["txid"] for e in ea), sorted(e["txid"] for e in eb))
        self.assertEqual(hash_migration_outputs(build_outputs(a)[0]),
                         hash_migration_outputs(build_outputs(b)[0]))

    def test_size_bound_refusal(self):
        allocations = many_allocations(2)
        original = snapshot.MAX_OUTPUTS_SERIALIZED_BYTES
        snapshot.MAX_OUTPUTS_SERIALIZED_BYTES = 50
        try:
            with self.assertRaises(SystemExit):
                build_outputs(allocations)
        finally:
            snapshot.MAX_OUTPUTS_SERIALIZED_BYTES = original


# ---------------------------------------------------------------------------
# the determinism fixture: a canned RPC corpus must reproduce a known
# commitment, byte for byte, forever
# ---------------------------------------------------------------------------

WINDOW_OPEN, FREEZE = 100, 200

def fixture_signature_page():
    entries = [
        ("sigM_project", 164),
        ("sigL_invalid_addr", 163), ("sigK_failed", 162),
        ("sigJ_unchecked", 161), ("sigB_addr_a_again", 160),
        ("sigI_sanctioned", 159), ("sigH_dust", 158),
        ("sigG_malformed", 157), ("sigF_nomemo", 156),
        ("sigE_twomemos", 155), ("sigA_addr_a", 150),
        ("sigC_addr_b", 149), ("sigD_before_window", 90),
    ]
    return [{"signature": s, "slot": slot, "err": None}
            for (s, slot) in entries]   # newest-first, ends below the window


def fixture_transactions():
    return {
        "sigA_addr_a": tx([burn_ins(5_000_000),
                           memo_ins("SOQMIG1:" + ADDR_A)]),
        "sigB_addr_a_again": tx([burn_ins(2_500_000, program=SPL),
                                 memo_ins("SOQMIG1:" + ADDR_A)]),
        "sigC_addr_b": tx([burn_ins(3_000_000)],
                          inner=[memo_ins("SOQMIG1:" + ADDR_B)]),
        "sigE_twomemos": tx([burn_ins(2_000_000),
                             memo_ins("SOQMIG1:" + ADDR_A),
                             memo_ins("SOQMIG1:" + ADDR_B)]),
        "sigF_nomemo": tx([burn_ins(2_000_000)]),
        "sigG_malformed": tx([burn_ins(2_000_000), memo_ins("SOQMIG2:x")]),
        "sigH_dust": tx([burn_ins(999_999), memo_ins("SOQMIG1:" + ADDR_A)]),
        "sigI_sanctioned": tx([burn_ins(9_000_000, authority=SDN_AUTHORITY),
                               memo_ins("SOQMIG1:" + ADDR_B)]),
        "sigJ_unchecked": tx([burn_ins(2_000_000, kind="burn"),
                              memo_ins("SOQMIG1:" + ADDR_A)]),
        "sigK_failed": tx([burn_ins(2_000_000),
                           memo_ins("SOQMIG1:" + ADDR_A)],
                          err={"InstructionError": [0, {}]}),
        "sigL_invalid_addr": tx([burn_ins(2_000_000),
                                 memo_ins("SOQMIG1:notbech32m")]),
        # The treasury burns 170M pSOQ WITH a valid memo during the
        # window. It must not allocate, and the expected hash must not move.
        "sigM_project": tx([burn_ins(170_001_000_000_000,
                                     authority=PROJECT_AUTHORITY),
                            memo_ins("SOQMIG1:" + ADDR_A)]),
    }


def build_fixture_corpus():
    corpus = {}
    key = RpcClient._key
    corpus[key("getSignaturesForAddress",
               [MINT, {"limit": 1000, "commitment": "finalized"}])] = \
        fixture_signature_page()
    for sig, transaction in fixture_transactions().items():
        corpus[key("getTransaction",
                   [sig, {"encoding": "jsonParsed",
                          "commitment": "finalized",
                          "maxSupportedTransactionVersion": 1}])] = transaction
    # The provider's finalized tip, past the freeze slot, for final runs.
    corpus[key("getSlot", [{"commitment": "finalized"}])] = FREEZE + 50
    return corpus


# The frozen expectations. sigA+sigB aggregate to ADDR_A (7.5 pSOQ = 750M
# sats), and sigC, a clean holder's 3 pSOQ, is credited to ADDR_B (300M sats).
# sigI is a burn by an SDN-listed authority naming ADDR_B, so it is withheld;
# it lands in a later slot than sigC's credited burn, so ADDR_B is not a
# tainted destination and keeps sigC. 9 exclusions (sigD is out of window and
# never fetched); the project burn sigM is in the corpus and contributes
# nothing.
EXPECTED_HASH = "051f96d449e64b54cccb50e178383a627ab123f324e489511467d9687d83d7d3"
EXPECTED_TOTAL = 1_050_000_000
EXPECTED_EXCLUSION_REASONS = ["multiple-memos", "no-memo", "malformed-memo",
                              "below-dust-floor", WITHHELD,
                              "unchecked-burn", "tx-failed",
                              "invalid-address", "project-address"]


class DeterminismFixtureTests(unittest.TestCase):
    def run_offline(self, corpus, sdn=(SDN_AUTHORITY,)):
        rpc = RpcClient(None, corpus=corpus)
        allocations, exclusions, withheld = run_snapshot(rpc, MINT, WINDOW_OPEN, FREEZE,
                                                         set(sdn), {PROJECT_AUTHORITY})
        outputs, total = build_outputs(allocations)
        return allocations, exclusions, withheld, outputs, total

    def test_corpus_reproduces_the_expected_commitment(self):
        # From the COMMITTED fixture file, not the in-memory builder: this is
        # what guarantees a recorded corpus stays replayable across
        # tool changes (a key-scheme change fails here loudly).
        path = os.path.join(FIXTURES, "rpc_corpus.json")
        with open(path) as f:
            corpus = json.load(f)
        allocations, exclusions, withheld, outputs, total = self.run_offline(corpus)
        self.assertEqual(hash_migration_outputs(outputs), EXPECTED_HASH)
        self.assertEqual(total, EXPECTED_TOTAL)
        self.assertEqual(sorted(e["reason"] for e in exclusions),
                         sorted(EXPECTED_EXCLUSION_REASONS))
        self.assertEqual(allocations[ADDR_A.lower()]["sats"], 750_000_000)
        self.assertEqual(allocations[ADDR_A.lower()]["txids"],
                         ["sigA_addr_a", "sigB_addr_a_again"])
        self.assertEqual(allocations[ADDR_B.lower()],
                         {"sats": 300_000_000, "txids": ["sigC_addr_b"]})
        self.assertEqual([w["txid"] for w in withheld], ["sigI_sanctioned"])
        self.assertEqual(withheld[0]["grounds"],
                         [{"ground": "sdn-authority", "authority": SDN_AUTHORITY}])

    def test_the_sdn_screen_alone_decides_sigI(self):
        # The same corpus with the SDN authority not listed: sigI is an
        # ordinary eligible burn and ADDR_B is credited sigC and sigI together.
        path = os.path.join(FIXTURES, "rpc_corpus.json")
        with open(path) as f:
            corpus = json.load(f)
        allocations, _, withheld, _, _ = self.run_offline(corpus, sdn=())
        self.assertEqual(allocations[ADDR_B.lower()]["sats"], 1_200_000_000)
        self.assertEqual(withheld, [])

    def test_committed_fixture_matches_builder(self):
        # The committed file must be exactly what the builder produces;
        # otherwise the fixture has drifted from the documented scenario.
        path = os.path.join(FIXTURES, "rpc_corpus.json")
        with open(path) as f:
            on_disk = json.load(f)
        self.assertEqual(on_disk, build_fixture_corpus())

    def test_determinism_two_runs_identical(self):
        corpus = build_fixture_corpus()
        first = self.run_offline(corpus)
        second = self.run_offline(corpus)
        self.assertEqual(first, second)


class CanonicalJsonTests(unittest.TestCase):
    def test_keys_are_sorted_at_every_level(self):
        # The published files and the screening record are hashed, so two
        # dicts built in different insertion orders must serialize to the
        # same bytes.
        first = snapshot.canonical_json({"b": 1, "a": {"d": 2, "c": 3}})
        second = snapshot.canonical_json({"a": {"c": 3, "d": 2}, "b": 1})
        self.assertEqual(first, second)
        self.assertEqual(first, '{\n "a": {\n  "c": 3,\n  "d": 2\n },\n "b": 1\n}\n')


class AddressFileTests(unittest.TestCase):
    def test_load(self):
        import tempfile
        with tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False) as f:
            f.write("# comment\n%s\n\nOther111 # trailing\n" % SDN_AUTHORITY)
            path = f.name
        try:
            addresses, sha = load_address_file(path)
            self.assertEqual(addresses, {SDN_AUTHORITY, "Other111"})
            self.assertEqual(len(sha), 64)
        finally:
            os.unlink(path)
        # A missing or empty path is never read as an empty list.
        for path in (None, ""):
            with self.assertRaises((TypeError, OSError), msg=repr(path)):
                load_address_file(path)

    def test_committed_project_file_loads(self):
        addresses, _ = load_address_file(os.path.join(HERE, "project-addresses.txt"))
        self.assertEqual(len(addresses), 8)
        self.assertIn("AAgEFLzJxbBq8tS1GFQ4omuhdzrFmxEX2QWemK23t98q", addresses)


# ---------------------------------------------------------------------------
# legal exclusions: every legal exclusion
# publishes the one code `withheld`, the grounds go to the unpublished
# screening record, and a destination named by a withheld transaction is
# withheld entirely
# ---------------------------------------------------------------------------

EXCL_AUTHORITY = "ListedAuthority11111111111111111111111111111"
TX_PARAMS = {"encoding": "jsonParsed", "commitment": "finalized",
             "maxSupportedTransactionVersion": 1}


def corpus_for(burns):
    """burns: list of (signature, slot, transaction). One signature page with
    a terminator below the window, like the committed fixture."""
    corpus = {}
    key = RpcClient._key
    page = [{"signature": s, "slot": slot, "err": None}
            for (s, slot, _) in sorted(burns, key=lambda b: -b[1])]
    page.append({"signature": "sig_terminator", "slot": WINDOW_OPEN - 10, "err": None})
    corpus[key("getSignaturesForAddress",
               [MINT, {"limit": 1000, "commitment": "finalized"}])] = page
    for s, _, transaction in burns:
        corpus[key("getTransaction", [s, TX_PARAMS])] = transaction
    return corpus


class LegalExclusionTests(unittest.TestCase):
    def classify(self, t, sdn=(), authorities=(), destinations=()):
        return classify_tx(t, MINT, set(sdn), {PROJECT_AUTHORITY}, set(),
                           set(authorities), {a.lower() for a in destinations})

    def test_sdn_authority_is_withheld_with_its_ground(self):
        t = tx([burn_ins(2_000_000, authority=SDN_AUTHORITY), memo_ins("SOQMIG1:" + ADDR_A)])
        self.assertEqual(self.classify(t, sdn=[SDN_AUTHORITY]),
                         (WITHHELD, ADDR_A.lower(),
                          [{"ground": "sdn-authority", "authority": SDN_AUTHORITY}]))
        self.assertEqual(self.classify(t)[0], "eligible")

    def test_excluded_authorities_list(self):
        t = tx([burn_ins(2_000_000, authority=EXCL_AUTHORITY), memo_ins("SOQMIG1:" + ADDR_A)])
        self.assertEqual(self.classify(t, authorities=[EXCL_AUTHORITY]),
                         (WITHHELD, ADDR_A.lower(),
                          [{"ground": "excluded-authority", "authority": EXCL_AUTHORITY}]))

    def test_excluded_destinations_list_is_case_insensitive(self):
        t = tx([burn_ins(2_000_000), memo_ins("SOQMIG1:" + ADDR_A.upper())])
        self.assertEqual(self.classify(t, destinations=[ADDR_A]),
                         (WITHHELD, ADDR_A.lower(),
                          [{"ground": "excluded-destination",
                            "destination": ADDR_A.lower()}]))

    def test_every_ground_that_applies_is_recorded(self):
        t = tx([burn_ins(2_000_000, authority=SDN_AUTHORITY), memo_ins("SOQMIG1:" + ADDR_A)])
        _, _, grounds = self.classify(t, sdn=[SDN_AUTHORITY], authorities=[SDN_AUTHORITY],
                                      destinations=[ADDR_A])
        self.assertEqual([g["ground"] for g in grounds],
                         ["sdn-authority", "excluded-authority", "excluded-destination"])

    def test_screen_checks_every_burn_authority(self):
        # The listed authority is neither the first nor the last of the
        # transaction's authorities in sorted order, so a screen that stops
        # early misses it.
        for listed, ground, lists in (
                (SDN_AUTHORITY, "sdn-authority", {"sdn": [SDN_AUTHORITY]}),
                (EXCL_AUTHORITY, "excluded-authority", {"authorities": [EXCL_AUTHORITY]})):
            t = tx([burn_ins(2_000_000, authority="AaaCleanHolder"),
                    burn_ins(2_000_000, authority=listed),
                    burn_ins(2_000_000, authority="ZzzCleanHolder"),
                    memo_ins("SOQMIG1:" + ADDR_A)])
            self.assertEqual(sorted(["AaaCleanHolder", listed, "ZzzCleanHolder"])[1], listed)
            self.assertEqual(self.classify(t, **lists),
                             (WITHHELD, ADDR_A.lower(), [{"ground": ground, "authority": listed}]))
            self.assertEqual(self.classify(t)[0], "eligible")

    def test_multisig_authority_is_the_burn_authority(self):
        # A burn signed by a multisig carries multisigAuthority and signers in
        # place of authority; the multisig address is what the lists name.
        ins = burn_ins(2_000_000)
        del ins["parsed"]["info"]["authority"]
        ins["parsed"]["info"]["multisigAuthority"] = SDN_AUTHORITY
        ins["parsed"]["info"]["signers"] = ["Signer1111111111111111111111111111111111111",
                                            "Signer2222222222222222222222222222222222222"]
        self.assertEqual(snapshot.parse_burn(ins, MINT), (2_000_000, SDN_AUTHORITY))
        t = tx([ins, memo_ins("SOQMIG1:" + ADDR_A)])
        self.assertEqual(self.classify(t, sdn=[SDN_AUTHORITY]),
                         (WITHHELD, ADDR_A.lower(),
                          [{"ground": "sdn-authority", "authority": SDN_AUTHORITY}]))
        self.assertEqual(self.classify(t, authorities=[SDN_AUTHORITY]),
                         (WITHHELD, ADDR_A.lower(),
                          [{"ground": "excluded-authority", "authority": SDN_AUTHORITY}]))
        self.assertEqual(self.classify(t)[0], "eligible")
        ins["parsed"]["info"]["multisigAuthority"] = PROJECT_AUTHORITY
        self.assertEqual(self.classify(t), ("excluded", "project-address"))

    def test_screen_runs_before_the_dust_floor(self):
        # THE EVASION: a listed authority names a destination with a burn
        # under the floor. The screen runs before the dust floor, so the burn
        # is withheld and the destination it names is tainted.
        t = tx([burn_ins(1, authority=SDN_AUTHORITY), memo_ins("SOQMIG1:" + ADDR_A)])
        self.assertEqual(self.classify(t, sdn=[SDN_AUTHORITY])[0], WITHHELD)
        self.assertEqual(self.classify(t), ("excluded", "below-dust-floor"))

    def test_structural_codes_and_project_address_still_win(self):
        # A listed authority that names no valid destination takes the
        # structural code: nothing could be credited and nothing is tainted.
        self.assertEqual(self.classify(tx([burn_ins(2_000_000, authority=SDN_AUTHORITY)]),
                                       sdn=[SDN_AUTHORITY]), ("excluded", "no-memo"))
        self.assertEqual(self.classify(tx([burn_ins(2_000_000, authority=SDN_AUTHORITY),
                                           memo_ins("SOQMIG1:notbech32m")]),
                                       sdn=[SDN_AUTHORITY]), ("excluded", "invalid-address"))
        self.assertEqual(self.classify(tx([burn_ins(2_000_000, authority=PROJECT_AUTHORITY),
                                           memo_ins("SOQMIG1:" + ADDR_A)]),
                                       sdn=[PROJECT_AUTHORITY]), ("excluded", "project-address"))
        # A project destination is project-destination whoever names it.
        verdict = classify_tx(tx([burn_ins(2_000_000, authority=SDN_AUTHORITY),
                                  memo_ins("SOQMIG1:" + ADDR_A)]),
                              MINT, {SDN_AUTHORITY}, set(), {ADDR_A.lower()})
        self.assertEqual(verdict, ("excluded", "project-destination"))


class TaintedDestinationTests(unittest.TestCase):
    def snapshot_of(self, burns, sdn=(SDN_AUTHORITY,), authorities=(), destinations=()):
        rpc = RpcClient(None, corpus=corpus_for(burns))
        return run_snapshot(rpc, MINT, WINDOW_OPEN, FREEZE, set(sdn), {PROJECT_AUTHORITY},
                            set(), set(authorities), {a.lower() for a in destinations})

    def test_withheld_transaction_taints_its_destination(self):
        # THE ATTACK the tainted-destination rule answers: a listed authority
        # names a fresh ADDR_B; a clean holder then burns to ADDR_B too.
        # Without the rule ADDR_B is credited the clean burn and the listed
        # party is paid through it.
        burns = [
            ("sig_clean_a", 150, tx([burn_ins(5_000_000), memo_ins("SOQMIG1:" + ADDR_A)])),
            ("sig_listed_b", 151, tx([burn_ins(9_000_000, authority=SDN_AUTHORITY),
                                      memo_ins("SOQMIG1:" + ADDR_B)])),
            ("sig_clean_b", 152, tx([burn_ins(3_000_000, authority="CleanHolder"),
                                     memo_ins("SOQMIG1:" + ADDR_B)])),
        ]
        allocations, exclusions, withheld = self.snapshot_of(burns)
        self.assertEqual(set(allocations), {ADDR_A.lower()})
        self.assertEqual(exclusions, [
            {"txid": "sig_clean_b", "slot": 152, "reason": WITHHELD},
            {"txid": "sig_listed_b", "slot": 151, "reason": WITHHELD}])
        self.assertEqual(withheld, [
            {"txid": "sig_clean_b", "slot": 152, "destination": ADDR_B.lower(),
             "grounds": [{"ground": "tainted-destination", "destination": ADDR_B.lower(),
                          "tainted_by": ["sig_listed_b"]}]},
            {"txid": "sig_listed_b", "slot": 151, "destination": ADDR_B.lower(),
             "grounds": [{"ground": "sdn-authority", "authority": SDN_AUTHORITY}]}])

    def test_a_later_withheld_burn_does_not_taint_a_credited_destination(self):
        # A listed authority reads ADDR_B from the provisional list and names
        # it after the holder's credited burn. The holder keeps the
        # allocation; the listed burn is withheld alone.
        burns = [
            ("sig_clean_b", 151, tx([burn_ins(3_000_000, authority="CleanHolder"),
                                     memo_ins("SOQMIG1:" + ADDR_B)])),
            ("sig_listed_b", 152, tx([burn_ins(1, authority=SDN_AUTHORITY),
                                      memo_ins("SOQMIG1:" + ADDR_B)])),
            ("sig_clean_b_again", 153, tx([burn_ins(2_000_000, authority="CleanHolder"),
                                           memo_ins("SOQMIG1:" + ADDR_B)])),
        ]
        allocations, exclusions, withheld = self.snapshot_of(burns)
        self.assertEqual(allocations, {ADDR_B.lower(): {
            "sats": 500_000_000, "txids": ["sig_clean_b", "sig_clean_b_again"]}})
        self.assertEqual(exclusions, [{"txid": "sig_listed_b", "slot": 152,
                                       "reason": WITHHELD}])
        self.assertEqual([w["txid"] for w in withheld], ["sig_listed_b"])

    def test_a_withheld_burn_in_the_same_slot_does_not_taint(self):
        # A tie goes to the credited burn: only a strictly earlier slot taints.
        burns = [
            ("sig_clean_b", 151, tx([burn_ins(3_000_000, authority="CleanHolder"),
                                     memo_ins("SOQMIG1:" + ADDR_B)])),
            ("sig_listed_b", 151, tx([burn_ins(9_000_000, authority=SDN_AUTHORITY),
                                      memo_ins("SOQMIG1:" + ADDR_B)])),
        ]
        allocations, _, withheld = self.snapshot_of(burns)
        self.assertEqual(allocations, {ADDR_B.lower(): {
            "sats": 300_000_000, "txids": ["sig_clean_b"]}})
        self.assertEqual([w["txid"] for w in withheld], ["sig_listed_b"])

    def test_first_credited_burn_is_the_earliest_slot_whatever_the_txid_order(self):
        # The credited transaction ids sort opposite to their slots; the
        # withheld burn lands between them, after the first credited burn.
        burns = [
            ("b_early", 150, tx([burn_ins(2_000_000, authority="CleanHolder"),
                                 memo_ins("SOQMIG1:" + ADDR_B)])),
            ("w_mid", 151, tx([burn_ins(1_000_000, authority=SDN_AUTHORITY),
                               memo_ins("SOQMIG1:" + ADDR_B)])),
            ("a_late", 152, tx([burn_ins(3_000_000, authority="CleanHolder"),
                                memo_ins("SOQMIG1:" + ADDR_B)])),
        ]
        allocations, _, withheld = self.snapshot_of(burns)
        self.assertEqual(allocations, {ADDR_B.lower(): {
            "sats": 500_000_000, "txids": ["a_late", "b_early"]}})
        self.assertEqual([w["txid"] for w in withheld], ["w_mid"])

    def test_only_the_earlier_withheld_burns_are_recorded_as_tainting(self):
        burns = [
            ("sig_listed_early", 150, tx([burn_ins(1_000_000, authority=SDN_AUTHORITY),
                                          memo_ins("SOQMIG1:" + ADDR_B)])),
            ("sig_clean_b", 151, tx([burn_ins(3_000_000, authority="CleanHolder"),
                                     memo_ins("SOQMIG1:" + ADDR_B)])),
            ("sig_listed_late", 152, tx([burn_ins(1_000_000, authority=SDN_AUTHORITY),
                                         memo_ins("SOQMIG1:" + ADDR_B)])),
        ]
        allocations, _, withheld = self.snapshot_of(burns)
        self.assertEqual(allocations, {})
        tainted = [w for w in withheld if w["grounds"][0]["ground"] == "tainted-destination"]
        self.assertEqual([w["txid"] for w in tainted], ["sig_clean_b"])
        self.assertEqual(tainted[0]["grounds"][0]["tainted_by"], ["sig_listed_early"])

    def test_taint_does_not_spread_through_the_clean_authority(self):
        # The clean holder's OTHER destination stands: the rule taints
        # destinations named by withheld transactions, never authorities.
        burns = [
            ("sig_listed_b", 149, tx([burn_ins(9_000_000, authority=SDN_AUTHORITY),
                                      memo_ins("SOQMIG1:" + ADDR_B)])),
            ("sig_clean_a", 150, tx([burn_ins(5_000_000, authority="CleanHolder"),
                                     memo_ins("SOQMIG1:" + ADDR_A)])),
            ("sig_clean_b", 151, tx([burn_ins(3_000_000, authority="CleanHolder"),
                                     memo_ins("SOQMIG1:" + ADDR_B)])),
        ]
        allocations, _, _ = self.snapshot_of(burns)
        self.assertEqual(allocations,
                         {ADDR_A.lower(): {"sats": 500_000_000, "txids": ["sig_clean_a"]}})

    def test_excluded_destination_withholds_every_burn_to_it(self):
        burns = [
            ("sig_one", 150, tx([burn_ins(5_000_000), memo_ins("SOQMIG1:" + ADDR_B)])),
            ("sig_two", 151, tx([burn_ins(3_000_000, authority="Other"),
                                 memo_ins("SOQMIG1:" + ADDR_B)])),
        ]
        allocations, exclusions, withheld = self.snapshot_of(burns, destinations=[ADDR_B])
        self.assertEqual(allocations, {})
        self.assertEqual([e["reason"] for e in exclusions], [WITHHELD, WITHHELD])
        self.assertTrue(all(w["grounds"][0]["ground"] == "excluded-destination"
                            for w in withheld))

    def test_public_exclusions_carry_no_ground(self):
        burns = [
            ("sig_listed_b", 150, tx([burn_ins(9_000_000, authority=SDN_AUTHORITY),
                                      memo_ins("SOQMIG1:" + ADDR_B)])),
            ("sig_clean_b", 151, tx([burn_ins(3_000_000), memo_ins("SOQMIG1:" + ADDR_B)])),
            ("sig_third", 153, tx([burn_ins(2_000_000, authority=EXCL_AUTHORITY),
                                    memo_ins("SOQMIG1:" + ADDR_A)])),
        ]
        _, exclusions, _ = self.snapshot_of(burns, authorities=[EXCL_AUTHORITY])
        self.assertEqual(len(exclusions), 3)
        for e in exclusions:
            self.assertEqual(set(e), {"txid", "slot", "reason"})
            self.assertEqual(e["reason"], WITHHELD)
        text = snapshot.canonical_json(exclusions).lower()
        for word in ("sdn", "sanction", "authority", "taint", "vendor", "ofac",
                     SDN_AUTHORITY.lower(), EXCL_AUTHORITY.lower()):
            self.assertNotIn(word, text)

    def test_taint_is_applied_before_the_cap(self):
        # A tainted destination never occupies one of the capped slots.
        addr_c = encode_v1_address("sq", bytes([0xCC] * 32))
        burns = [
            ("sig_listed_b", 149, tx([burn_ins(1_000_000, authority=SDN_AUTHORITY),
                                      memo_ins("SOQMIG1:" + ADDR_B)])),
            ("sig_a", 150, tx([burn_ins(5_000_000), memo_ins("SOQMIG1:" + ADDR_A)])),
            ("sig_b", 151, tx([burn_ins(4_000_000), memo_ins("SOQMIG1:" + ADDR_B)])),
            ("sig_c", 152, tx([burn_ins(3_000_000, authority="Third"),
                               memo_ins("SOQMIG1:" + addr_c)])),
        ]
        allocations, _, _ = self.snapshot_of(burns)
        committed, over_cap = apply_allocation_cap(allocations, cap=2)
        self.assertEqual(set(committed), {ADDR_A.lower(), addr_c.lower()})
        self.assertEqual(over_cap, [])


class ScreeningRecordTests(unittest.TestCase):
    def build(self):
        withheld = [{"txid": "sig_x", "slot": 5, "destination": ADDR_A.lower(),
                     "grounds": [{"ground": "sdn-authority", "authority": SDN_AUTHORITY}]}]
        inputs = {"sdn_addresses": ("/somewhere/sdn.txt", "aa" * 32),
                  "excluded_authorities": ("/somewhere/authorities.txt", "bb" * 32)}
        return withheld, build_screening_record(
            withheld, inputs, mint=MINT, window_open_slot=1, cutoff_slot=2, freeze_slot=2,
            commitment_hash="cc" * 32, exclusions_sha256="dd" * 32, provisional=False)

    def test_record_carries_grounds_and_binds_to_the_published_set(self):
        withheld, record = self.build()
        self.assertEqual(record["published_code"], WITHHELD)
        self.assertEqual(record["tool_version"], snapshot.TOOL_VERSION)
        self.assertEqual(record["entries"], withheld)
        self.assertEqual(record["inputs"]["sdn_addresses"],
                         {"file": "sdn.txt", "sha256": "aa" * 32})
        self.assertEqual(record["inputs"]["excluded_authorities"],
                         {"file": "authorities.txt", "sha256": "bb" * 32})
        self.assertEqual(record["hash_migration_outputs"], "cc" * 32)
        self.assertEqual(record["exclusions_sha256"], "dd" * 32)
        self.assertEqual(record["provisional"], False)
        self.assertIn("five years", record["retention"])

    def test_record_is_deterministic(self):
        _, first = self.build()
        _, second = self.build()
        self.assertEqual(snapshot.canonical_json(first), snapshot.canonical_json(second))

    def test_record_path_must_be_outside_the_published_directory(self):
        with tempfile.TemporaryDirectory() as d:
            out = os.path.join(d, "artifacts")
            os.makedirs(out)
            self.assertFalse(record_path_is_outside(out, os.path.join(out, "record.json")))
            self.assertFalse(record_path_is_outside(out, os.path.join(out, "sub", "r.json")))
            self.assertTrue(record_path_is_outside(out, os.path.join(d, "record.json")))
            # A sibling whose name merely starts with the artifact directory's.
            self.assertTrue(record_path_is_outside(out, os.path.join(d, "artifacts-private",
                                                                     "r.json")))


DERIVED_LINES = ("hash_migration_outputs", "n_migration_total", "allocation_count",
                 "over_cap_count", "withheld_count", "allocations_sha256",
                 "exclusions_sha256", "outputs_sha256")


def run_files(allocations, exclusions):
    """What snapshot.py writes for a set: the two JSON files, outputs.hex, and
    the lines of commitment.txt that are a function of them."""
    files = {"allocations.json": snapshot.canonical_json(allocations),
             "exclusions.json": snapshot.canonical_json(exclusions)}
    outputs, total = build_outputs(allocations)
    files["outputs.hex"] = ser_txout_vector(outputs).hex() + "\n"
    lines = {
        "hash_migration_outputs": hash_migration_outputs(outputs),
        "n_migration_total": str(total),
        "allocation_count": str(len(outputs)),
        "over_cap_count": str(len({e["address"] for e in exclusions
                                   if e["reason"] == "over-cap"})),
        "withheld_count": str(sum(1 for e in exclusions if e["reason"] == WITHHELD)),
    }
    for name, key in (("allocations.json", "allocations_sha256"),
                      ("exclusions.json", "exclusions_sha256"),
                      ("outputs.hex", "outputs_sha256")):
        lines[key] = hashlib.sha256(files[name].encode()).hexdigest()
    return files, lines


def write_run(directory, allocations, exclusions, commitment, outputs_hex=None):
    """A run directory as snapshot.py writes one; a line in `commitment`
    replaces the computed line, and `outputs_hex` replaces outputs.hex."""
    files, lines = run_files(allocations, exclusions)
    lines.update(commitment)
    if outputs_hex is not None:
        files["outputs.hex"] = outputs_hex
    files["commitment.txt"] = "".join("%s=%s\n" % item for item in lines.items())
    os.makedirs(directory, exist_ok=True)
    for name, text in files.items():
        with open(os.path.join(directory, name), "w") as f:
            f.write(text)


class CompareRunsTests(unittest.TestCase):
    """The re-run before the constants are fixed may differ from the freeze
    run by withheld removals alone; compare_runs.py is that sentence as a check."""

    def setUp(self):
        self.dir = tempfile.mkdtemp()
        self.prev = os.path.join(self.dir, "freeze")
        self.new = os.path.join(self.dir, "rerun")
        self.alloc = {ADDR_A.lower(): {"sats": 750_000_000, "txids": ["sigA", "sigB"]},
                      ADDR_B.lower(): {"sats": 300_000_000, "txids": ["sigC"]}}
        self.excl = [{"txid": "sigF", "slot": 156, "reason": "no-memo"}]
        self.commitment = {"window_open_slot": "100",
                           "cutoff_slot": "200", "freeze_slot": "200", "provisional": "no",
                           "tool_version": "4", "mint": MINT, "allocation_cap": "20000",
                           "sdn_file_sha256": "s1", "project_file_sha256": "p",
                           "project_destinations_sha256": "q",
                           "excluded_authorities_sha256": "e1",
                           "excluded_destinations_sha256": "e2"}
        write_run(self.prev, self.alloc, self.excl, self.commitment)

    def tearDown(self):
        shutil.rmtree(self.dir)

    def new_run(self, alloc=None, excl=None, **changes):
        commitment = dict(self.commitment, **changes)
        write_run(self.new, self.alloc if alloc is None else alloc,
                  self.excl if excl is None else excl, commitment)
        return compare_runs.compare(self.prev, self.new)

    def test_identical_runs_pass(self):
        self.assertEqual(self.new_run(sdn_file_sha256="s2"), [])

    def test_a_line_its_files_do_not_give_fails_in_either_run(self):
        # The same allocations and exclusions as the freeze run, with one line
        # that is a function of the files set to another value. The hash and
        # the total are the constants compiled in.
        for key in DERIVED_LINES:
            problems = self.new_run(**{key: "1"})
            self.assertTrue(any(p.startswith("new run's %s is 1;" % key)
                                for p in problems), (key, problems))
            write_run(self.prev, self.alloc, self.excl, dict(self.commitment, **{key: "1"}))
            problems = self.new_run()
            self.assertTrue(any(p.startswith("previous run's %s is 1;" % key)
                                for p in problems), (key, problems))
            write_run(self.prev, self.alloc, self.excl, self.commitment)

    def test_a_vector_that_is_not_the_allocations_fails_in_either_run(self):
        # outputs.hex, the hash, the total and the outputs hash agree with one
        # another and describe a vector that pays ADDR_A more than
        # allocations.json does; every other line is the honest one.
        forged = dict(self.alloc)
        forged[ADDR_A.lower()] = {"sats": 950_000_000, "txids": ["sigA", "sigB"]}
        forged_files, forged_lines = run_files(forged, self.excl)
        consensus = {key: forged_lines[key] for key in
                     ("hash_migration_outputs", "n_migration_total", "outputs_sha256")}
        for directory, label in ((self.new, "new"), (self.prev, "previous")):
            write_run(self.prev, self.alloc, self.excl, self.commitment)
            write_run(self.new, self.alloc, self.excl, self.commitment)
            write_run(directory, self.alloc, self.excl, dict(self.commitment, **consensus),
                      outputs_hex=forged_files["outputs.hex"])
            problems = compare_runs.compare(self.prev, self.new)
            self.assertEqual(sorted(p.split(" is ")[0] for p in problems),
                             ["%s run's %s" % (label, key) for key in
                              ("hash_migration_outputs", "n_migration_total",
                               "outputs.hex", "outputs_sha256")], problems)

    def test_allocations_the_tool_would_refuse_fail(self):
        # An allocation under the utxo-cost floor: build_outputs refuses it, so
        # no run of the tool wrote it, and the check lists it.
        write_run(self.new, self.alloc, self.excl, self.commitment)
        alloc = dict(self.alloc)
        alloc[ADDR_B.lower()] = {"sats": 279_499, "txids": ["sigC"]}
        with open(os.path.join(self.new, "allocations.json"), "w") as f:
            f.write(snapshot.canonical_json(alloc))
        self.assertTrue(any(p.startswith("new run's allocations.json is refused")
                            for p in compare_runs.compare(self.prev, self.new)))

    def test_reduction_by_withholding_passes(self):
        # A wallet withheld after the freeze had burned to ADDR_A after its
        # first credited burn: the re-run withholds that burn alone and ADDR_A
        # keeps the rest.
        alloc = dict(self.alloc)
        alloc[ADDR_A.lower()] = {"sats": 500_000_000, "txids": ["sigA"]}
        excl = self.excl + [{"txid": "sigB", "slot": 152, "reason": WITHHELD}]
        self.assertEqual(self.new_run(alloc=alloc, excl=excl), [])

    def test_reduction_without_a_withheld_entry_fails(self):
        alloc = dict(self.alloc)
        alloc[ADDR_A.lower()] = {"sats": 500_000_000, "txids": ["sigA"]}
        self.assertTrue(any(p.startswith("allocation changed")
                            for p in self.new_run(alloc=alloc)))

    def test_reduction_edges_that_are_not_withholding_fail(self):
        # A dropped transaction with the sats unchanged, lower sats with nothing
        # dropped, and higher sats are each a change the re-run cannot make.
        excl = self.excl + [{"txid": "sigB", "slot": 152, "reason": WITHHELD}]
        for entry, exclusions in (
                ({"sats": 750_000_000, "txids": ["sigA"]}, excl),
                ({"sats": 500_000_000, "txids": ["sigA", "sigB"]}, self.excl),
                ({"sats": 900_000_000, "txids": ["sigA"]}, excl)):
            alloc = dict(self.alloc)
            alloc[ADDR_A.lower()] = entry
            self.assertTrue(any(p.startswith("allocation changed")
                                for p in self.new_run(alloc=alloc, excl=exclusions)), entry)

    def test_reduction_that_adds_a_transaction_fails(self):
        alloc = dict(self.alloc)
        alloc[ADDR_A.lower()] = {"sats": 500_000_000, "txids": ["sigA", "sigZ"]}
        excl = self.excl + [{"txid": "sigB", "slot": 152, "reason": WITHHELD}]
        self.assertTrue(any(p.startswith("allocation changed")
                            for p in self.new_run(alloc=alloc, excl=excl)))

    def test_a_fixed_line_missing_from_both_runs_fails(self):
        commitment = dict(self.commitment)
        del commitment["freeze_slot"]
        write_run(self.prev, self.alloc, self.excl, commitment)
        write_run(self.new, self.alloc, self.excl, commitment)
        problems = compare_runs.compare(self.prev, self.new)
        self.assertIn("previous run's commitment.txt has no freeze_slot line", problems)
        self.assertIn("new run's commitment.txt has no freeze_slot line", problems)

    def test_withheld_removal_passes(self):
        alloc = {ADDR_A.lower(): self.alloc[ADDR_A.lower()]}
        excl = self.excl + [{"txid": "sigC", "slot": 149, "reason": WITHHELD},
                            {"txid": "sigNew", "slot": 199, "reason": WITHHELD}]
        self.assertEqual(self.new_run(alloc, excl, sdn_file_sha256="s2",
                                      excluded_authorities_sha256="e3"), [])

    def test_removal_without_a_withheld_entry_fails(self):
        alloc = {ADDR_A.lower(): self.alloc[ADDR_A.lower()]}
        problems = self.new_run(alloc)
        self.assertEqual(len(problems), 1)
        self.assertIn(ADDR_B.lower(), problems[0])
        self.assertIn("sigC", problems[0])

    def test_addition_and_change_fail(self):
        addr_c = encode_v1_address("sq", bytes([0xCC] * 32)).lower()
        alloc = dict(self.alloc)
        alloc[addr_c] = {"sats": 100_000_000, "txids": ["sigX"]}
        self.assertTrue(any("added" in p and addr_c in p for p in self.new_run(alloc)))
        alloc = dict(self.alloc)
        alloc[ADDR_A.lower()] = {"sats": 760_000_000, "txids": ["sigA", "sigB"]}
        self.assertTrue(any("changed" in p and ADDR_A.lower() in p for p in self.new_run(alloc)))
        alloc = dict(self.alloc)
        alloc[ADDR_A.lower()] = {"sats": 750_000_000, "txids": ["sigA", "sigB", "sigZ"]}
        self.assertTrue(any("changed" in p for p in self.new_run(alloc)))

    def test_structural_verdicts_may_not_move(self):
        self.assertTrue(any("disappeared" in p for p in self.new_run(excl=[])))
        excl = self.excl + [{"txid": "sigQ", "slot": 170, "reason": "malformed-memo"}]
        self.assertTrue(any("not withheld" in p and "sigQ" in p for p in self.new_run(excl=excl)))
        excl = [{"txid": "sigF", "slot": 156, "reason": "multiple-memos"}]
        self.assertTrue(any("exclusion changed" in p for p in self.new_run(excl=excl)))
        # A structural exclusion that becomes withheld is a legal removal.
        excl = [{"txid": "sigF", "slot": 156, "reason": WITHHELD}]
        self.assertEqual(self.new_run(excl=excl), [])

    def test_window_tool_mint_and_project_inputs_may_not_move(self):
        for key in ("window_open_slot", "freeze_slot", "cutoff_slot", "tool_version", "mint",
                    "project_file_sha256", "project_destinations_sha256"):
            problems = self.new_run(**{key: "moved"})
            self.assertTrue(any(key in p for p in problems), key)

    def test_provisional_runs_are_refused(self):
        self.assertTrue(any("provisional" in p for p in self.new_run(provisional="yes")))


class CommandLineTests(unittest.TestCase):
    """The tool end to end over the committed corpus: the gates on a final
    run, the published set, the unpublished record."""

    def setUp(self):
        self.dir = tempfile.mkdtemp()
        self.paths = {}
        for name, content in (("sdn.txt", SDN_AUTHORITY + "\n"),
                              ("project.txt", PROJECT_AUTHORITY + "\n"),
                              ("destinations.txt", "# none\n"),
                              ("authorities.txt", "# none\n"),
                              ("excluded-destinations.txt", "# none\n")):
            path = os.path.join(self.dir, name)
            with open(path, "w") as f:
                f.write(content)
            self.paths[name] = path
        self.out = os.path.join(self.dir, "out")
        self.record = os.path.join(self.dir, "private", "screening-record.json")

    def tearDown(self):
        shutil.rmtree(self.dir)

    def run_tool(self, *extra, omit=()):
        cmd = [sys.executable, os.path.join(HERE, "snapshot.py"),
               "--rpc-corpus", os.path.join(FIXTURES, "rpc_corpus.json"),
               "--mint", MINT, "--window-open-slot", str(WINDOW_OPEN),
               "--freeze-slot", str(FREEZE), "--out", self.out]
        for flag, path in (("--sdn-addresses", self.paths["sdn.txt"]),
                           ("--project-addresses", self.paths["project.txt"]),
                           ("--project-destinations", self.paths["destinations.txt"]),
                           ("--excluded-authorities", self.paths["authorities.txt"]),
                           ("--excluded-destinations", self.paths["excluded-destinations.txt"]),
                           ("--screening-record", self.record)):
            if flag not in omit:
                cmd += [flag, path]
        cmd += list(extra)
        return subprocess.run(cmd, capture_output=True, text=True)

    def test_final_run_requires_every_list_and_the_record(self):
        for flag in ("--project-destinations", "--excluded-authorities",
                     "--excluded-destinations", "--screening-record"):
            result = self.run_tool(omit=(flag,))
            self.assertEqual(result.returncode, 2, flag)
            self.assertIn(flag, result.stderr)
            self.assertFalse(os.path.exists(self.out), flag)
        # A draft needs the project destinations as well.
        result = self.run_tool("--provisional", omit=("--project-destinations",))
        self.assertEqual(result.returncode, 2)
        self.assertIn("--project-destinations", result.stderr)

    def test_an_empty_list_path_stops_the_run(self):
        # An empty argument satisfies argparse's required check. It must not
        # be read as an empty list with the sentinel `none` as its hash.
        for flag in ("--project-destinations", "--excluded-authorities",
                     "--excluded-destinations"):
            result = self.run_tool(flag, "", omit=(flag,))
            self.assertNotEqual(result.returncode, 0, flag)
            self.assertFalse(os.path.exists(self.out), flag)
            self.assertFalse(os.path.exists(self.record), flag)

    def test_record_inside_the_published_directory_is_refused(self):
        self.record = os.path.join(self.out, "screening-record.json")
        result = self.run_tool()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("screening record", result.stderr.lower())
        self.assertFalse(os.path.exists(self.out))

    def test_full_run_publishes_the_code_and_records_the_grounds(self):
        result = self.run_tool()
        self.assertEqual(result.returncode, 0, result.stderr)
        commitment = dict(line.split("=", 1) for line in result.stdout.strip().splitlines())
        self.assertEqual(commitment["hash_migration_outputs"], EXPECTED_HASH)
        self.assertEqual(commitment["n_migration_total"], str(EXPECTED_TOTAL))
        self.assertEqual(commitment["tool_version"], "5")
        self.assertEqual(commitment["mint"], MINT)
        self.assertEqual(commitment["withheld_count"], "1")
        self.assertEqual(commitment["excluded_authorities_sha256"],
                         hashlib.sha256(b"# none\n").hexdigest())
        self.assertEqual(commitment["excluded_destinations_sha256"],
                         hashlib.sha256(b"# none\n").hexdigest())
        with open(os.path.join(self.out, "exclusions.json")) as f:
            exclusions = json.load(f)
        self.assertEqual([e["txid"] for e in exclusions if e["reason"] == WITHHELD],
                         ["sigI_sanctioned"])
        self.assertTrue(all(set(e) == {"txid", "slot", "reason"} for e in exclusions))
        self.assertEqual(sorted(os.listdir(self.out)),
                         ["allocations.json", "commitment.txt", "exclusions.json",
                          "outputs.hex"])
        with open(self.record) as f:
            record = json.load(f)
        self.assertEqual(record["hash_migration_outputs"], EXPECTED_HASH)
        self.assertEqual(record["exclusions_sha256"], commitment["exclusions_sha256"])
        self.assertEqual([w["txid"] for w in record["entries"]], ["sigI_sanctioned"])
        self.assertEqual(record["entries"][0]["grounds"][0]["ground"], "sdn-authority")
        self.assertEqual(record["inputs"]["sdn_addresses"]["file"], "sdn.txt")
        # The record is deterministic: a second run writes the same bytes.
        with open(self.record, "rb") as f:
            first = f.read()
        self.run_tool()
        with open(self.record, "rb") as f:
            self.assertEqual(f.read(), first)

    def test_screening_record_is_readable_by_its_owner_alone(self):
        # Under a umask that grants everyone everything, the record is created
        # 0600 in a directory created 0700; a record left readable by others is
        # set to 0600 before the next run writes to it.
        previous = os.umask(0)
        try:
            result = self.run_tool()
        finally:
            os.umask(previous)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(stat.S_IMODE(os.stat(self.record).st_mode), 0o600)
        self.assertEqual(stat.S_IMODE(os.stat(os.path.dirname(self.record)).st_mode), 0o700)
        os.chmod(self.record, 0o644)
        result = self.run_tool()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(stat.S_IMODE(os.stat(self.record).st_mode), 0o600)

    def test_two_runs_of_the_tool_compare_clean(self):
        # The freeze run, then a re-run whose excluded-destinations list names
        # ADDR_B: sigC is withheld and ADDR_B removed. compare_runs recomputes
        # both runs' lines from their files and finds nothing to refuse.
        freeze = self.out
        result = self.run_tool()
        self.assertEqual(result.returncode, 0, result.stderr)
        with open(self.paths["excluded-destinations.txt"], "w") as f:
            f.write(ADDR_B + "\n")
        self.out = os.path.join(self.dir, "rerun")
        result = self.run_tool()
        self.assertEqual(result.returncode, 0, result.stderr)
        result = subprocess.run([sys.executable, os.path.join(HERE, "compare_runs.py"),
                                 freeze, self.out], capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        with open(os.path.join(self.out, "allocations.json")) as f:
            self.assertEqual(set(json.load(f)), {ADDR_A.lower()})

    def published_set(self):
        with open(os.path.join(self.out, "allocations.json")) as f:
            allocations = json.load(f)
        with open(os.path.join(self.out, "exclusions.json")) as f:
            exclusions = json.load(f)
        return allocations, {e["txid"]: e["reason"] for e in exclusions}

    def test_uppercase_project_destination_in_the_list_file_is_matched(self):
        # The list file spells the address in uppercase; the memos spell it in
        # lowercase. The tool lowercases the list, so the burns to it are
        # project-destination and the address is not credited.
        with open(self.paths["destinations.txt"], "w") as f:
            f.write(ADDR_A.upper() + "\n")
        result = self.run_tool()
        self.assertEqual(result.returncode, 0, result.stderr)
        allocations, reasons = self.published_set()
        self.assertNotIn(ADDR_A.lower(), allocations)
        self.assertEqual((reasons["sigA_addr_a"], reasons["sigB_addr_a_again"]),
                         ("project-destination", "project-destination"))

    def test_uppercase_excluded_destination_in_the_list_file_is_matched(self):
        with open(self.paths["excluded-destinations.txt"], "w") as f:
            f.write(ADDR_A.upper() + "\n")
        result = self.run_tool()
        self.assertEqual(result.returncode, 0, result.stderr)
        allocations, reasons = self.published_set()
        self.assertNotIn(ADDR_A.lower(), allocations)
        self.assertEqual((reasons["sigA_addr_a"], reasons["sigB_addr_a_again"]),
                         (WITHHELD, WITHHELD))
        with open(self.record) as f:
            record = json.load(f)
        grounds = {w["txid"]: w["grounds"] for w in record["entries"]}
        self.assertEqual(grounds["sigA_addr_a"],
                         [{"ground": "excluded-destination", "destination": ADDR_A.lower()}])


class InProcessMainTests(unittest.TestCase):
    """main() called in-process over the committed corpus, so that a module
    constant can be patched for the run: the allocation cap binds, and the
    over-cap entries reach the published exclusions."""

    def setUp(self):
        self.dir = tempfile.mkdtemp()
        self.paths = {}
        for name, content in (("sdn.txt", "# none\n"),
                              ("project.txt", PROJECT_AUTHORITY + "\n"),
                              ("none.txt", "# none\n")):
            path = os.path.join(self.dir, name)
            with open(path, "w") as f:
                f.write(content)
            self.paths[name] = path
        self.out = os.path.join(self.dir, "out")

    def tearDown(self):
        shutil.rmtree(self.dir)

    def run_main(self):
        argv = ["snapshot.py", "--rpc-corpus", os.path.join(FIXTURES, "rpc_corpus.json"),
                "--mint", MINT, "--window-open-slot", str(WINDOW_OPEN),
                "--freeze-slot", str(FREEZE), "--out", self.out,
                "--sdn-addresses", self.paths["sdn.txt"],
                "--project-addresses", self.paths["project.txt"],
                "--project-destinations", self.paths["none.txt"],
                "--excluded-authorities", self.paths["none.txt"],
                "--excluded-destinations", self.paths["none.txt"],
                "--screening-record", os.path.join(self.dir, "private", "record.json")]
        stdout = io.StringIO()
        with unittest.mock.patch.object(sys, "argv", argv), contextlib.redirect_stdout(stdout):
            snapshot.main()
        commitment = dict(line.split("=", 1) for line in stdout.getvalue().strip().splitlines())
        with open(os.path.join(self.out, "allocations.json")) as f:
            allocations = json.load(f)
        with open(os.path.join(self.out, "exclusions.json")) as f:
            exclusions = json.load(f)
        return commitment, allocations, exclusions

    def test_over_cap_entries_are_published(self):
        # With the SDN authority not listed the corpus credits two
        # destinations: ADDR_B 1,200,000,000 sats and ADDR_A 750,000,000 sats.
        # A cap of one keeps ADDR_B; ADDR_A's two transactions are over-cap.
        with unittest.mock.patch.object(snapshot, "MAX_ALLOCATION_OUTPUTS", 1):
            commitment, allocations, exclusions = self.run_main()
            # compare_runs recomputes over_cap_count as the tool writes it.
            self.assertEqual(compare_runs.self_check("capped", compare_runs.read_run(self.out)),
                             [])
        self.assertEqual(commitment["allocation_cap"], "1")
        self.assertEqual(commitment["over_cap_count"], "1")
        self.assertEqual(commitment["allocation_count"], "1")
        self.assertEqual(commitment["n_migration_total"], "1200000000")
        self.assertEqual(set(allocations), {ADDR_B.lower()})
        self.assertEqual([e for e in exclusions if e["reason"] == "over-cap"], [
            {"txid": "sigA_addr_a", "reason": "over-cap",
             "address": ADDR_A.lower(), "sats": 750_000_000},
            {"txid": "sigB_addr_a_again", "reason": "over-cap",
             "address": ADDR_A.lower(), "sats": 750_000_000}])
        # Without the patch the same run commits both destinations.
        commitment, allocations, exclusions = self.run_main()
        self.assertEqual(commitment["over_cap_count"], "0")
        self.assertEqual(set(allocations), {ADDR_A.lower(), ADDR_B.lower()})
        self.assertFalse([e for e in exclusions if e["reason"] == "over-cap"])


# ---------------------------------------------------------------------------
# the provider and the run: every transaction version the chain carries, a
# history that does not reach the window, metadata and slot agreement, and a
# draft that can never pass for the final set
# ---------------------------------------------------------------------------

class ProviderTests(unittest.TestCase):
    def burn(self, base_units=2_000_000):
        return tx([burn_ins(base_units), memo_ins("SOQMIG1:" + ADDR_A)])

    def run_corpus(self, corpus):
        return run_snapshot(RpcClient(None, corpus=corpus), MINT, WINDOW_OPEN, FREEZE,
                            set(), {PROJECT_AUTHORITY})

    def test_version_1_transaction_is_fetched_and_credited(self):
        # Mainnet carries version 1 transactions. The corpus answers only a
        # request that asks for them, so a lower ceiling stops the run here.
        t = self.burn()
        t["version"] = 1
        allocations, _, _ = self.run_corpus(corpus_for([("sig_v1", 150, t)]))
        self.assertEqual(allocations[ADDR_A.lower()]["txids"], ["sig_v1"])

    def test_history_across_two_pages_is_read_whole(self):
        key = RpcClient._key
        params = {"limit": 1000, "commitment": "finalized"}
        corpus = {
            key("getSignaturesForAddress", [MINT, params]):
                [{"signature": "sig_b", "slot": 180, "err": None}],
            key("getSignaturesForAddress", [MINT, dict(params, before="sig_b")]):
                [{"signature": "sig_a", "slot": 120, "err": None},
                 {"signature": "sig_old", "slot": WINDOW_OPEN - 5, "err": None}],
        }
        for sig in ("sig_a", "sig_b"):
            corpus[key("getTransaction", [sig, TX_PARAMS])] = self.burn()
        allocations, _, _ = self.run_corpus(corpus)
        self.assertEqual(allocations[ADDR_A.lower()]["txids"], ["sig_a", "sig_b"])

    def test_history_that_ends_above_the_window_is_refused(self):
        # A provider whose index does not reach the window returns a page and
        # then nothing; the run must not treat the silence as an empty window.
        key = RpcClient._key
        params = {"limit": 1000, "commitment": "finalized"}
        corpus = {
            key("getSignaturesForAddress", [MINT, params]):
                [{"signature": "sig_new", "slot": FREEZE + 20, "err": None}],
            key("getSignaturesForAddress", [MINT, dict(params, before="sig_new")]): [],
        }
        with self.assertRaises(SystemExit) as ctx:
            self.run_corpus(corpus)
        self.assertIn("does not serve the whole window", str(ctx.exception))

    def test_empty_history_is_refused(self):
        corpus = {RpcClient._key("getSignaturesForAddress",
                                 [MINT, {"limit": 1000, "commitment": "finalized"}]): []}
        with self.assertRaises(SystemExit) as ctx:
            self.run_corpus(corpus)
        self.assertIn("no signatures", str(ctx.exception))

    def test_page_ending_at_the_open_slot_is_followed_to_the_next_page(self):
        # More signatures at the open slot can sit on the next page, so a page
        # whose last entry is at the open slot does not end the walk.
        key = RpcClient._key
        params = {"limit": 1000, "commitment": "finalized"}
        corpus = {
            key("getSignaturesForAddress", [MINT, params]):
                [{"signature": "sig_open_1", "slot": WINDOW_OPEN, "err": None}],
            key("getSignaturesForAddress", [MINT, dict(params, before="sig_open_1")]):
                [{"signature": "sig_open_2", "slot": WINDOW_OPEN, "err": None},
                 {"signature": "sig_old", "slot": WINDOW_OPEN - 1, "err": None}],
        }
        for sig in ("sig_open_1", "sig_open_2"):
            corpus[key("getTransaction", [sig, TX_PARAMS])] = self.burn()
        allocations, _, _ = self.run_corpus(corpus)
        self.assertEqual(allocations[ADDR_A.lower()]["txids"], ["sig_open_1", "sig_open_2"])

    def test_missing_metadata_is_refused(self):
        t = self.burn()
        t["meta"] = None
        with self.assertRaises(SystemExit) as ctx:
            self.run_corpus(corpus_for([("sig_nometa", 150, t)]))
        self.assertIn("no transaction metadata", str(ctx.exception))

    def test_slot_disagreement_is_refused(self):
        t = self.burn()
        t["slot"] = 151
        with self.assertRaises(SystemExit) as ctx:
            self.run_corpus(corpus_for([("sig_slot", 150, t)]))
        self.assertIn("refusing to guess", str(ctx.exception))
        t["slot"] = 150
        allocations, _, _ = self.run_corpus(corpus_for([("sig_slot", 150, t)]))
        self.assertIn(ADDR_A.lower(), allocations)

    def test_null_transaction_is_refused(self):
        # The provider answers null for a finalized signature: the run stops
        # rather than skipping the transaction.
        with self.assertRaises(SystemExit) as ctx:
            self.run_corpus(corpus_for([("sig_null", 150, None),
                                        ("sig_burn", 151, self.burn())]))
        self.assertIn("sig_null", str(ctx.exception))
        self.assertIn("has no transaction", str(ctx.exception))

    def test_window_is_inclusive_at_both_ends(self):
        # Burns at the open slot and at the cutoff slot are credited; one slot
        # outside either end is neither fetched, credited nor excluded.
        to_b = tx([burn_ins(2_000_000), memo_ins("SOQMIG1:" + ADDR_B)])
        burns = [("sig_before_open", WINDOW_OPEN - 1, to_b),
                 ("sig_at_open", WINDOW_OPEN, self.burn()),
                 ("sig_at_cutoff", FREEZE, self.burn()),
                 ("sig_after_cutoff", FREEZE + 1, to_b)]
        corpus = corpus_for(burns)
        self.assertEqual(snapshot.enumerate_signatures(RpcClient(None, corpus=corpus), MINT,
                                                       WINDOW_OPEN, FREEZE),
                         [(WINDOW_OPEN, "sig_at_open"), (FREEZE, "sig_at_cutoff")])
        allocations, exclusions, withheld = self.run_corpus(corpus)
        self.assertEqual(allocations, {ADDR_A.lower(): {"sats": 400_000_000,
                                                        "txids": ["sig_at_cutoff", "sig_at_open"]}})
        self.assertEqual((exclusions, withheld), ([], []))

    def test_signatures_are_deduplicated_and_ordered_by_slot_then_signature(self):
        # The second page repeats the cursor signature and holds three
        # signatures at one slot in provider order; the walk yields each
        # signature once, in (slot, signature) order, and the run credits
        # the repeated signature once.
        key = RpcClient._key
        params = {"limit": 1000, "commitment": "finalized"}
        corpus = {
            key("getSignaturesForAddress", [MINT, params]):
                [{"signature": "sig_d", "slot": 180, "err": None},
                 {"signature": "sig_b", "slot": 150, "err": None}],
            key("getSignaturesForAddress", [MINT, dict(params, before="sig_b")]):
                [{"signature": "sig_b", "slot": 150, "err": None},
                 {"signature": "sig_c", "slot": 150, "err": None},
                 {"signature": "sig_a", "slot": 150, "err": None},
                 {"signature": "sig_old", "slot": WINDOW_OPEN - 5, "err": None}],
        }
        self.assertEqual(snapshot.enumerate_signatures(RpcClient(None, corpus=corpus), MINT,
                                                       WINDOW_OPEN, FREEZE),
                         [(150, "sig_a"), (150, "sig_b"), (150, "sig_c"), (180, "sig_d")])
        for sig in ("sig_a", "sig_b", "sig_c", "sig_d"):
            corpus[key("getTransaction", [sig, TX_PARAMS])] = self.burn()
        allocations, _, _ = self.run_corpus(corpus)
        self.assertEqual(allocations,
                         {ADDR_A.lower(): {"sats": 800_000_000,
                                           "txids": ["sig_a", "sig_b", "sig_c", "sig_d"]}})

    def test_mint_traffic_without_a_burn_is_in_neither_list(self):
        # A transfer of the mint and a memo without a burn are not burn
        # attempts: fetched, classified no-burn, published nowhere.
        transfer = {"programId": TOKEN22,
                    "parsed": {"type": "transferChecked",
                               "info": {"mint": MINT, "authority": "HolderAuthority",
                                        "tokenAmount": {"amount": "2000000", "decimals": 6}}}}
        burns = [("sig_transfer", 150, tx([transfer, memo_ins("SOQMIG1:" + ADDR_B)])),
                 ("sig_memo_only", 151, tx([memo_ins("SOQMIG1:" + ADDR_B)])),
                 ("sig_burn", 152, self.burn())]
        allocations, exclusions, withheld = self.run_corpus(corpus_for(burns))
        self.assertEqual(allocations,
                         {ADDR_A.lower(): {"sats": 200_000_000, "txids": ["sig_burn"]}})
        self.assertEqual((exclusions, withheld), ([], []))

    def test_list_file_with_a_byte_order_mark_keeps_its_first_address(self):
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "list.txt")
            with open(path, "wb") as f:
                f.write(b"\xef\xbb\xbfFirstAddress111\nSecondAddress222\n")
            addresses, _ = load_address_file(path)
        self.assertEqual(addresses, {"FirstAddress111", "SecondAddress222"})


class RpcRetryTests(unittest.TestCase):
    """The network path: dropped connections, timeouts and 5xx answers are
    retried with a bounded backoff; the last failure is raised; a reply that is
    not a JSON object stops the run."""

    class Response(object):
        def __init__(self, body):
            self.body = body

        def __enter__(self):
            return self

        def __exit__(self, *exc):
            return False

        def read(self):
            return self.body

    def call_with(self, effects):
        calls = []

        def fake_urlopen(req, timeout):
            effect = effects[len(calls)]
            calls.append(effect)
            if isinstance(effect, Exception):
                raise effect
            return self.Response(effect)

        with unittest.mock.patch.object(snapshot.urllib.request, "urlopen", fake_urlopen), \
                unittest.mock.patch.object(snapshot.time, "sleep", lambda seconds: None):
            try:
                return RpcClient("http://rpc.invalid").call(
                    "getSlot", [{"commitment": "finalized"}]), len(calls)
            except (SystemExit, Exception) as e:
                return e, len(calls)

    def test_dropped_connection_and_timeout_are_retried(self):
        import urllib.error
        ok = b'{"jsonrpc": "2.0", "id": 1, "result": 42}'
        result, calls = self.call_with([urllib.error.URLError("reset"), TimeoutError(), ok])
        self.assertEqual((result, calls), (42, 3))

    def test_a_persistent_failure_is_raised_after_the_last_attempt(self):
        import urllib.error
        failures = [urllib.error.URLError("reset")] * snapshot.RPC_RETRIES
        result, calls = self.call_with(failures)
        self.assertIsInstance(result, urllib.error.URLError)
        self.assertEqual(calls, snapshot.RPC_RETRIES)

    def test_a_client_error_is_not_retried(self):
        import urllib.error
        error = urllib.error.HTTPError("http://rpc.invalid", 400, "bad request", {}, None)
        result, calls = self.call_with([error])
        self.assertIsInstance(result, urllib.error.HTTPError)
        self.assertEqual(calls, 1)

    def test_a_reply_that_is_not_an_object_stops_the_run(self):
        result, calls = self.call_with([b"[1, 2]"])
        self.assertIsInstance(result, SystemExit)
        self.assertIn("malformed rpc reply", str(result))


class DraftAndFinalRunTests(unittest.TestCase):
    """A provisional run is a draft and says so. It never reaches the freeze
    slot, so no draft can pass for the final set, and a final run needs the
    freeze slot and a provider whose finalized chain has passed it."""

    def setUp(self):
        self.dir = tempfile.mkdtemp()
        self.lists = {}
        for name, content in (("sdn.txt", SDN_AUTHORITY + "\n"),
                              ("project.txt", PROJECT_AUTHORITY + "\n"),
                              ("none.txt", "# none\n")):
            path = os.path.join(self.dir, name)
            with open(path, "w") as f:
                f.write(content)
            self.lists[name] = path
        self.out = os.path.join(self.dir, "out")
        self.final = ("--screening-record", os.path.join(self.dir, "private", "record.json"))

    def tearDown(self):
        shutil.rmtree(self.dir)

    def run_tool(self, finalized_slot, *extra):
        with open(os.path.join(FIXTURES, "rpc_corpus.json")) as f:
            corpus = json.load(f)
        corpus[RpcClient._key("getSlot", [{"commitment": "finalized"}])] = finalized_slot
        path = os.path.join(self.dir, "corpus.json")
        with open(path, "w") as f:
            json.dump(corpus, f)
        cmd = [sys.executable, os.path.join(HERE, "snapshot.py"), "--rpc-corpus", path,
               "--mint", MINT, "--window-open-slot", str(WINDOW_OPEN), "--out", self.out,
               "--sdn-addresses", self.lists["sdn.txt"],
               "--project-addresses", self.lists["project.txt"],
               "--project-destinations", self.lists["none.txt"],
               "--excluded-authorities", self.lists["none.txt"],
               "--excluded-destinations", self.lists["none.txt"]] + list(extra)
        result = subprocess.run(cmd, capture_output=True, text=True)
        commitment = {}
        if result.returncode == 0:
            commitment = dict(line.split("=", 1) for line in result.stdout.strip().splitlines())
        return result, commitment

    def test_draft_without_a_freeze_slot_says_so(self):
        result, c = self.run_tool(180, "--provisional")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual((c["provisional"], c["cutoff_slot"], c["freeze_slot"]),
                         ("yes", "180", "unknown"))

    def test_draft_before_the_freeze_slot_is_provisional(self):
        result, c = self.run_tool(180, "--provisional", "--freeze-slot", str(FREEZE))
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual((c["provisional"], c["cutoff_slot"], c["freeze_slot"]),
                         ("yes", "180", str(FREEZE)))

    def test_draft_at_or_past_the_freeze_slot_is_refused(self):
        # With the cutoff at the freeze slot a draft would carry the final
        # set's slots without its SDN screen or its screening record.
        for finalized_slot in (FREEZE, FREEZE + 1, 999):
            result, _ = self.run_tool(finalized_slot, "--provisional", "--freeze-slot", str(FREEZE))
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("reached the freeze slot", result.stderr)
            self.assertFalse(os.path.exists(self.out))

    def test_a_run_before_the_window_or_with_an_inverted_window_is_refused(self):
        result, _ = self.run_tool(WINDOW_OPEN - 1, "--provisional")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("below the window open slot", result.stderr)
        result, _ = self.run_tool(FREEZE + 50, "--window-open-slot", str(FREEZE + 1),
                                  "--freeze-slot", str(FREEZE), *self.final)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("after --freeze-slot", result.stderr)
        self.assertFalse(os.path.exists(self.out))

    def test_the_window_edges_of_the_two_gates_are_accepted(self):
        # A provider exactly at the open slot may run a draft, and a window whose
        # open slot is its freeze slot is a valid one-slot window.
        result, c = self.run_tool(WINDOW_OPEN, "--provisional")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(c["cutoff_slot"], str(WINDOW_OPEN))
        result, c = self.run_tool(FREEZE, "--window-open-slot", str(FREEZE),
                                  "--freeze-slot", str(FREEZE), *self.final)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual((c["window_open_slot"], c["freeze_slot"]), (str(FREEZE), str(FREEZE)))

    def test_every_run_requires_the_sdn_file(self):
        cmd_tail = ["--freeze-slot", str(FREEZE)] + list(self.final)
        for extra in (["--provisional"], cmd_tail):
            cmd = [sys.executable, os.path.join(HERE, "snapshot.py"),
                   "--rpc-corpus", os.path.join(FIXTURES, "rpc_corpus.json"),
                   "--mint", MINT, "--window-open-slot", str(WINDOW_OPEN), "--out", self.out,
                   "--project-addresses", self.lists["project.txt"],
                   "--project-destinations", self.lists["none.txt"],
                   "--excluded-authorities", self.lists["none.txt"],
                   "--excluded-destinations", self.lists["none.txt"]] + extra
            result = subprocess.run(cmd, capture_output=True, text=True)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("requires --sdn-addresses", result.stderr)

    def test_withheld_count_includes_tainted_transactions(self):
        corpus = corpus_for([
            ("sig_listed_b", 150, tx([burn_ins(1_000_000, authority=SDN_AUTHORITY),
                                      memo_ins("SOQMIG1:" + ADDR_B)])),
            ("sig_clean_b", 151, tx([burn_ins(3_000_000, authority="CleanHolder"),
                                     memo_ins("SOQMIG1:" + ADDR_B)])),
            ("sig_clean_a", 152, tx([burn_ins(2_000_000), memo_ins("SOQMIG1:" + ADDR_A)])),
        ])
        corpus[RpcClient._key("getSlot", [{"commitment": "finalized"}])] = FREEZE
        path = os.path.join(self.dir, "taint-corpus.json")
        with open(path, "w") as f:
            json.dump(corpus, f)
        cmd = [sys.executable, os.path.join(HERE, "snapshot.py"), "--rpc-corpus", path,
               "--mint", MINT, "--window-open-slot", str(WINDOW_OPEN),
               "--freeze-slot", str(FREEZE), "--out", self.out,
               "--sdn-addresses", self.lists["sdn.txt"],
               "--project-addresses", self.lists["project.txt"],
               "--project-destinations", self.lists["none.txt"],
               "--excluded-authorities", self.lists["none.txt"],
               "--excluded-destinations", self.lists["none.txt"]] + list(self.final)
        result = subprocess.run(cmd, capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        c = dict(line.split("=", 1) for line in result.stdout.strip().splitlines())
        self.assertEqual((c["withheld_count"], c["allocation_count"]), ("2", "1"))

    def test_final_run_needs_the_freeze_slot_and_the_whole_window_finalized(self):
        result, _ = self.run_tool(FREEZE + 50, *self.final)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("requires --freeze-slot", result.stderr)
        result, _ = self.run_tool(FREEZE - 1, "--freeze-slot", str(FREEZE), *self.final)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("below the freeze slot", result.stderr)
        self.assertFalse(os.path.exists(self.out))
        result, c = self.run_tool(FREEZE, "--freeze-slot", str(FREEZE), *self.final)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual((c["provisional"], c["cutoff_slot"], c["hash_migration_outputs"]),
                         ("no", str(FREEZE), EXPECTED_HASH))


SDN_XML_SAMPLE = """<?xml version="1.0" standalone="yes"?>
<sdnList xmlns="https://sanctionslistservice.ofac.treas.gov/api/PublicationPreview/exports/XML">
  <publshInformation><Publish_Date>09/10/2026</Publish_Date><Record_Count>3</Record_Count></publshInformation>
  <sdnEntry><uid>1</uid><lastName>NAME ONE</lastName><sdnType>Individual</sdnType>
    <idList>
      <id><uid>10</uid><idType>Passport</idType><idNumber>X1234567</idNumber></id>
      <id><uid>11</uid><idType>Digital Currency Address - SOL</idType><idNumber>%s</idNumber></id>
      <id><uid>12</uid><idType>Digital Currency Address - XBT</idType><idNumber>1BoatSLRHtKNngkdXEeobR76b53LETtpyT</idNumber></id>
    </idList></sdnEntry>
  <sdnEntry><uid>2</uid><lastName>NAME TWO</lastName><sdnType>Entity</sdnType>
    <idList>
      <id><uid>20</uid><idType>Digital Currency Address - SOL</idType><idNumber>%s</idNumber></id>
    </idList></sdnEntry>
  <sdnEntry><uid>3</uid><lastName>NAME THREE</lastName><sdnType>Entity</sdnType></sdnEntry>
</sdnList>
""" % (SDN_AUTHORITY, SDN_AUTHORITY)   # the same address listed twice dedupes


class SdnExtractTests(unittest.TestCase):
    def test_extract_and_roundtrip(self):
        import tempfile
        with tempfile.TemporaryDirectory() as d:
            xml_path = os.path.join(d, "sdn.xml")
            with open(xml_path, "w") as f:
                f.write(SDN_XML_SAMPLE)
            date, count, entries = sdn_extract.extract(xml_path)
            self.assertEqual((date, count), ("09/10/2026", "3"))
            self.assertEqual(entries, [("SOL", SDN_AUTHORITY),
                                       ("XBT", "1BoatSLRHtKNngkdXEeobR76b53LETtpyT")])
            text = sdn_extract.render(date, count, sdn_extract.sha256_file(xml_path),
                                      entries)
            # No name from the list may reach the output file.
            self.assertNotIn("NAME", text)
            self.assertNotIn("Passport", text)
            self.assertNotIn("X1234567", text)
            out_path = os.path.join(d, "sdn-addresses.txt")
            with open(out_path, "w") as f:
                f.write(text)
            addresses, _ = load_address_file(out_path)
            self.assertEqual(addresses,
                             {SDN_AUTHORITY, "1BoatSLRHtKNngkdXEeobR76b53LETtpyT"})


def regen():
    os.makedirs(FIXTURES, exist_ok=True)
    with open(os.path.join(FIXTURES, "rpc_corpus.json"), "w") as f:
        json.dump(build_fixture_corpus(), f, sort_keys=True, indent=1)
    rpc = RpcClient(None, corpus=build_fixture_corpus())
    allocations, _, _ = run_snapshot(rpc, MINT, WINDOW_OPEN, FREEZE,
                                     {SDN_AUTHORITY}, {PROJECT_AUTHORITY})
    outputs, total = build_outputs(allocations)
    print("regenerated fixtures/rpc_corpus.json")
    print("hash_migration_outputs=%s" % hash_migration_outputs(outputs))
    print("n_migration_total=%d" % total)
    print("Update EXPECTED_HASH/EXPECTED_TOTAL in this file if they moved,")
    print("and say why in the commit.")


if __name__ == "__main__":
    if "--regen" in sys.argv:
        regen()
    else:
        unittest.main(verbosity=2)

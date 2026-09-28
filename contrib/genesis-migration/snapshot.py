#!/usr/bin/env python3
# Copyright (c) 2026 Soqucoin Labs Inc.
# Distributed under the MIT software license.
#
# Genesis-migration snapshot tool. The rules it implements are SPEC.md.
#
# Scans burns of the pSOQ mint on Solana over a finalized slot window,
# applies the SPEC.md eligibility rules, and produces:
#
#   allocations.json   address -> sats, with contributing txids
#   exclusions.json    txid -> reason code, for every ineligible burn
#   outputs.hex        the serialized CTxOut vector (what the hash covers);
#                      pastes into regtest -migrationoutputs and is the
#                      input for the compiled-in vMigrationOutputs
#   commitment.txt     hashMigrationOutputs / nMigrationTotal / window / hashes
#
# Standard library + plain JSON-RPC only. Every run over the same window and
# the same chain history is byte-identical: outputs are sorted, floats never
# touched, no clock, no randomness. Before the constants are fixed, two
# independent RPC providers must produce identical commitment.txt.
#
# THE LIVE PROVISIONAL LIST: run with --provisional on a schedule during the
# window. Each run publishes the allocation list as of the latest finalized
# slot; a holder burns and sees their address appear in the public draft
# within minutes. The final committed hash MUST equal the hash of the last
# published list, except for removals and reductions by withholding at the
# re-run before the constants are fixed (SPEC.md, legal exclusions); any other
# mismatch is public, provable, before the allocation block exists. The final
# run, made without --provisional at cutoff == freeze_slot, is published as
# the last draft and as the final set.
#
# Project addresses: every project-controlled Solana address is carried in a
# published file (--project-addresses) and its burns are excluded from the
# allocation regardless of memo, so a project burn inside the window can never
# allocate SOQ to the project. The file's sha256 is part of commitment.txt.
# Every run, draft or final, refuses to start without the SDN screen input
# (--sdn-addresses) and the four published lists, each of which is a file.
#
# Legal exclusions: every legal exclusion publishes the ONE code `withheld`;
# the ground (an SDN match, a listed authority, a listed destination, a
# tainted destination) is written to an unpublished screening record
# (--screening-record, required for a final run, refused inside --out, kept
# five years). Two more published lists, --excluded-authorities and
# --excluded-destinations, are hashed into commitment.txt like the project
# lists, so the project's reservation to exclude an address is exercised
# deterministically and anyone re-running the tool reproduces it. The
# tainted-destination rule: a destination that a withheld transaction named
# before its first credited burn is withheld entirely, clean burns to it
# included; a withheld burn naming an address after its first credited burn
# never taints it. compare_runs.py checks the re-run before the constants are
# fixed against the freeze run (removals and reductions by withholding alone).
#
# Offline modes for tests and audits:
#   --rpc-corpus FILE   replay canned RPC responses instead of the network
#   --dump-corpus FILE  record every RPC response for later replay

import argparse
import hashlib
import http.client
import json
import os
import sys
import time
import urllib.error
import urllib.request

from bech32m import decode_v1_address
from serialize import (MAX_ALLOCATION_OUTPUTS, MAX_BLOCK_SUBSIDY, MAX_MONEY,
                       MAX_OUTPUTS_SERIALIZED_BYTES, hash_migration_outputs,
                       is_block_commitment_shape, ser_txout_vector, utxo_cost_floor,
                       v1_script)

RPC_RETRIES = 8
RPC_BACKOFF_SECONDS = 1.0

# The highest transaction version the tool asks the RPC to return. Mainnet
# carries legacy, version 0 and version 1 transactions; a lower ceiling makes
# the RPC refuse every newer transaction touching the mint, and the run stops.
MAX_TRANSACTION_VERSION = 1

TOOL_VERSION = "5"   # recorded in commitment.txt; SPEC.md describes this version

WITHHELD = "withheld"   # the one published code for every legal exclusion

MEMO_PREFIX = "SOQMIG1:"
ADDRESS_HRP = "sq"

# pSOQ is 6 decimals, SOQ is 8: one pSOQ base unit = 100 sats. Integer math
# only, everywhere.
PSOQ_DECIMALS = 6
BASE_UNITS_TO_SATS = 100

# Dust floor: burns below 1 pSOQ are ineligible (SPEC.md).
DUST_FLOOR_BASE_UNITS = 1_000_000

# The scan covers BOTH token programs.
TOKEN_PROGRAMS = (
    "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA",   # SPL Token
    "TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb",   # Token-2022
)
MEMO_PROGRAMS = (
    "MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr",   # Memo v2
    "Memo1UhkJRfHyvLMcVucJwxXeuD728EqVDDwQDxFMNo",   # Memo v1
)


class RpcClient(object):
    """Plain JSON-RPC over HTTP, with optional record/replay for determinism
    fixtures. The replay corpus is keyed by the exact request (method+params),
    so a code change that alters what is asked also fails the fixture."""

    def __init__(self, url, corpus=None, dump_path=None, cache_path=None):
        self.url = url
        self.corpus = corpus            # dict key -> response (replay mode)
        self.dump = {} if dump_path else None
        self.dump_path = dump_path
        # Persistent cache of getTransaction responses keyed by signature. A
        # finalized transaction never changes, so a cached copy is as good as
        # a fresh fetch, and a provisional run every 15 minutes over a flooded
        # window then costs one fetch per NEW signature instead of one per
        # signature. Signature pages and getSlot are never cached: they move.
        self.cache_path = cache_path
        self.cache = {}
        if cache_path and os.path.exists(cache_path):
            with open(cache_path) as f:
                self.cache = json.load(f)
        self._cache_dirty = False
        self._id = 0

    @staticmethod
    def _key(method, params):
        return hashlib.sha256(
            json.dumps([method, params], sort_keys=True,
                       separators=(",", ":")).encode()).hexdigest()

    def call(self, method, params):
        key = self._key(method, params)
        cacheable = (method == "getTransaction" and self.cache_path is not None)
        if cacheable and params[0] in self.cache:
            result = self.cache[params[0]]
            if self.dump is not None:
                self.dump[key] = result
            return result
        if self.corpus is not None:
            if key not in self.corpus:
                raise SystemExit("rpc-corpus miss: %s %s (key %s)" %
                                 (method, json.dumps(params), key))
            result = self.corpus[key]
            if cacheable:
                self.cache[params[0]] = result
                self._cache_dirty = True
            return result
        self._id += 1
        body = json.dumps({"jsonrpc": "2.0", "id": self._id,
                           "method": method, "params": params}).encode()
        req = urllib.request.Request(self.url, data=body,
                                     headers={"Content-Type": "application/json"})
        # Public endpoints rate-limit (HTTP 429), hiccup (5xx), drop connections
        # and time out. Retry with backoff, bounded; a retry never changes what
        # is asked or recorded, and the last failure is raised, never swallowed.
        for attempt in range(RPC_RETRIES):
            try:
                with urllib.request.urlopen(req, timeout=60) as resp:
                    reply = json.loads(resp.read().decode())
                break
            except urllib.error.HTTPError as e:
                if e.code not in (429, 500, 502, 503, 504) or attempt == RPC_RETRIES - 1:
                    raise
            except (OSError, http.client.HTTPException, ValueError):
                if attempt == RPC_RETRIES - 1:
                    raise
            time.sleep(min(RPC_BACKOFF_SECONDS * (2 ** attempt), 30))
        if not isinstance(reply, dict):
            raise SystemExit("malformed rpc reply from %s %s" % (method, json.dumps(params)))
        if "error" in reply and reply["error"]:
            raise SystemExit("rpc error from %s %s: %s" %
                             (method, json.dumps(params), reply["error"]))
        result = reply["result"]
        if self.dump is not None:
            self.dump[key] = result
        if cacheable and result is not None:
            self.cache[params[0]] = result
            self._cache_dirty = True
        return result

    def write_dump(self):
        if self.dump is not None:
            with open(self.dump_path, "w") as f:
                json.dump(self.dump, f, sort_keys=True, indent=1)
        if self.cache_path and self._cache_dirty:
            tmp = self.cache_path + ".tmp"
            with open(tmp, "w") as f:
                json.dump(self.cache, f, sort_keys=True, separators=(",", ":"))
            os.replace(tmp, self.cache_path)
            self._cache_dirty = False


def enumerate_signatures(rpc, mint, open_slot, cutoff_slot):
    """All finalized signatures touching the mint within [open_slot,
    cutoff_slot], oldest-first, deduplicated. getSignaturesForAddress pages
    newest-first via the `before` cursor; we walk until the page falls below
    the window. The mint's history begins long before any window, so a walk
    that ends without reaching a slot below the window means the provider
    does not serve the whole window, and the run refuses."""
    sigs = []
    before = None
    lowest = None
    while True:
        params = [mint, {"limit": 1000, "commitment": "finalized"}]
        if before:
            params[1]["before"] = before
        page = rpc.call("getSignaturesForAddress", params)
        if not page:
            if lowest is None:
                raise SystemExit("the provider returned no signatures for the mint; "
                                 "refusing to guess")
            raise SystemExit("the provider's signature history ends at slot %d, above "
                             "the window open slot %d; it does not serve the whole window"
                             % (lowest, open_slot))
        for entry in page:
            slot = entry["slot"]
            if open_slot <= slot <= cutoff_slot:
                sigs.append((slot, entry["signature"]))
        before = page[-1]["signature"]
        lowest = page[-1]["slot"]
        if lowest < open_slot:
            break
    # Deterministic processing order: (slot, signature) ascending.
    return sorted(set(sigs))


def walk_instructions(tx):
    """Every instruction, outer then inner, in transaction order."""
    msg = tx["transaction"]["message"]
    for ins in msg.get("instructions", []):
        yield ins
    meta = tx.get("meta") or {}
    for group in (meta.get("innerInstructions") or []):
        for ins in group.get("instructions", []):
            yield ins


def parse_burn(ins, mint):
    """Return (base_units, authority) if this is a BurnChecked of the mint
    under either token program, else None."""
    if ins.get("programId") not in TOKEN_PROGRAMS:
        return None
    parsed = ins.get("parsed")
    if not isinstance(parsed, dict) or parsed.get("type") != "burnChecked":
        return None
    info = parsed.get("info", {})
    if info.get("mint") != mint:
        return None
    token_amount = info.get("tokenAmount", {})
    if int(token_amount.get("decimals", -1)) != PSOQ_DECIMALS:
        return None
    base_units = int(token_amount["amount"])
    authority = info.get("authority") or info.get("multisigAuthority") or ""
    return (base_units, authority)


def is_unchecked_burn(ins, mint):
    """A plain (unchecked) `burn` of the mint. Ineligible per SPEC.md
    (BurnChecked only), but it MUST land in exclusions.json rather than
    vanish: it is a holder destroying tokens in a way the window will not
    credit, and the provisional list exists precisely to surface that while
    they can still be warned."""
    if ins.get("programId") not in TOKEN_PROGRAMS:
        return False
    parsed = ins.get("parsed")
    if not isinstance(parsed, dict) or parsed.get("type") != "burn":
        return False
    return parsed.get("info", {}).get("mint") == mint


def parse_memo(ins):
    """Return the memo payload string if this is a memo instruction."""
    if ins.get("programId") not in MEMO_PROGRAMS:
        return None
    parsed = ins.get("parsed")
    return parsed if isinstance(parsed, str) else None


def classify_tx(tx, mint, sdn_addresses, project_addresses=frozenset(),
                project_destinations=frozenset(), excluded_authorities=frozenset(),
                excluded_destinations=frozenset()):
    """Apply the SPEC.md eligibility rules to one finalized transaction.
    Returns one of
      ('eligible', address, sats, authorities)
      ('excluded', reason)             a structural defect, published as is
      ('withheld', address, grounds)   a legal exclusion: published as the one
                                       code WITHHELD; the grounds go to the
                                       screening record and nowhere else

    Order of the checks is part of the published behaviour: a project-address
    burn is 'project-address' whatever its memo says; the legal screen
    applies to every burn that names a valid non-project destination,
    whatever its amount, so a listed authority cannot name a destination
    unrecorded by keeping the burn under the dust floor."""
    meta = tx.get("meta") or {}
    if meta.get("err") is not None:
        return ("excluded", "tx-failed")

    burns = []
    memos = []
    unchecked = False
    for ins in walk_instructions(tx):
        burn = parse_burn(ins, mint)
        if burn is not None:
            burns.append(burn)
        unchecked = unchecked or is_unchecked_burn(ins, mint)
        memo = parse_memo(ins)
        if memo is not None:
            memos.append(memo)

    if not burns:
        if unchecked:
            return ("excluded", "unchecked-burn")
        return ("excluded", "no-burn")
    if unchecked:
        # Mixed checked+unchecked burns in one tx: refuse to guess intent.
        return ("excluded", "unchecked-burn")
    authorities = sorted(set(a for (_, a) in burns))
    for authority in authorities:
        if authority in project_addresses:
            return ("excluded", "project-address")
    if len(memos) == 0:
        return ("excluded", "no-memo")
    if len(memos) > 1:
        return ("excluded", "multiple-memos")

    memo = memos[0]
    if not memo.startswith(MEMO_PREFIX):
        return ("excluded", "malformed-memo")
    address = memo[len(MEMO_PREFIX):]
    if address != address.strip():
        return ("excluded", "invalid-address")
    # bech32 permits an all-uppercase spelling of the same address (some
    # wallets and QR codes produce it). Accept it as the same destination;
    # mixed case stays invalid, as the encoding requires.
    if address.isupper():
        address = address.lower()
    if decode_v1_address(ADDRESS_HRP, address) is None:
        return ("excluded", "invalid-address")
    # A memo naming a project-controlled Soqucoin address is not credited, so
    # no burn by anyone can route an allocation to the project. The list is
    # published like project-addresses.txt.
    if address in project_destinations:
        return ("excluded", "project-destination")

    # The legal screen. Every ground that applies is recorded; the
    # published artifact carries only the code.
    grounds = []
    for authority in authorities:
        if authority in sdn_addresses:
            grounds.append({"ground": "sdn-authority", "authority": authority})
    for authority in authorities:
        if authority in excluded_authorities:
            grounds.append({"ground": "excluded-authority", "authority": authority})
    if address in excluded_destinations:
        grounds.append({"ground": "excluded-destination", "destination": address})
    if grounds:
        return (WITHHELD, address, grounds)

    base_units = sum(b for (b, _) in burns)
    if base_units < DUST_FLOOR_BASE_UNITS:
        return ("excluded", "below-dust-floor")

    return ("eligible", address, base_units * BASE_UNITS_TO_SATS, authorities)


def load_address_file(path):
    """One address per line; '#' comments and blank lines ignored. Used for
    every published list: the SDN digital-currency addresses (built by
    sdn_extract.py), the project-controlled addresses and destinations, and
    the two legal lists. Each file's sha256 is recorded in commitment.txt so
    the exact inputs are part of the published artifact set. Every list is a
    file, and an empty list is a file with no address line: a missing or empty
    path stops the run, never reads as an empty list."""
    with open(path, "rb") as f:
        raw = f.read()
    addresses = set()
    for line in raw.decode("utf-8-sig").splitlines():
        line = line.split("#", 1)[0].strip()
        if line:
            addresses.add(line)
    return addresses, hashlib.sha256(raw).hexdigest()


def run_snapshot(rpc, mint, open_slot, cutoff_slot, sdn_addresses,
                 project_addresses=frozenset(), project_destinations=frozenset(),
                 excluded_authorities=frozenset(), excluded_destinations=frozenset()):
    """Returns (allocations, exclusions, withheld).

    allocations  address -> {"sats", "txids"}, after the tainted-destination
                 pass and before the allocation cap
    exclusions   the published list: {"txid", "slot", "reason"} and nothing
                 else, so no ground can leak through it
    withheld     the screening-record entries: every legal exclusion with its
                 grounds, in txid order; never written into --out
    """
    allocations = {}
    exclusions = []
    withheld = []
    slot_of = {}

    for (slot, sig) in enumerate_signatures(rpc, mint, open_slot, cutoff_slot):
        tx = rpc.call("getTransaction",
                      [sig, {"encoding": "jsonParsed",
                             "commitment": "finalized",
                             "maxSupportedTransactionVersion": MAX_TRANSACTION_VERSION}])
        if tx is None:
            raise SystemExit("finalized signature %s has no transaction; "
                             "refusing to guess" % sig)
        if tx.get("meta") is None:
            raise SystemExit("finalized signature %s has no transaction metadata; "
                             "refusing to guess" % sig)
        if tx.get("slot") is not None and tx["slot"] != slot:
            raise SystemExit("signature %s is at slot %d in the signature list and at "
                             "slot %d in its transaction; refusing to guess"
                             % (sig, slot, tx["slot"]))
        verdict = classify_tx(tx, mint, sdn_addresses, project_addresses,
                              project_destinations, excluded_authorities,
                              excluded_destinations)
        if verdict[0] == "excluded":
            if verdict[1] != "no-burn":   # non-burn mint traffic is not a burn attempt
                exclusions.append({"txid": sig, "slot": slot,
                                   "reason": verdict[1]})
            continue
        if verdict[0] == WITHHELD:
            _, address, grounds = verdict
            exclusions.append({"txid": sig, "slot": slot, "reason": WITHHELD})
            withheld.append({"txid": sig, "slot": slot, "destination": address,
                             "grounds": grounds})
            continue
        _, address, sats, _authorities = verdict
        entry = allocations.setdefault(address, {"sats": 0, "txids": []})
        entry["sats"] += sats
        entry["txids"].append(sig)
        slot_of[sig] = slot

    # The tainted-destination rule: a destination that a withheld transaction
    # named in a strictly earlier slot than every credited burn to it is
    # withheld entirely, burns to it by authorities on no list included. A
    # destination's first credited burn fixes it, so a withheld burn naming it
    # in the same or a later slot withholds only itself and a third party
    # cannot withhold an address that is already credited. Destinations only;
    # the clean authority's other burns stand.
    named_by_withheld = {}
    for w in withheld:
        named_by_withheld.setdefault(w["destination"], []).append(w)
    for address in sorted(named_by_withheld):
        entry = allocations.get(address)
        if entry is None:
            continue
        first_credited = min(slot_of[txid] for txid in entry["txids"])
        tainting = sorted(w["txid"] for w in named_by_withheld[address]
                          if w["slot"] < first_credited)
        if not tainting:
            continue
        del allocations[address]
        for txid in entry["txids"]:
            exclusions.append({"txid": txid, "slot": slot_of[txid], "reason": WITHHELD})
            withheld.append({"txid": txid, "slot": slot_of[txid], "destination": address,
                             "grounds": [{"ground": "tainted-destination",
                                          "destination": address,
                                          "tainted_by": tainting}]})

    for entry in allocations.values():
        entry["txids"].sort()
    exclusions.sort(key=lambda e: e["txid"])
    withheld.sort(key=lambda w: w["txid"])
    return allocations, exclusions, withheld


def apply_allocation_cap(allocations, cap=None):
    """SPEC.md, the allocation cap: at most `cap` aggregated allocations are committed.

    Block 1 has a fixed maximum size, so the committed vector must have a
    fixed maximum length or a flood of minimum burns to distinct addresses
    would produce a list no valid block can carry (a veto for the price of
    the burns). The rule is deterministic and published: order by amount,
    largest first, ties by address ascending; keep the first `cap`; the rest
    are excluded with reason code `over-cap`, one exclusion entry per
    contributing txid. Returns (committed, over_cap_exclusions).
    """
    if cap is None:
        cap = MAX_ALLOCATION_OUTPUTS
    if len(allocations) <= cap:
        return allocations, []
    ranked = sorted(allocations.items(),
                    key=lambda item: (-item[1]["sats"], item[0]))
    committed = dict(ranked[:cap])
    over_cap = []
    for address, entry in ranked[cap:]:
        for txid in entry["txids"]:
            over_cap.append({"txid": txid, "reason": "over-cap",
                             "address": address, "sats": entry["sats"]})
    return committed, over_cap


def build_outputs(allocations):
    """Lexicographic aggregation (the committed order is sorted by address),
    mapped to the exact consensus outputs. The caller applies the allocation
    cap first; this function refuses a vector the cap should have bounded."""
    if len(allocations) > MAX_ALLOCATION_OUTPUTS:
        raise SystemExit("%d allocations exceed the cap of %d; apply_allocation_cap "
                         "was not run" % (len(allocations), MAX_ALLOCATION_OUTPUTS))
    outputs = []
    for address in sorted(allocations):
        sats = allocations[address]["sats"]
        program = decode_v1_address(ADDRESS_HRP, address)
        assert program is not None  # classify_tx validated it
        script = v1_script(program)
        if is_block_commitment_shape(script):
            raise SystemExit(
                "allocation %s has a block-commitment-shaped script; "
                "ConnectBlock would strip it from the committed range" % address)
        floor = utxo_cost_floor(script)
        if sats < floor:
            raise SystemExit(
                "allocation %s = %d sats is below the utxo-cost floor %d; "
                "committing it would make the migration height unmineable "
                "under an active UTXO_COST" % (address, sats, floor))
        outputs.append((sats, script))
    total = sum(sats for (sats, _) in outputs)
    if total > MAX_MONEY - MAX_BLOCK_SUBSIDY:
        raise SystemExit("aggregate allocation %d exceeds %d, the per-tx MAX_MONEY bound "
                         "less the block subsidy the same coinbase pays"
                         % (total, MAX_MONEY - MAX_BLOCK_SUBSIDY))
    size = len(ser_txout_vector(outputs))
    if size > MAX_OUTPUTS_SERIALIZED_BYTES:
        raise SystemExit("serialized output vector is %d bytes, over the %d-byte "
                         "bound derived from MAX_BLOCK_BASE_SIZE; block 1 could not "
                         "carry it" % (size, MAX_OUTPUTS_SERIALIZED_BYTES))
    return outputs, total


def canonical_json(obj):
    return json.dumps(obj, sort_keys=True, indent=1) + "\n"


def build_screening_record(withheld, inputs, mint, window_open_slot, cutoff_slot,
                           freeze_slot, commitment_hash, exclusions_sha256, *,
                           provisional):
    """The unpublished record behind every `withheld` entry: the grounds,
    the exact list files that produced them and the published artifact set
    they belong to. Deterministic (no clock), so a re-run reproduces it.
    `inputs` maps a name to (path, sha256); `freeze_slot` is None for a
    provisional run made before the freeze slot is known."""
    return {
        "record": "genesis-migration screening record",
        "published_code": WITHHELD,
        "retention": "five years from block 1",
        "tool_version": TOOL_VERSION,
        "mint": mint,
        "window_open_slot": window_open_slot,
        "cutoff_slot": cutoff_slot,
        "freeze_slot": freeze_slot,
        "provisional": provisional,
        "hash_migration_outputs": commitment_hash,
        "exclusions_sha256": exclusions_sha256,
        "inputs": {name: {"file": os.path.basename(path), "sha256": sha}
                   for name, (path, sha) in sorted(inputs.items())},
        "entries": withheld,
    }


def record_path_is_outside(out_dir, record_path):
    """True when the screening record would not land inside the published
    artifact directory or a subdirectory of it."""
    out = os.path.realpath(out_dir)
    record = os.path.realpath(record_path)
    return os.path.commonpath([out, record]) != out


def main():
    ap = argparse.ArgumentParser(description="Genesis-migration snapshot tool")
    ap.add_argument("--rpc-url", help="Solana JSON-RPC endpoint")
    ap.add_argument("--mint", required=True, help="pSOQ mint address")
    ap.add_argument("--window-open-slot", type=int, required=True)
    ap.add_argument("--freeze-slot", type=int,
                    help="the last slot of the window; required for a final run. Optional "
                         "with --provisional, which then refuses once the finalized chain "
                         "has reached it")
    ap.add_argument("--out", required=True, help="output directory")
    ap.add_argument("--sdn-addresses",
                    help="file of OFAC SDN digital-currency addresses, one per line "
                         "(sdn_extract.py output); required for every run")
    ap.add_argument("--project-addresses", required=True,
                    help="published file of project-controlled Solana addresses, "
                         "one per line; their burns never allocate")
    ap.add_argument("--project-destinations", required=True,
                    help="published file of project-controlled Soqucoin addresses, "
                         "one per line; a memo naming one is never credited; "
                         "may list no addresses; its sha256 is in commitment.txt")
    ap.add_argument("--excluded-authorities", required=True,
                    help="published file of Solana addresses whose burns are withheld; "
                         "may list no addresses; its sha256 is in commitment.txt")
    ap.add_argument("--excluded-destinations", required=True,
                    help="published file of Soqucoin addresses to which nothing is "
                         "allocated; may list no addresses; its sha256 is in "
                         "commitment.txt")
    ap.add_argument("--screening-record",
                    help="path for the UNPUBLISHED screening record, the grounds behind "
                         "every withheld entry; required for a final run; refused "
                         "inside --out")
    ap.add_argument("--provisional", action="store_true",
                    help="cutoff at the latest finalized slot, for a draft list during the "
                         "window; commitment.txt then reads provisional=yes")
    ap.add_argument("--rpc-corpus", help="replay canned RPC responses (offline)")
    ap.add_argument("--dump-corpus", help="record RPC responses for replay")
    ap.add_argument("--cache",
                    help="persistent getTransaction cache (JSON); finalized transactions "
                         "never change, so repeated provisional runs fetch only new "
                         "signatures. Use one cache per provider at the final run")
    args = ap.parse_args()

    corpus = None
    if args.rpc_corpus:
        with open(args.rpc_corpus) as f:
            corpus = json.load(f)
    elif not args.rpc_url:
        ap.error("--rpc-url is required without --rpc-corpus")
    rpc = RpcClient(args.rpc_url, corpus=corpus, dump_path=args.dump_corpus,
                    cache_path=args.cache)

    if args.freeze_slot is None and not args.provisional:
        ap.error("a final run requires --freeze-slot")
    if not args.sdn_addresses:
        ap.error("every run requires --sdn-addresses (the SDN screen applies to "
                 "every draft and to the final run)")
    if args.freeze_slot is not None and args.window_open_slot > args.freeze_slot:
        ap.error("--window-open-slot is after --freeze-slot")
    if not args.screening_record and not args.provisional:
        ap.error("a final run requires --screening-record (the ground behind "
                 "every withheld entry is recorded, unpublished, before any commitment)")
    if args.screening_record and not record_path_is_outside(args.out, args.screening_record):
        ap.error("--screening-record must not be inside --out: the screening record is "
                 "never part of the published artifact set")
    sdn_addresses, sdn_sha = load_address_file(args.sdn_addresses)
    project_addresses, project_sha = load_address_file(args.project_addresses)
    if not project_addresses:
        ap.error("--project-addresses lists no addresses")
    project_destinations, destinations_sha = load_address_file(args.project_destinations)
    project_destinations = {a.lower() for a in project_destinations}
    excluded_authorities, authorities_sha = load_address_file(args.excluded_authorities)
    excluded_destinations, excluded_destinations_sha = \
        load_address_file(args.excluded_destinations)
    excluded_destinations = {a.lower() for a in excluded_destinations}

    # The provider's finalized slot decides the cutoff of a provisional run and
    # gates a final run: every slot of the window must be finalized before a
    # final run reads it, and a provisional run never reaches the freeze slot,
    # so no draft can pass for the final set.
    latest = rpc.call("getSlot", [{"commitment": "finalized"}])
    if not isinstance(latest, int) or isinstance(latest, bool) or latest < 0:
        raise SystemExit("malformed getSlot answer: %r" % (latest,))
    if latest < args.window_open_slot:
        raise SystemExit("the provider's finalized slot %d is below the window open "
                         "slot %d; there is no window to read yet"
                         % (latest, args.window_open_slot))
    if args.provisional:
        if args.freeze_slot is not None and latest >= args.freeze_slot:
            raise SystemExit("the finalized chain has reached the freeze slot %d; the "
                             "final run is made without --provisional" % args.freeze_slot)
        cutoff = latest
    else:
        if latest < args.freeze_slot:
            raise SystemExit("the provider's finalized slot %d is below the freeze slot "
                             "%d; a final run needs the whole window finalized"
                             % (latest, args.freeze_slot))
        cutoff = args.freeze_slot

    allocations, exclusions, withheld = run_snapshot(
        rpc, args.mint, args.window_open_slot, cutoff, sdn_addresses,
        project_addresses, project_destinations, excluded_authorities,
        excluded_destinations)
    allocations, over_cap = apply_allocation_cap(allocations)
    exclusions = sorted(exclusions + over_cap, key=lambda e: e["txid"])
    outputs, total = build_outputs(allocations)
    commitment_hash = hash_migration_outputs(outputs)

    alloc_json = canonical_json(allocations)
    excl_json = canonical_json(exclusions)
    excl_sha = hashlib.sha256(excl_json.encode()).hexdigest()
    if args.screening_record:
        record = build_screening_record(
            withheld,
            {"sdn_addresses": (args.sdn_addresses, sdn_sha),
             "project_addresses": (args.project_addresses, project_sha),
             "project_destinations": (args.project_destinations, destinations_sha),
             "excluded_authorities": (args.excluded_authorities, authorities_sha),
             "excluded_destinations": (args.excluded_destinations,
                                       excluded_destinations_sha)},
            args.mint, args.window_open_slot, cutoff, args.freeze_slot,
            commitment_hash, excl_sha, provisional=args.provisional)
        # The record is readable by its owner alone: created 0600, and an
        # existing file is set to 0600 before a byte of this run is written.
        # A directory the tool creates for it is 0700.
        record_dir = os.path.dirname(os.path.abspath(args.screening_record))
        os.makedirs(record_dir, mode=0o700, exist_ok=True)
        fd = os.open(args.screening_record, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w") as f:
            os.fchmod(f.fileno(), 0o600)
            f.write(canonical_json(record))
    os.makedirs(args.out, exist_ok=True)
    with open(os.path.join(args.out, "allocations.json"), "w") as f:
        f.write(alloc_json)
    with open(os.path.join(args.out, "exclusions.json"), "w") as f:
        f.write(excl_json)
    outputs_hex = ser_txout_vector(outputs).hex() + "\n"
    with open(os.path.join(args.out, "outputs.hex"), "w") as f:
        f.write(outputs_hex)
    commitment = (
        "hash_migration_outputs=%s\n"
        "n_migration_total=%d\n"
        "allocation_count=%d\n"
        "allocation_cap=%d\n"
        "over_cap_count=%d\n"
        "withheld_count=%d\n"
        "window_open_slot=%d\n"
        "cutoff_slot=%d\n"
        "freeze_slot=%s\n"
        "provisional=%s\n"
        "tool_version=%s\n"
        "mint=%s\n"
        "allocations_sha256=%s\n"
        "exclusions_sha256=%s\n"
        "outputs_sha256=%s\n"
        "sdn_file_sha256=%s\n"
        "project_file_sha256=%s\n"
        "project_destinations_sha256=%s\n"
        "excluded_authorities_sha256=%s\n"
        "excluded_destinations_sha256=%s\n"
    ) % (commitment_hash, total, len(outputs), MAX_ALLOCATION_OUTPUTS,
         len({e["address"] for e in over_cap}), len(withheld), args.window_open_slot,
         cutoff, "unknown" if args.freeze_slot is None else args.freeze_slot,
         "yes" if args.provisional else "no",
         TOOL_VERSION, args.mint,
         hashlib.sha256(alloc_json.encode()).hexdigest(), excl_sha,
         hashlib.sha256(outputs_hex.encode()).hexdigest(), sdn_sha, project_sha,
         destinations_sha, authorities_sha, excluded_destinations_sha)
    with open(os.path.join(args.out, "commitment.txt"), "w") as f:
        f.write(commitment)
    rpc.write_dump()
    sys.stdout.write(commitment)


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
# Copyright (c) 2026 Soqucoin Labs Inc.
# Distributed under the MIT software license.
#
# Check of the genesis-migration snapshot's re-run before the constants are
# fixed (SPEC.md, legal exclusions).
#
# The final run at the freeze is repeated when the constants are fixed, with
# that day's SDN release and any update to the published legal lists. The notice
# says in advance that the final hash may differ from the last published
# list by exactly those exclusions. This script is that sentence as a check:
# the new artifact set may differ from the previous one ONLY by allocations
# removed or reduced, every transaction an allocation loses now `withheld`.
# Anything else (an allocation added, increased or otherwise changed, a structural verdict that moved, a different
# window, a different project list or mint, a provisional run) fails, and the
# constants are not fixed until the difference is published and explained.
# There is no manual reconciliation.
#
# Each run is also checked against its own files: outputs.hex and every line
# of commitment.txt that is a function of the run's files (the hash, the
# total, the counts and the hashes of those files) are recomputed from
# allocations.json and exclusions.json as snapshot.py computes them, so the
# constants compiled in are the ones the compared allocations produce.
#
# A reduction is checked for its shape, not its size: allocations.json
# carries no per-transaction amounts. The amounts come from the chain and are
# checked by re-running the tool from the published inputs, which two
# providers do with byte-identical commitment.txt.
#
#   python3 compare_runs.py <previous-dir> <new-dir>
#
# Exit 0 when the new set is acceptable; 1 with every problem listed.
#
# One case fails on purpose: if the allocation cap bound at the freeze and a
# withheld removal frees a slot, the deterministic re-run commits the next
# allocation in rank, which is an addition. The cap is not expected to bind
# (about 880 holders); if it does and this happens, the check fails as it
# does for any other difference.

import hashlib
import json
import os
import sys

from serialize import hash_migration_outputs, ser_txout_vector
from snapshot import WITHHELD, build_outputs

# Lines of commitment.txt that must not move between the two runs. The SDN
# file and the two legal lists MAY move: they are what the re-run is for.
FIXED_LINES = ("window_open_slot", "cutoff_slot", "freeze_slot", "tool_version", "mint",
               "allocation_cap", "project_file_sha256", "project_destinations_sha256")


def read_commitment(path):
    values = {}
    with open(path) as f:
        for line in f:
            line = line.strip()
            if line and "=" in line:
                key, value = line.split("=", 1)
                values[key] = value
    return values


def read_run(directory):
    """The run's files: allocations.json and exclusions.json parsed, each with
    the sha256 of its bytes on disk; outputs.hex as bytes; commitment.txt as a
    dict."""
    run = {}
    for name in ("allocations", "exclusions"):
        with open(os.path.join(directory, name + ".json"), "rb") as f:
            raw = f.read()
        run[name] = json.loads(raw.decode())
        run[name + "_sha256"] = hashlib.sha256(raw).hexdigest()
    with open(os.path.join(directory, "outputs.hex"), "rb") as f:
        run["outputs_hex"] = f.read()
    run["commitment"] = read_commitment(os.path.join(directory, "commitment.txt"))
    return run


def self_check(label, run):
    """The problems of one run against its own files: outputs.hex and the
    commitment lines recomputed the way snapshot.py computes them."""
    try:
        outputs, total = build_outputs(run["allocations"])
    except SystemExit as e:
        return ["%s run's allocations.json is refused: %s" % (label, e)]
    outputs_hex = (ser_txout_vector(outputs).hex() + "\n").encode()
    exclusions = run["exclusions"]
    expected = {
        "hash_migration_outputs": hash_migration_outputs(outputs),
        "n_migration_total": str(total),
        "allocation_count": str(len(outputs)),
        "over_cap_count": str(len({e["address"] for e in exclusions
                                   if e["reason"] == "over-cap"})),
        "withheld_count": str(sum(1 for e in exclusions if e["reason"] == WITHHELD)),
        "allocations_sha256": run["allocations_sha256"],
        "exclusions_sha256": run["exclusions_sha256"],
        "outputs_sha256": hashlib.sha256(outputs_hex).hexdigest(),
    }
    problems = []
    for key, value in sorted(expected.items()):
        if run["commitment"].get(key) != value:
            problems.append("%s run's %s is %s; its files give %s"
                            % (label, key, run["commitment"].get(key), value))
    if run["outputs_hex"] != outputs_hex:
        problems.append("%s run's outputs.hex is not the serialization of its "
                        "allocations.json" % label)
    return problems


def compare(previous_dir, new_dir):
    """Returns the list of problems; empty means each run matches its own
    files and the new run differs from the previous one by withholding alone:
    allocations removed or reduced, every transaction an allocation loses
    withheld in the new run."""
    prev_run, new_run = read_run(previous_dir), read_run(new_dir)
    prev_alloc, prev_excl, prev_c = (prev_run["allocations"], prev_run["exclusions"],
                                     prev_run["commitment"])
    new_alloc, new_excl, new_c = (new_run["allocations"], new_run["exclusions"],
                                  new_run["commitment"])
    problems = self_check("previous", prev_run) + self_check("new", new_run)

    for key in FIXED_LINES:
        for label, commitment in (("previous", prev_c), ("new", new_c)):
            if key not in commitment:
                problems.append("%s run's commitment.txt has no %s line" % (label, key))
        if prev_c.get(key) != new_c.get(key):
            problems.append("%s moved: %s -> %s" % (key, prev_c.get(key), new_c.get(key)))
    for label, commitment in (("previous", prev_c), ("new", new_c)):
        if commitment.get("provisional") != "no":
            problems.append("%s run is provisional; only final runs are compared" % label)

    new_withheld = {e["txid"] for e in new_excl if e["reason"] == WITHHELD}

    for address, entry in sorted(new_alloc.items()):
        if address not in prev_alloc:
            problems.append("allocation added: %s" % address)
        elif prev_alloc[address] != entry:
            # A wallet withheld after the freeze that burned to an address after
            # its first credited burn loses its own burns alone, so the address
            # keeps the rest: a reduction whose every dropped transaction is
            # withheld, with nothing added.
            prev = prev_alloc[address]
            dropped = [t for t in prev["txids"] if t not in entry["txids"]]
            added = [t for t in entry["txids"] if t not in prev["txids"]]
            reduced = (not added and dropped and entry["sats"] < prev["sats"]
                       and all(t in new_withheld for t in dropped))
            if not reduced:
                problems.append("allocation changed: %s %s -> %s"
                                % (address, prev, entry))
    for address, entry in sorted(prev_alloc.items()):
        if address in new_alloc:
            continue
        missing = [t for t in entry["txids"] if t not in new_withheld]
        if missing:
            problems.append("allocation removed without a withheld entry for every "
                            "transaction: %s (%s)" % (address, ", ".join(missing)))

    prev_by_txid = {e["txid"]: e for e in prev_excl}
    new_by_txid = {e["txid"]: e for e in new_excl}
    for txid, entry in sorted(prev_by_txid.items()):
        if txid not in new_by_txid:
            problems.append("exclusion disappeared: %s (%s)" % (txid, entry["reason"]))
        elif (new_by_txid[txid]["reason"] != entry["reason"]
              and new_by_txid[txid]["reason"] != WITHHELD):
            problems.append("exclusion changed: %s %s -> %s"
                            % (txid, entry["reason"], new_by_txid[txid]["reason"]))
    for txid, entry in sorted(new_by_txid.items()):
        if txid not in prev_by_txid and entry["reason"] != WITHHELD:
            problems.append("new exclusion that is not withheld: %s (%s)"
                            % (txid, entry["reason"]))
    return problems


def main():
    if len(sys.argv) != 3:
        raise SystemExit("usage: compare_runs.py <previous-dir> <new-dir>")
    problems = compare(sys.argv[1], sys.argv[2])
    if problems:
        for problem in problems:
            print("FAIL " + problem)
        raise SystemExit(1)
    print("OK: each run matches its own files, and the new run differs from the previous "
          "one by withheld removals alone")


if __name__ == "__main__":
    main()

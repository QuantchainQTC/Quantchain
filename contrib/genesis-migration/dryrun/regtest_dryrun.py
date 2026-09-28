#!/usr/bin/env python3
# Copyright (c) 2026 Soqucoin Labs Inc.
# Distributed under the MIT software license.
#
# Regtest half of the genesis-migration end-to-end dry run.
#
# Two phases, run against a real soqucoind:
#
#   addresses   start a regtest node with a wallet, hand out two fresh sq1
#               addresses (the destinations the devnet burns will name), stop.
#               The datadir is kept so the same wallet can later see and spend
#               the allocations.
#
#   arm         given the snapshot tool's output directory: start node 0 armed
#               with -migrationoutputs=<outputs.hex> -migrationheight=H on the
#               kept wallet datadir, start node 1 UNARMED and connected to it,
#               mine to H, and check
#                 - node 0's arming log hash equals commitment.txt (the
#                   cross-language KAT on the real snapshot data),
#                 - the coinbase at H carries exactly the committed outputs,
#                 - node 1 rejects block H and stays at H-1 (arming is a hard
#                   fork: the unarmed node forks off),
#                 - the allocation is not spendable before coinbase maturity
#                   and is spendable after it (regtest: 60 blocks),
#               then write run-log.json with every observed value.
#
# Standard library only. The node binary is $SOQUCOIND or <repo>/src/soqucoind.

import argparse
import base64
import json
import os
import shutil
import subprocess
import sys
import time
import urllib.error
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.abspath(os.path.join(HERE, "..", "..", ".."))
sys.path.insert(0, os.path.join(HERE, ".."))
from bech32m import decode_v1_address          # noqa: E402
from serialize import hash_migration_outputs   # noqa: E402

REGTEST_MATURITY = 60
COIN = 100_000_000
NODE_PORTS = {0: (18801, 18802), 1: (18811, 18812)}   # (p2p, rpc)


class Node(object):
    def __init__(self, index, datadir, extra_args=()):
        self.index = index
        self.datadir = datadir
        self.p2p, self.rpcport = NODE_PORTS[index]
        self.user, self.password = "dryrun%d" % index, "dryrunpass%d" % index
        self.extra_args = list(extra_args)
        self.proc = None

    def start(self, binary):
        os.makedirs(self.datadir, exist_ok=True)
        args = [binary, "-regtest", "-datadir=" + self.datadir, "-server", "-listen",
                "-port=%d" % self.p2p, "-rpcport=%d" % self.rpcport,
                "-rpcuser=" + self.user, "-rpcpassword=" + self.password,
                "-discover=0", "-dnsseed=0", "-listenonion=0", "-printtoconsole=0",
                "-debug=1", "-keypool=1"] + self.extra_args
        self.proc = subprocess.Popen(args, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
        deadline = time.time() + 60
        while time.time() < deadline:
            if self.proc.poll() is not None:
                raise SystemExit("node %d exited at startup: %s"
                                 % (self.index, self.proc.stderr.read().decode()))
            try:
                self.rpc("getblockcount")
                return
            except Exception:
                time.sleep(0.5)
        raise SystemExit("node %d did not answer RPC within 60s" % self.index)

    def rpc(self, method, *params):
        body = json.dumps({"jsonrpc": "1.0", "id": "dryrun", "method": method,
                           "params": list(params)}).encode()
        auth = base64.b64encode(("%s:%s" % (self.user, self.password)).encode()).decode()
        req = urllib.request.Request("http://127.0.0.1:%d/" % self.rpcport, data=body,
                                     headers={"Content-Type": "application/json",
                                              "Authorization": "Basic " + auth})
        try:
            with urllib.request.urlopen(req, timeout=120) as resp:
                reply = json.loads(resp.read().decode())
        except urllib.error.HTTPError as e:
            reply = json.loads(e.read().decode())
        if reply.get("error"):
            raise RpcError(reply["error"])
        return reply["result"]

    def stop(self):
        if self.proc is None:
            return
        try:
            self.rpc("stop")
        except (OSError, ValueError, RpcError):
            # The node may already be down or refuse the call; wait() and kill()
            # below stop it either way.
            pass
        try:
            self.proc.wait(timeout=60)
        except subprocess.TimeoutExpired:
            self.proc.kill()
        self.proc = None

    def debug_log(self):
        with open(os.path.join(self.datadir, "regtest", "debug.log")) as f:
            return f.read()


class RpcError(Exception):
    pass


def wait_until(predicate, timeout=60, what="condition"):
    deadline = time.time() + timeout
    while time.time() < deadline:
        if predicate():
            return
        time.sleep(0.5)
    raise SystemExit("timed out waiting for %s" % what)


def coinbase_vout(node, height):
    block = node.rpc("getblock", node.rpc("getblockhash", height))
    return node.rpc("getrawtransaction", block["tx"][0], 1)["vout"], block


def read_commitment(path):
    values = {}
    with open(path) as f:
        for line in f:
            if "=" in line:
                k, v = line.rstrip("\n").split("=", 1)
                values[k] = v
    return values


def phase_addresses(args, binary):
    node = Node(0, os.path.join(args.workdir, "node0"))
    node.start(binary)
    try:
        addresses = [node.rpc("getnewaddress") for _ in range(2)]
        for a in addresses:
            if decode_v1_address("sq", a) is None:
                raise SystemExit("wallet handed out a non-sq1 address: %s" % a)
    finally:
        node.stop()
    out = {"address1": addresses[0], "address2": addresses[1],
           "note": "regtest wallet, HRP sq, witness v1; datadir kept for the arm phase"}
    with open(os.path.join(args.workdir, "addresses.json"), "w") as f:
        json.dump(out, f, indent=1)
    print(json.dumps(out, indent=1))


def phase_arm(args, binary):
    snap = args.snapshot_dir
    with open(os.path.join(snap, "allocations.json")) as f:
        allocations = json.load(f)
    with open(os.path.join(snap, "outputs.hex")) as f:
        outputs_hex = f.read().strip()
    commitment = read_commitment(os.path.join(snap, "commitment.txt"))
    if commitment.get("provisional") != "no":
        raise SystemExit("commitment.txt is a PROVISIONAL run (cutoff before the freeze "
                         "slot); only a final run may be armed. Re-run the snapshot "
                         "without --provisional.")
    expected_hash = commitment["hash_migration_outputs"]
    expected_total = int(commitment["n_migration_total"])
    H = args.height
    log = {"height": H, "commitment": commitment, "checks": []}

    def check(name, ok, **detail):
        log["checks"].append(dict(name=name, ok=bool(ok), **detail))
        print(("PASS " if ok else "FAIL ") + name, json.dumps(detail, default=str)[:200])
        if not ok and not args.keep_going:
            raise SystemExit("check failed: " + name)

    # Recompute the hash from the published vector, independently of the tool run.
    ordered = sorted(allocations)
    outputs = [(allocations[a]["sats"], b"\x51\x20" + decode_v1_address("sq", a)) for a in ordered]
    check("published_vector_rehashes_to_commitment",
          hash_migration_outputs(outputs) == expected_hash,
          recomputed=hash_migration_outputs(outputs), committed=expected_hash)

    # Fresh chain, same wallet: copy only wallet.dat out of the addresses-phase
    # datadir so every arm run starts from genesis with the keys the burns named.
    node0_dir = os.path.join(args.workdir, "node0-arm")
    if os.path.isdir(node0_dir):
        shutil.rmtree(node0_dir)
    os.makedirs(os.path.join(node0_dir, "regtest"))
    shutil.copy(os.path.join(args.workdir, "node0", "regtest", "wallet.dat"),
                os.path.join(node0_dir, "regtest", "wallet.dat"))
    node0 = Node(0, node0_dir,
                 ["-migrationoutputs=" + outputs_hex, "-migrationheight=%d" % H])
    node1_dir = os.path.join(args.workdir, "node1")
    if os.path.isdir(node1_dir):
        shutil.rmtree(node1_dir)
    node1 = Node(1, node1_dir, ["-disablewallet=1", "-connect=127.0.0.1:%d" % node0.p2p])
    try:
        node0.start(binary)
        arming = [l for l in node0.debug_log().splitlines()
                  if "Arming regtest genesis-migration rule" in l]
        armed_hash = arming[-1].split("hash=")[-1].strip() if arming else None
        check("node0_arming_log_hash_equals_commitment", armed_hash == expected_hash,
              log_line=arming[-1] if arming else None)

        node1.start(binary)
        wait_until(lambda: node0.rpc("getconnectioncount") >= 1, what="node1 to connect")

        node0.rpc("generate", H - 1)
        wait_until(lambda: node1.rpc("getblockcount") == H - 1, what="node1 to sync to H-1")
        check("both_nodes_at_H_minus_1", node0.rpc("getblockcount") == H - 1 == node1.rpc("getblockcount"))

        # The migration block.
        node0.rpc("generate", 1)
        vout, block = coinbase_vout(node0, H)
        got = [(int(round(o["value"] * COIN)), o["scriptPubKey"]["hex"]) for o in vout[1:1 + len(outputs)]]
        want = [(sats, script.hex()) for (sats, script) in outputs]
        check("coinbase_at_H_carries_committed_outputs_in_order", got == want, got=got, want=want)
        committed_sum = sum(v for (v, _) in got)
        check("committed_sum_equals_n_migration_total", committed_sum == expected_total,
              committed_sum=committed_sum, n_migration_total=expected_total)
        trailing = vout[1 + len(outputs):]
        check("only_zero_value_commitment_outputs_trail", all(o["value"] == 0 for o in trailing),
              trailing=[o["scriptPubKey"]["hex"][:12] for o in trailing])
        log["block_H_hash"] = block["hash"]

        # The hard-fork fact: the unarmed node rejects block H.
        time.sleep(5)
        node1_height = node1.rpc("getblockcount")
        tips = node1.rpc("getchaintips")
        invalid_tip = [t for t in tips if t["hash"] == block["hash"]]
        check("unarmed_node_stays_at_H_minus_1", node1_height == H - 1, node1_height=node1_height)
        check("unarmed_node_marks_block_H_invalid",
              bool(invalid_tip) and invalid_tip[0]["status"] == "invalid", tips=tips)
        node1_log = [l for l in node1.debug_log().splitlines() if "coinbase pays too much" in l]
        check("unarmed_node_logs_coinbase_reject", bool(node1_log), log_lines=node1_log[-2:])

        # Maturity: the allocation is a coinbase output. At H+1 it exists in the
        # UTXO set but the wallet does not offer it (listunspent hides immature
        # coinbase) and a spend is rejected; at H+60 it is offered and spends.
        node0.rpc("generate", 1)
        a1 = ordered[0]
        coinbase_txid = block["tx"][0]
        txout = node0.rpc("gettxout", coinbase_txid, 1)
        check("allocation_exists_in_utxo_set_as_coinbase",
              txout is not None and txout.get("coinbase") is True
              and int(round(txout["value"] * COIN)) == allocations[a1]["sats"], gettxout=txout)
        check("wallet_hides_allocation_before_maturity",
              node0.rpc("listunspent", 0, 9999999, [a1]) == [])
        # Once node 0 announces H+1, node 1 sees a header whose parent it holds
        # invalid and penalises the peer: the operational face of the fork.
        time.sleep(3)
        misbehaving = [l for l in node1.debug_log().splitlines()
                       if "Misbehaving" in l or "prev block invalid" in l]
        check("unarmed_node_penalises_armed_peer", bool(misbehaving), log_lines=misbehaving[-3:])

        # Spend through the wallet's own signing path (the raw-transaction RPC
        # does not produce the witness this chain requires). Lock every other
        # unspent output so the only coin the wallet can select is the allocation.
        spend_to = node0.rpc("getnewaddress")
        spend_amount = round(allocations[a1]["sats"] / COIN - 1.0, 8)

        def lock_everything_but_allocation():
            others = [{"txid": u["txid"], "vout": u["vout"]}
                      for u in node0.rpc("listunspent", 0, 9999999)
                      if not (u["txid"] == coinbase_txid and u["vout"] == 1)]
            if others:
                node0.rpc("lockunspent", False, others)
            return len(others)

        locked = lock_everything_but_allocation()
        premature_error = None
        try:
            node0.rpc("sendtoaddress", spend_to, spend_amount)
        except RpcError as e:
            premature_error = str(e)
        check("wallet_refuses_to_spend_allocation_before_maturity",
              premature_error is not None and "Insufficient funds" in premature_error,
              error=premature_error, other_outputs_locked=locked,
              scope="wallet-level refusal; the consensus premature-spend reject is "
                    "upstream behaviour covered by the existing test suite")

        node0.rpc("generate", REGTEST_MATURITY - 1)
        height_now = node0.rpc("getblockcount")
        matured = [u for u in node0.rpc("listunspent", 0, 9999999, [a1]) if u["txid"] == coinbase_txid]
        check("allocation_spendable_at_maturity",
              bool(matured) and matured[0].get("spendable") is True,
              height=height_now, confirmations=matured[0]["confirmations"] if matured else None)
        locked = lock_everything_but_allocation()
        spend_txid = node0.rpc("sendtoaddress", spend_to, spend_amount)
        node0.rpc("generate", 1)
        spend = node0.rpc("getrawtransaction", spend_txid, 1)
        spent_allocation = any(v.get("txid") == coinbase_txid and v.get("vout") == 1 for v in spend["vin"])
        check("allocation_spend_confirmed_from_the_allocation_output",
              spend.get("confirmations", 0) >= 1 and spent_allocation,
              spend_txid=spend_txid, vin=[(v.get("txid"), v.get("vout")) for v in spend["vin"]],
              other_outputs_locked=locked)
        log["final_height_node0"] = node0.rpc("getblockcount")
        log["final_height_node1"] = node1.rpc("getblockcount")
    finally:
        node0.stop()
        node1.stop()

    log["all_passed"] = all(c["ok"] for c in log["checks"])
    with open(os.path.join(args.workdir, "run-log.json"), "w") as f:
        json.dump(log, f, indent=1, default=str)
    print("all_passed" if log["all_passed"] else "SOME CHECKS FAILED", "-> run-log.json")
    if not log["all_passed"]:
        sys.exit(1)


def main():
    ap = argparse.ArgumentParser(description="Regtest half of the migration dry run")
    ap.add_argument("phase", choices=["addresses", "arm"])
    ap.add_argument("--workdir", required=True, help="kept between phases (wallet datadir lives here)")
    ap.add_argument("--snapshot-dir", help="snapshot tool output directory (arm phase)")
    ap.add_argument("--height", type=int, default=10, help="regtest activation height H (arm phase)")
    ap.add_argument("--keep-going", action="store_true", help="record failed checks instead of stopping")
    args = ap.parse_args()
    binary = os.environ.get("SOQUCOIND", os.path.join(REPO, "src", "soqucoind"))
    if not os.path.exists(binary):
        raise SystemExit("soqucoind not found at %s (set SOQUCOIND)" % binary)
    os.makedirs(args.workdir, exist_ok=True)
    if args.phase == "addresses":
        phase_addresses(args, binary)
    else:
        if not args.snapshot_dir:
            ap.error("--snapshot-dir is required for the arm phase")
        phase_arm(args, binary)


if __name__ == "__main__":
    main()

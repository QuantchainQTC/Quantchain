#!/usr/bin/env python3
# Copyright (c) 2026 Soqucoin Labs Inc.
# Distributed under the MIT software license.
#
# Devnet fixture for the genesis-migration end-to-end dry run.
#
# Builds, on Solana devnet, the burn history the snapshot tool will be run
# against: a throwaway Token-2022 mint with 6 decimals, several fresh holder
# wallets, and one burn per eligibility case, each made with the stock
# `spl-token burn --with-memo` command so the path is exactly the one a holder
# would use with no project software in it. Records every public key, signature
# and slot into run.json; never writes a private key anywhere but the
# throwaway keypair files in the run directory.
#
# Cases (label -> expected snapshot verdict):
#   holder_a   two burns, valid memo to address 1      eligible, aggregated
#   holder_b   one burn, valid memo to address 2       eligible
#   project    one burn, valid memo to address 1       excluded project-address
#   malformed  one burn, memo not in SOQMIG1 form      excluded malformed-memo
#   dust       one burn below 1 pSOQ, valid memo       excluded below-dust-floor
#   nomemo     one burn, no memo                       excluded no-memo
#   sanctioned one burn, valid memo, address planted   withheld (SDN match)
#              into a copy of the SDN screen file
#
# Requires: solana and spl-token CLIs on PATH, the default CLI keypair funded
# with devnet SOL (it pays for mint creation, account creation and funding).
#
#   python3 devnet_fixture.py --out /tmp/gm-dryrun/run1 --address1 sq1... --address2 sq1...

import argparse
import json
import os
import subprocess
import sys
import time
import urllib.request

DEVNET_RPC = "https://api.devnet.solana.com"
WALLET_FUND_SOL = "0.02"
LABELS = ["holder_a", "holder_b", "project", "malformed", "dust", "nomemo", "sanctioned"]


def sh(args, **kw):
    """Run a CLI command, return stdout; raise with both streams on failure."""
    proc = subprocess.run(args, capture_output=True, text=True, **kw)
    if proc.returncode != 0:
        raise SystemExit("command failed: %s\n%s\n%s" % (" ".join(args), proc.stdout, proc.stderr))
    return proc.stdout


def sh_json(args):
    out = sh(args + ["--output", "json"])
    return json.loads(out)


def rpc(method, params):
    body = json.dumps({"jsonrpc": "2.0", "id": 1, "method": method, "params": params}).encode()
    req = urllib.request.Request(DEVNET_RPC, data=body, headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=60) as resp:
        reply = json.loads(resp.read().decode())
    if reply.get("error"):
        raise SystemExit("rpc error %s: %s" % (method, reply["error"]))
    return reply["result"]


def wait_finalized(signature, timeout=180):
    deadline = time.time() + timeout
    while time.time() < deadline:
        res = rpc("getSignatureStatuses", [[signature], {"searchTransactionHistory": True}])
        status = res["value"][0]
        if status and status.get("confirmationStatus") == "finalized":
            if status.get("err"):
                raise SystemExit("transaction %s failed: %s" % (signature, status["err"]))
            return status["slot"]
        time.sleep(3)
    raise SystemExit("transaction %s not finalized after %ds" % (signature, timeout))


def main():
    ap = argparse.ArgumentParser(description="Build the devnet burn fixture for the migration dry run")
    ap.add_argument("--out", required=True, help="run directory (created)")
    ap.add_argument("--address1", required=True, help="Soqucoin sq1 destination address 1")
    ap.add_argument("--address2", required=True, help="Soqucoin sq1 destination address 2")
    ap.add_argument("--mint", help="reuse an existing devnet Token-2022 mint (6 decimals) instead of creating one")
    args = ap.parse_args()

    os.makedirs(args.out, exist_ok=True)
    payer = sh(["solana", "address"]).strip()
    # spl-token needs the fee payer spelled out when --owner is someone else.
    payer_keypair = [l.split(":", 1)[1].strip() for l in sh(["solana", "config", "get"]).splitlines()
                     if l.startswith("Keypair Path")][0]
    run = {"network": "devnet", "rpc": DEVNET_RPC, "fee_payer": payer,
           "address1": args.address1, "address2": args.address2,
           "wallets": {}, "burns": []}

    # 1. Mint.
    if args.mint:
        run["mint"] = args.mint
        run["mint_created_here"] = False
    else:
        created = sh_json(["spl-token", "create-token", "--program-2022", "--decimals", "6"])
        run["mint"] = created["commandOutput"]["address"]
        run["mint_created_here"] = True
        run["mint_create_signature"] = created["commandOutput"]["transactionData"]["signature"]
    mint = run["mint"]
    print("mint", mint, file=sys.stderr)

    # 2. Wallets: fresh keypair, funded, token account, tokens minted.
    for label in LABELS:
        keyfile = os.path.join(args.out, "wallet-%s.json" % label)
        if not os.path.exists(keyfile):
            sh(["solana-keygen", "new", "--no-bip39-passphrase", "--silent", "--outfile", keyfile])
        pubkey = sh(["solana-keygen", "pubkey", keyfile]).strip()
        if sh(["solana", "balance", pubkey]).strip().startswith("0 "):
            sh(["solana", "transfer", "--allow-unfunded-recipient", pubkey, WALLET_FUND_SOL,
                "--commitment", "confirmed"])
        accounts = [a for a in sh_json(["spl-token", "accounts", "--owner", pubkey])["accounts"]
                    if a["mint"] == mint]
        if not accounts:
            sh_json(["spl-token", "create-account", mint, "--owner", pubkey,
                     "--fee-payer", payer_keypair])
            accounts = [a for a in sh_json(["spl-token", "accounts", "--owner", pubkey])["accounts"]
                        if a["mint"] == mint]
        ata = accounts[0]["address"]
        mint_sig = None
        if accounts[0]["tokenAmount"]["amount"] == "0":
            mint_sig = sh_json(["spl-token", "mint", mint, "100", ata])["signature"]
        run["wallets"][label] = {"pubkey": pubkey, "token_account": ata,
                                 "mint_signature": mint_sig}
        print("wallet", label, pubkey, ata, file=sys.stderr)

    # 3. Burns, each from the holder's own key with the stock CLI.
    a1, a2 = args.address1, args.address2
    plan = [
        ("holder_a", "5", "SOQMIG1:" + a1, "eligible"),
        ("holder_a", "2.5", "SOQMIG1:" + a1, "eligible"),
        ("holder_b", "3", "SOQMIG1:" + a2, "eligible"),
        ("project", "50", "SOQMIG1:" + a1, "project-address"),
        ("malformed", "2", "SOQMIG1:sq1notanaddress", "invalid-address"),
        ("dust", "0.5", "SOQMIG1:" + a1, "below-dust-floor"),
        ("nomemo", "2", None, "no-memo"),
        ("sanctioned", "4", "SOQMIG1:" + a2, "withheld"),
    ]
    for label, amount, memo, expected in plan:
        w = run["wallets"][label]
        keyfile = os.path.join(args.out, "wallet-%s.json" % label)
        cmd = ["spl-token", "burn", w["token_account"], amount,
               "--owner", keyfile, "--fee-payer", keyfile]
        if memo is not None:
            cmd += ["--with-memo", memo]
        res = sh_json(cmd)
        sig = res["signature"]
        run["burns"].append({"label": label, "authority": w["pubkey"], "amount": amount,
                             "memo": memo, "expected": expected, "signature": sig})
        print("burn", label, amount, sig, file=sys.stderr)

    # 4. Finalization and the window bounds.
    for burn in run["burns"]:
        burn["slot"] = wait_finalized(burn["signature"])
    slots = [b["slot"] for b in run["burns"]]
    run["window_open_slot"] = min(slots)
    run["freeze_slot"] = max(slots)
    run["expected_allocations_sats"] = {
        a1.lower(): int((5 + 2.5) * 1_000_000) * 100,
        a2.lower(): 3_000_000 * 100,
    }

    with open(os.path.join(args.out, "run.json"), "w") as f:
        json.dump(run, f, indent=1, sort_keys=True)
    print(json.dumps({"mint": mint, "window_open_slot": run["window_open_slot"],
                      "freeze_slot": run["freeze_slot"], "burns": len(run["burns"])}, indent=1))


if __name__ == "__main__":
    main()

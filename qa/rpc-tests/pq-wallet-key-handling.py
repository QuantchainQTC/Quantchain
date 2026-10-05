#!/usr/bin/env python3
# Copyright (c) 2026 The Soqucoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

"""ML-DSA-44 private-key handling end to end.

Behaviours an integrator relies on:
  1. the string dumpprivkey prints, for a bech32m address, imports with importprivkey;
  2. a file dumpwallet writes restores its keys with importwallet;
  3. a copy made by backupwallet restores the wallet on another node, which signs;
  4. a seed WIF (the SDK's portable secret) imports to the address the SDK derives;
  5. signrawtransaction signs a witness v1 input, with the wallet's key and with a supplied key;
  6. soqucoin-tx sign= signs a witness v1 input with a supplied key, and the node accepts the result.

Checks 1 to 4 cover the key codec (bead yznn); 5 and 6 cover CombineSignatures keeping the v1
witness (bead zt4n). Every check runs and prints its outcome; the test fails if any did not hold.
"""

import hashlib
import json
import os
import shutil
import subprocess

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import *

_B58 = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'


def base58check(version, payload):
    data = bytes([version]) + payload
    data += hashlib.sha256(hashlib.sha256(data).digest()).digest()[:4]
    n = int.from_bytes(data, 'big')
    out = ''
    while n > 0:
        n, r = divmod(n, 58)
        out = _B58[r] + out
    for b in data:
        if b == 0:
            out = _B58[0] + out
        else:
            break
    return out

# sha256("soqucoin") is the SDK's node vector. On regtest (bech32 prefix "sq", shared with mainnet)
# it derives this address, the SDK's own "sq" vector.
SDK_SQ_ADDRESS = 'sq1pa3n373z2lgva3m53nssuwm7jl0dz697uzul7wh55ct7maf00xe4s2m80fs'
REGTEST_SECRET_KEY_PREFIX = 239


def sha256(b):
    import hashlib
    return hashlib.sha256(b).digest()


def rpc_error(fn, *args):
    try:
        fn(*args)
        return None
    except JSONRPCException as e:
        return '%s (%d)' % (e.error['message'], e.error['code'])


class PQWalletKeyHandlingTest(BitcoinTestFramework):

    def __init__(self):
        super().__init__()
        self.setup_clean_chain = True
        self.num_nodes = 2

    def setup_network(self, split=False):
        self.nodes = start_nodes(self.num_nodes, self.options.tmpdir)
        connect_nodes_bi(self.nodes, 0, 1)
        self.is_network_split = False
        self.sync_all()

    def mine(self, n):
        self.sync_all()
        self.nodes[0].generate(n)
        self.sync_all()

    def tx_binary(self):
        soqucoind = os.getenv('SOQUCOIND', 'soqucoind')
        return os.getenv('SOQUCOINTX', os.path.join(os.path.dirname(soqucoind), 'soqucoin-tx'))

    def run_test(self):
        # Coinbase maturity on regtest is 60 blocks.
        self.mine(70)

        results = [
            ('dumpprivkey then importprivkey', self.check_wif_round_trip()),
            ('dumpwallet then importwallet', self.check_dumpwallet()),
            ('backupwallet restored elsewhere', self.check_backupwallet()),
            ('seed WIF imports to the SDK address', self.check_seed_wif()),
            ('signrawtransaction on a v1 input', self.check_signrawtransaction_v1()),
            ('soqucoin-tx sign= on a v1 input', self.check_soqucoin_tx_sign()),
        ]
        print()
        for name, (ok, detail) in results:
            print('%-40s %s' % (name, 'HOLDS' if ok else 'DOES NOT HOLD'))
            for line in detail:
                print('    ' + line)
        failed = [name for name, (ok, _) in results if not ok]
        if failed:
            raise AssertionError('did not hold: ' + '; '.join(failed))

    def check_wif_round_trip(self):
        src, dst = self.nodes[0], self.nodes[1]
        detail = []
        addr = src.getnewaddress()
        detail.append('getnewaddress (bech32m): %s' % addr)
        try:
            wif = src.dumpprivkey(addr)
        except JSONRPCException as e:
            detail.append('dumpprivkey: %s (%d)' % (e.error['message'], e.error['code']))
            return False, detail
        detail.append('dumpprivkey printed %d characters' % len(wif))
        err = rpc_error(dst.importprivkey, wif, '', False)
        if err:
            detail.append('importprivkey of that string: %s' % err)
            return False, detail
        ismine = dst.validateaddress(addr).get('ismine')
        detail.append('importprivkey accepted it; ismine=%s' % ismine)
        return bool(ismine), detail

    def check_dumpwallet(self):
        src, dst = self.nodes[0], self.nodes[1]
        detail = []
        addr = src.getnewaddress()
        path = os.path.join(self.options.tmpdir, 'node0', 'regtest', 'backups', 'node0.dump')
        err = rpc_error(src.dumpwallet, 'node0.dump')
        if err:
            detail.append('dumpwallet: %s' % err)
            return False, detail
        with open(path) as f:
            lines = [l for l in f if l.strip() and not l.startswith('#')]
        detail.append('dumpwallet wrote %d key lines; first field is %d characters' %
                      (len(lines), len(lines[0].split()[0]) if lines else 0))
        err = rpc_error(dst.importwallet, path)
        if err:
            detail.append('importwallet: %s' % err)
            return False, detail
        ismine = dst.validateaddress(addr).get('ismine')
        detail.append('importwallet returned; ismine for an address in the dump: %s' % ismine)
        return bool(ismine), detail

    def check_backupwallet(self):
        src = self.nodes[0]
        detail = []
        addr = src.getnewaddress()
        src.sendtoaddress(addr, 3)
        self.mine(1)
        path = os.path.join(self.options.tmpdir, 'node0', 'regtest', 'backups', 'node0.backup')
        src.backupwallet('node0.backup')

        stop_node(self.nodes[1], 1)
        wallet = os.path.join(self.options.tmpdir, 'node1', 'regtest', 'wallet.dat')
        shutil.copyfile(path, wallet)
        self.nodes[1] = start_node(1, self.options.tmpdir, ['-rescan'])
        connect_nodes_bi(self.nodes, 0, 1)
        node = self.nodes[1]
        ismine = node.validateaddress(addr).get('ismine')
        detail.append("backupwallet copy started as node 1's wallet: ismine=%s, balance %s" %
                      (ismine, node.getbalance()))
        try:
            txid = node.sendtoaddress(self.nodes[0].getnewaddress(), 1)
        except JSONRPCException as e:
            detail.append('sendtoaddress from the restored wallet: %s (%d)' % (e.error['message'], e.error['code']))
            return False, detail
        self.mine(1)
        confs = node.gettransaction(txid)['confirmations']
        detail.append('sendtoaddress from the restored wallet: %d confirmation' % confs)
        return bool(ismine) and confs >= 1, detail

    def check_seed_wif(self):
        dst = self.nodes[1]
        detail = []
        seed = sha256(b'soqucoin')
        wif = base58check(REGTEST_SECRET_KEY_PREFIX, seed + b'\x02')
        detail.append('seed WIF for sha256("soqucoin"): %s' % wif)
        err = rpc_error(dst.importprivkey, wif, '', False)
        if err:
            detail.append('importprivkey of the seed WIF: %s' % err)
            return False, detail
        info = dst.validateaddress(SDK_SQ_ADDRESS)
        detail.append('validateaddress %s: isvalid=%s ismine=%s' %
                      (SDK_SQ_ADDRESS, info.get('isvalid'), info.get('ismine')))
        return bool(info.get('ismine')), detail

    def v1_utxo(self, node):
        # Fund a fresh bech32m address and return its one spendable output.
        addr = node.getnewaddress()
        node.sendtoaddress(addr, 100)
        self.mine(1)
        for u in node.listunspent(1, 9999, [addr]):
            return addr, u
        raise AssertionError('no utxo for %s' % addr)

    def check_signrawtransaction_v1(self):
        src, other = self.nodes[0], self.nodes[1]
        detail = []
        addr, u = self.v1_utxo(src)
        out = src.getnewaddress()
        value = float(u['amount']) - 10.0
        raw = src.createrawtransaction([{'txid': u['txid'], 'vout': u['vout']}], {out: value})

        # The wallet owns the key; signrawtransaction still routes through CombineSignatures.
        signed = src.signrawtransaction(raw)
        detail.append('wallet signrawtransaction complete=%s' % signed.get('complete'))
        if not signed.get('complete'):
            detail.append('errors: %s' % signed.get('errors'))
            return False, detail
        err = rpc_error(src.sendrawtransaction, signed['hex'])
        detail.append('sendrawtransaction: %s' % (err or 'accepted'))
        if err:
            return False, detail

        # A supplied key, on a node that does not own the address.
        addr2, u2 = self.v1_utxo(src)
        wif = src.dumpprivkey(addr2)
        raw2 = src.createrawtransaction([{'txid': u2['txid'], 'vout': u2['vout']}], {src.getnewaddress(): float(u2['amount']) - 10.0})
        prevtx = {'txid': u2['txid'], 'vout': u2['vout'], 'scriptPubKey': u2['scriptPubKey'], 'amount': u2['amount']}
        signed2 = other.signrawtransaction(raw2, [prevtx], [wif])
        detail.append('supplied-key signrawtransaction complete=%s' % signed2.get('complete'))
        if not signed2.get('complete'):
            detail.append('errors: %s' % signed2.get('errors'))
            return False, detail
        err = rpc_error(src.sendrawtransaction, signed2['hex'])
        detail.append('sendrawtransaction of the supplied-key spend: %s' % (err or 'accepted'))
        return err is None, detail

    def check_soqucoin_tx_sign(self):
        src = self.nodes[0]
        detail = []
        txbin = self.tx_binary()
        if not os.path.exists(txbin):
            detail.append('soqucoin-tx not found at %s' % txbin)
            return False, detail

        addr, u = self.v1_utxo(src)
        wif = src.dumpprivkey(addr)
        # Pay back to the same witness v1 program; its scriptPubKey is OP_1 <32-byte program>.
        program = u['scriptPubKey'][4:]  # strip "5120"
        value = float(u['amount']) - 10.0
        prevtxs = [{'txid': u['txid'], 'vout': u['vout'], 'scriptPubKey': u['scriptPubKey'], 'amount': float(u['amount'])}]
        cmd = [txbin, '-regtest', '-create',
               'in=%s:%d' % (u['txid'], u['vout']),
               'outscript=%.8f:1 0x20 0x%s' % (value, program),
               'set=prevtxs:' + json.dumps(prevtxs),
               'set=privatekeys:' + json.dumps([wif]),
               'sign=ALL']
        proc = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True)
        if proc.returncode != 0:
            detail.append('soqucoin-tx sign= failed: %s' % proc.stderr.strip())
            return False, detail
        signed_hex = proc.stdout.strip()
        detail.append('soqucoin-tx sign= produced %d hex characters' % len(signed_hex))
        err = rpc_error(src.sendrawtransaction, signed_hex)
        detail.append('sendrawtransaction of the soqucoin-tx spend: %s' % (err or 'accepted'))
        return err is None, detail


if __name__ == '__main__':
    PQWalletKeyHandlingTest().main()

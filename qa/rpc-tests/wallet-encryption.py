#!/usr/bin/env python3
# Copyright (c) 2026 The Soqucoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

"""Wallet encryption with ML-DSA-44 keys.

encryptwallet, walletpassphrase, walletlock and walletpassphrasechange on node 1, across restarts: a wrong
passphrase is refused and the wallet stays locked; the right one unlocks it and it spends, including from the
key encryptwallet put in the key pool; a timed unlock locks it again; after walletpassphrasechange only the new
passphrase unlocks it.

ENCRYPT_SOQUCOIND, when set, is the binary node 1 runs while encryptwallet executes, so that this build opens a
wallet another build encrypted. The key pool check is skipped then.
"""

import os
import time

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import *

PASSPHRASE = 'a test passphrase of several words'
NEW_PASSPHRASE = 'a second test passphrase of several words'

RPC_WALLET_KEYPOOL_RAN_OUT = -12
RPC_WALLET_UNLOCK_NEEDED = -13
RPC_WALLET_PASSPHRASE_INCORRECT = -14


class WalletEncryptionTest(BitcoinTestFramework):

    def __init__(self):
        super().__init__()
        self.setup_clean_chain = True
        self.num_nodes = 2

    def setup_network(self, split=False):
        self.nodes = start_nodes(self.num_nodes, self.options.tmpdir)
        connect_nodes_bi(self.nodes, 0, 1)
        self.is_network_split = False
        self.sync_all()

    def start_node1(self, binary=None):
        self.nodes[1] = start_node(1, self.options.tmpdir, binary=binary)
        connect_nodes_bi(self.nodes, 0, 1)
        return self.nodes[1]

    def confirm(self, txid):
        self.sync_all()
        self.nodes[0].generate(1)
        self.sync_all()
        assert_equal(self.nodes[1].gettransaction(txid)['confirmations'], 1)

    def assert_locked(self, node):
        assert_equal(node.getwalletinfo()['unlocked_until'], 0)
        assert_raises_jsonrpc(RPC_WALLET_UNLOCK_NEEDED, None,
                              node.sendtoaddress, self.nodes[0].getnewaddress(), 1)

    def run_test(self):
        # Coinbase maturity on regtest is 60 blocks.
        self.nodes[0].generate(70)
        self.sync_all()
        self.confirm(self.nodes[0].sendtoaddress(self.nodes[1].getnewaddress(), 10))

        encrypt_binary = os.getenv('ENCRYPT_SOQUCOIND')
        if encrypt_binary:
            stop_node(self.nodes[1], 1)
            self.start_node1(encrypt_binary)
        self.nodes[1].encryptwallet(PASSPHRASE)
        soqucoind_processes[1].wait()
        node = self.start_node1()
        assert_equal(node.getbalance(), 10)

        # Refused while locked: a wrong passphrase, the passphrase less its last character, and a change of
        # passphrase from a wrong one. The wallet stays locked.
        for wrong in ['not ' + PASSPHRASE, PASSPHRASE[:-1]]:
            assert_raises_jsonrpc(RPC_WALLET_PASSPHRASE_INCORRECT, None, node.walletpassphrase, wrong, 60)
        assert_raises_jsonrpc(RPC_WALLET_PASSPHRASE_INCORRECT, None,
                              node.walletpassphrasechange, 'not ' + PASSPHRASE, NEW_PASSPHRASE)
        self.assert_locked(node)

        spend = 1
        if not encrypt_binary:
            # encryptwallet refills the key pool (-keypool=1) after encrypting, so the locked wallet gives one
            # address. Coins sent to it are spent below with the 10 already held, so that key signs too.
            pooled = node.getnewaddress()
            assert_raises_jsonrpc(RPC_WALLET_KEYPOOL_RAN_OUT, None, node.getnewaddress)
            self.confirm(self.nodes[0].sendtoaddress(pooled, 5))
            assert_equal(node.getbalance(), 15)
            spend = 12

        # The right passphrase unlocks the wallet and it spends.
        node.walletpassphrase(PASSPHRASE, 60)
        assert_greater_than(node.getwalletinfo()['unlocked_until'], 0)
        self.confirm(node.sendtoaddress(self.nodes[0].getnewaddress(), spend))

        # walletlock locks it, and so does the end of a timed unlock.
        node.walletlock()
        self.assert_locked(node)
        node.walletpassphrase(PASSPHRASE, 1)
        deadline = time.time() + 30
        while node.getwalletinfo()['unlocked_until'] != 0:
            assert time.time() < deadline, 'the wallet was still unlocked 30 seconds after a 1 second unlock'
            time.sleep(0.2)
        self.assert_locked(node)

        # After walletpassphrasechange only the new passphrase unlocks it, before and after a restart.
        node.walletpassphrasechange(PASSPHRASE, NEW_PASSPHRASE)
        assert_raises_jsonrpc(RPC_WALLET_PASSPHRASE_INCORRECT, None, node.walletpassphrase, PASSPHRASE, 60)
        self.assert_locked(node)
        stop_node(node, 1)
        node = self.start_node1()
        assert_raises_jsonrpc(RPC_WALLET_PASSPHRASE_INCORRECT, None, node.walletpassphrase, PASSPHRASE, 60)
        self.assert_locked(node)
        node.walletpassphrase(NEW_PASSPHRASE, 60)
        self.confirm(node.sendtoaddress(self.nodes[0].getnewaddress(), 1))


if __name__ == '__main__':
    WalletEncryptionTest().main()

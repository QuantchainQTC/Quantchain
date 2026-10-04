#!/usr/bin/env python3
# Copyright (c) 2026 The Soqucoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

"""sendrawtransaction refuses outputs the script layer can never spend.

Node 0 runs with -acceptnonstdtxn=0, as mainnet and stagenet do. Every transaction here spends an outpoint that
does not exist, with a witness of the shape CheckTransaction requires, so the output check alone decides the
outcome: "scriptpubkey" means policy refused the output, "Missing inputs" means policy let it through. Refused:
pay-to-pubkey, pay-to-pubkey-hash, pay-to-script-hash, bare multisig, and witness v0 with a 20-byte or a 32-byte
program, among them the pay-to-pubkey-hash and pay-to-script-hash outputs createrawtransaction builds from base58
addresses. Let through: witness v1 and OP_RETURN. Node 1 runs with the regtest default, which accepts non-standard
transactions, and lets every form through to the input check.
"""

import hashlib

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import *
from test_framework.mininode import CTransaction, CTxIn, CTxOut, COutPoint, CTxInWitness, COIN
from test_framework.script import CScript, OP_0, OP_1, OP_TRUE, OP_DUP, OP_HASH160, OP_EQUALVERIFY, \
    OP_CHECKSIG, OP_EQUAL, OP_CHECKMULTISIG, OP_RETURN, hash160
from test_framework.address import byte_to_base58

RPC_TRANSACTION_ERROR = -25
RPC_TRANSACTION_REJECTED = -26

REGTEST_PUBKEY_ADDRESS = 111
REGTEST_SCRIPT_ADDRESS = 196


def shaped_spend(script, value):
    # Pays `script` from an outpoint that does not exist. The witness is a 2,420-byte signature and a 0x00-prefixed
    # 1,312-byte public key, the ML-DSA-44 shape CheckTransaction requires of every input.
    tx = CTransaction()
    tx.nVersion = 2
    tx.vin.append(CTxIn(COutPoint(int('77' * 32, 16), 0), b'', 0xffffffff))
    tx.vout.append(CTxOut(value, bytes(script)))
    witness = CTxInWitness()
    witness.scriptWitness.stack = [b'\x01' * 2420, b'\x00' + b'\x02' * 1312]
    tx.wit.vtxinwit = [witness]
    return bytes_to_hex_str(tx.serialize_with_witness())


def assert_refused(node, name, hex_tx, code, message):
    try:
        node.sendrawtransaction(hex_tx)
    except JSONRPCException as e:
        if e.error['code'] != code or message not in e.error['message']:
            raise AssertionError('%s: expected %d "%s", got %d "%s"' % (
                name, code, message, e.error['code'], e.error['message']))
        return
    raise AssertionError('%s: sendrawtransaction accepted a transaction whose input does not exist' % name)


class UnspendableOutputsTest(BitcoinTestFramework):

    def __init__(self):
        super().__init__()
        self.setup_clean_chain = True
        self.num_nodes = 2

    def setup_network(self, split=False):
        self.nodes = start_nodes(self.num_nodes, self.options.tmpdir, extra_args=[['-acceptnonstdtxn=0'], []])
        self.is_network_split = False

    def run_test(self):
        key = b'\x02' + b'\x11' * 32
        redeem_script = CScript([OP_TRUE])
        refused = [
            ('pay-to-pubkey', CScript([key, OP_CHECKSIG])),
            ('pay-to-pubkey-hash', CScript([OP_DUP, OP_HASH160, b'\x22' * 20, OP_EQUALVERIFY, OP_CHECKSIG])),
            ('pay-to-script-hash', CScript([OP_HASH160, hash160(bytes(redeem_script)), OP_EQUAL])),
            ('bare multisig', CScript([OP_1, key, OP_1, OP_CHECKMULTISIG])),
            ('witness v0, 20-byte program', CScript([OP_0, b'\x22' * 20])),
            ('witness v0, 32-byte program', CScript([OP_0, hashlib.sha256(bytes(redeem_script)).digest()])),
        ]

        # createrawtransaction falls back to base58 and builds the classical forms itself.
        for name, address, kind in [
                ('base58 pay-to-pubkey-hash', byte_to_base58(b'\x33' * 20, REGTEST_PUBKEY_ADDRESS), 'pubkeyhash'),
                ('base58 pay-to-script-hash', byte_to_base58(hash160(bytes(redeem_script)), REGTEST_SCRIPT_ADDRESS),
                 'scripthash')]:
            raw = self.nodes[0].createrawtransaction([], {address: 10})
            output = self.nodes[0].decoderawtransaction(raw)['vout'][0]['scriptPubKey']
            assert_equal(output['type'], kind)
            refused.append(('createrawtransaction, ' + name, CScript(hex_str_to_bytes(output['hex']))))

        let_through = [
            ('witness v1', CScript([OP_1, b'\x44' * 32]), 10 * COIN),
            ('OP_RETURN', CScript([OP_RETURN, b'data']), 0),
        ]

        for name, script in refused:
            assert_refused(self.nodes[0], name, shaped_spend(script, 10 * COIN),
                           RPC_TRANSACTION_REJECTED, '64: scriptpubkey')
            assert_refused(self.nodes[1], name, shaped_spend(script, 10 * COIN),
                           RPC_TRANSACTION_ERROR, 'Missing inputs')
        for name, script, value in let_through:
            for node in self.nodes:
                assert_refused(node, name, shaped_spend(script, value), RPC_TRANSACTION_ERROR, 'Missing inputs')


if __name__ == '__main__':
    UnspendableOutputsTest().main()

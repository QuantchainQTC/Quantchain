#!/usr/bin/env python3
# Copyright (c) 2026 The Soqucoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

"""pqvalidateaddress follows the node's address decoder, and pqgetnewaddress is gone.

pqvalidateaddress reports an address valid exactly when validateaddress finds a witness version 1 program in it,
and then reports that program as pubkey_hash. The strings checked: an address from getnewaddress, which
sendtoaddress pays; the same program in the layout pqgetnewaddress returned (the version byte converted with the
program, so the address reads as witness version 0 under a bech32m checksum), which sendtoaddress refuses; the
program under stagenet's prefix and under tsq, which no network uses; witness versions 0 and 2; programs of 20
and 33 bytes; the bech32 checksum; upper case; and strings that are not addresses. Node 1 runs with
-disablewallet and answers the same. pqgetnewaddress is not a method on either node.
"""

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import *

RPC_INVALID_ADDRESS_OR_KEY = -5
RPC_METHOD_NOT_FOUND = -32601

# Bech32 and bech32m encoding (BIP-173, BIP-350), to build the strings; the nodes do all the decoding.
CHARSET = 'qpzry9x8gf2tvdw0s3jn54khce6mua7l'
BECH32 = 1
BECH32M = 0x2bc830a3


def polymod(values):
    generator = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3]
    chk = 1
    for value in values:
        top = chk >> 25
        chk = (chk & 0x1ffffff) << 5 ^ value
        for i in range(5):
            if (top >> i) & 1:
                chk ^= generator[i]
    return chk


def encode(hrp, groups, constant=BECH32M):
    values = [ord(c) >> 5 for c in hrp] + [0] + [ord(c) & 31 for c in hrp] + groups
    mod = polymod(values + [0] * 6) ^ constant
    checksum = [(mod >> 5 * (5 - i)) & 31 for i in range(6)]
    return hrp + '1' + ''.join(CHARSET[g] for g in groups + checksum)


def five_bit(data):
    acc, bits, groups = 0, 0, []
    for byte in data:
        acc = (acc << 8) | byte
        bits += 8
        while bits >= 5:
            bits -= 5
            groups.append((acc >> bits) & 31)
    if bits:
        groups.append((acc << (5 - bits)) & 31)
    return groups


def witness_address(hrp, version, program, constant=BECH32M):
    # The node's layout: the witness version is a 5-bit group of its own, followed by the program.
    return encode(hrp, [version] + five_bit(program), constant)


def pqgetnewaddress_layout(hrp, program):
    # The layout pqgetnewaddress returned: the version byte 0x01 converted together with the program.
    return encode(hrp, five_bit(bytes([1]) + program))


class PQAddressRPCsTest(BitcoinTestFramework):

    def __init__(self):
        super().__init__()
        self.setup_clean_chain = True
        self.num_nodes = 2
        self.extra_args = [[], ['-disablewallet']]

    def setup_network(self, split=False):
        self.nodes = start_nodes(self.num_nodes, self.options.tmpdir, self.extra_args)
        connect_nodes_bi(self.nodes, 0, 1)
        self.is_network_split = False
        self.sync_all()

    def check(self, address):
        """pqvalidateaddress on both nodes against validateaddress on node 0; returns isvalid."""
        decoded = self.nodes[0].validateaddress(address)
        program = decoded.get('witness_program') if decoded['isvalid'] else None
        for node in self.nodes:
            if program is None:
                assert_equal(node.pqvalidateaddress(address), {'isvalid': False, 'error': 'Invalid address format'})
            else:
                assert_equal(node.pqvalidateaddress(address),
                             {'isvalid': True, 'network': 'regtest', 'pubkey_hash': program, 'type': 'P2PQ'})
        return program is not None

    def run_test(self):
        wallet = self.nodes[0]
        address = wallet.getnewaddress()
        program = bytes.fromhex(wallet.validateaddress(address)['witness_program'])
        assert_equal(witness_address('sq', 1, program), address)

        # An address from getnewaddress is valid, and sendtoaddress pays it. Coinbase maturity on regtest is 60 blocks.
        assert self.check(address)
        wallet.generate(70)
        wallet.sendtoaddress(address, 1)
        wallet.generate(1)
        self.sync_all()
        assert_equal(wallet.getreceivedbyaddress(address), 1)

        # The layout pqgetnewaddress returned is refused, as sendtoaddress refuses it.
        old = pqgetnewaddress_layout('sq', program)
        assert old.startswith('sq1q')
        assert not self.check(old)
        assert_raises_jsonrpc(RPC_INVALID_ADDRESS_OR_KEY, 'Invalid Soqucoin address', wallet.sendtoaddress, old, 1)

        for refused in [
            witness_address('ssq', 1, program),
            witness_address('tsq', 1, program),
            pqgetnewaddress_layout('tsq', program),
            witness_address('sq', 0, program),
            witness_address('sq', 2, program),
            witness_address('sq', 1, program[:20]),
            witness_address('sq', 1, program + b'\x00'),
            witness_address('sq', 1, program, BECH32),
            address[:-1],
            address + 'q',
            'sq1',
            '',
            'not an address',
        ]:
            assert not self.check(refused)

        # The node's decoder accepts an address in upper case, and so does pqvalidateaddress.
        assert self.check(address.upper())

        # pqgetnewaddress is not a method, with or without a wallet.
        for node in self.nodes:
            assert_raises_jsonrpc(RPC_METHOD_NOT_FOUND, 'Method not found', node.pqgetnewaddress)
            assert 'pqgetnewaddress' not in node.help()


if __name__ == '__main__':
    PQAddressRPCsTest().main()

// Copyright (c) 2026 Soqucoin Labs Inc.
// Distributed under the MIT software license.
//
// unspendable_output_policy_tests.cpp — relay policy refuses every output form
// the script layer can never spend. Bead trp6.
//
// Solver still names the classical forms inherited from Bitcoin Core
// (pay-to-pubkey, pay-to-pubkey-hash, pay-to-script-hash, bare multisig) and
// both witness v0 forms. VerifyScript refuses the four classical forms and the
// 22-byte v0 program outright (SCRIPT_ERR_DISALLOWED_CLASSICAL_CRYPTO), and
// reads a 34-byte v0 program as the SHA256 of an ML-DSA-44 public key, which a
// script hash is not. IsStandard used to accept all six, so a transaction
// paying one relayed, confirmed, and left an output nobody could spend.
//
// The pay-to-pubkey-hash, pay-to-script-hash and v0 forms come from the node's
// own script builders, which createrawtransaction, fundrawtransaction's
// changeAddress, soqucoin-tx and addwitnessaddress use. The transactions are
// real: they spend mature v1 coinbase outputs of the regtest chain fixture with
// ML-DSA-44 signatures, and go through AcceptToMemoryPool and ConnectBlock.

#include "test/dilithium_chain_setup.h"

#include "policy/policy.h"
#include "script/standard.h"
#include "txmempool.h"

#include <boost/test/unit_test.hpp>

#include <string>
#include <vector>

namespace {

struct Form {
    std::string name;
    CScript spk;
    CScript redeemScript;   // pay-to-script-hash only: what a spender would reveal
};

const CAmount FEE = 1 * COIN;

} // namespace

struct UnspendableOutputSetup : public DilithiumChainSetup {
    //! The six forms Solver names and VerifyScript never lets anyone spend.
    std::vector<Form> UnspendableForms()
    {
        const CKeyID keyID = coinbaseKey.GetPubKey().GetID();
        const CScript p2pkh = GetScriptForDestination(keyID);
        const CScript redeem = CScript() << OP_TRUE;
        // Solver names pay-to-pubkey and bare multisig only for 33- to
        // 65-byte keys, so an ML-DSA-44 key (1,312 bytes) cannot appear in them.
        const std::vector<unsigned char> classicalKey(33, 0x02);

        std::vector<Form> forms;
        forms.push_back({"pay-to-pubkey", CScript() << classicalKey << OP_CHECKSIG, CScript()});
        forms.push_back({"pay-to-pubkey-hash", p2pkh, CScript()});
        forms.push_back({"pay-to-script-hash", GetScriptForDestination(CScriptID(redeem)), redeem});
        forms.push_back({"bare multisig",
                         CScript() << OP_1 << classicalKey << OP_1 << OP_CHECKMULTISIG, CScript()});
        forms.push_back({"witness v0, 20-byte program", GetScriptForWitness(p2pkh), CScript()});
        forms.push_back({"witness v0, 32-byte program", GetScriptForWitness(redeem), CScript()});
        return forms;
    }

    //! Spend output 0 of a mature coinbase to `outputs`, signed by its key.
    CMutableTransaction Pay(const CTransaction& cb, const std::vector<CTxOut>& outputs)
    {
        CMutableTransaction tx;
        tx.nVersion = 2;
        tx.vin.push_back(CTxIn(COutPoint(cb.GetHash(), 0), CScript(), CTxIn::SEQUENCE_FINAL));
        tx.vout = outputs;
        SignInput(tx, 0, coinbaseSpk, cb.vout[0].nValue);
        return tx;
    }

    CMutableTransaction Pay(const CTransaction& cb, const CScript& spk)
    {
        return Pay(cb, {CTxOut(cb.vout[0].nValue - FEE, spk)});
    }

    std::string MempoolVerdict(const CMutableTransaction& tx)
    {
        CValidationState state;
        LOCK(cs_main);
        if (AcceptToMemoryPool(mempool, state, MakeTransactionRef(tx), false, nullptr, nullptr, false, 0))
            return "accepted";
        return state.GetRejectReason();
    }
};

BOOST_FIXTURE_TEST_SUITE(unspendable_output_policy_tests, UnspendableOutputSetup)

// The relay path. Each form is refused with reason "scriptpubkey", the one
// IsStandardTx gives for an output it does not accept.
BOOST_AUTO_TEST_CASE(the_mempool_refuses_every_form_nothing_can_spend)
{
    BOOST_REQUIRE_MESSAGE(fRequireStandard,
        "unit tests must run with fRequireStandard set, as mainnet and stagenet do");

    const std::vector<Form> forms = UnspendableForms();
    for (size_t i = 0; i < forms.size(); ++i) {
        const std::string verdict = MempoolVerdict(Pay(coinbaseTxns[i], forms[i].spk));
        BOOST_CHECK_MESSAGE(verdict == "scriptpubkey",
            "a transaction paying " + forms[i].name + " got '" + verdict + "' from the mempool, "
            "expected 'scriptpubkey'");
    }

    // Controls: the same construction paying a witness v1 program, and an
    // OP_RETURN output beside one, is accepted.
    BOOST_CHECK_EQUAL(MempoolVerdict(Pay(coinbaseTxns[10], coinbaseSpk)), "accepted");
    const CAmount value = coinbaseTxns[11].vout[0].nValue;
    BOOST_CHECK_EQUAL(MempoolVerdict(Pay(coinbaseTxns[11],
        {CTxOut(0, CScript() << OP_RETURN << std::vector<unsigned char>(8, 0x42)),
         CTxOut(value - FEE, coinbaseSpk)})), "accepted");
}

// Consensus is unchanged: a block may still create each form, and no spend of
// one connects, not even one the key holder signs over the output's own script.
BOOST_AUTO_TEST_CASE(a_block_may_still_create_them_and_no_spend_connects)
{
    const std::vector<Form> forms = UnspendableForms();
    std::vector<CMutableTransaction> pays;
    for (size_t i = 0; i < forms.size(); ++i)
        pays.push_back(Pay(coinbaseTxns[i], forms[i].spk));

    const int height = chainActive.Height();
    CreateAndProcessBlock(pays, coinbaseSpk);
    BOOST_REQUIRE_MESSAGE(chainActive.Height() == height + 1,
        "a block creating the six forms must connect: this change is policy only");

    for (size_t i = 0; i < forms.size(); ++i) {
        const CAmount value = pays[i].vout[0].nValue;
        CMutableTransaction spend;
        spend.nVersion = 2;
        spend.vin.push_back(CTxIn(COutPoint(pays[i].GetHash(), 0), CScript(), CTxIn::SEQUENCE_FINAL));
        spend.vout.push_back(CTxOut(value - FEE, coinbaseSpk));
        SignInput(spend, 0, forms[i].spk, value);
        if (!forms[i].redeemScript.empty())
            spend.vin[0].scriptSig = CScript() << ToByteVector(forms[i].redeemScript);
        BOOST_CHECK_MESSAGE(!BlockIsValid({spend}),
            "a spend of " + forms[i].name + " connected; the script layer is meant to refuse it");
    }
}

// The one v0 form the script layer can release is a 32-byte program that is
// the SHA256 of an ML-DSA-44 key. Its spend still connects in a block. Through
// the mempool that spend was refused before this change, because
// IsWitnessStandard applies the P2WSH item limit of 80 bytes to the signature,
// and it still is: the input side of policy is not part of this change.
BOOST_AUTO_TEST_CASE(a_v0_program_that_hashes_a_key_is_spent_only_in_a_block)
{
    const CScript v0key = Spk(OP_0);
    const COutPoint coin = SeedCoin(v0key, 10 * COIN, 0xA1);

    CMutableTransaction spend;
    spend.nVersion = 2;
    spend.vin.push_back(CTxIn(coin, CScript(), CTxIn::SEQUENCE_FINAL));
    spend.vout.push_back(CTxOut(9 * COIN, coinbaseSpk));
    SignInput(spend, 0, v0key, 10 * COIN);

    BOOST_CHECK_MESSAGE(BlockIsValid({spend}), "a signed spend of a v0 key-hash program must connect");
    BOOST_CHECK_EQUAL(MempoolVerdict(spend), "bad-witness-nonstandard");
}

BOOST_AUTO_TEST_SUITE_END()

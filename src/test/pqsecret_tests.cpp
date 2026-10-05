// Copyright (c) 2026 Soqucoin Labs Inc.
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
//
// The ML-DSA-44 private-key codec (CBitcoinSecret) and the witness v1 branch
// of CombineSignatures.
//
// A key is carried in two forms. The seed WIF is base58check of the SECRET_KEY
// prefix, a 32-byte FIPS 204 seed and a 0x02 marker; it is the portable secret
// an integrator holds, and the node expands it with FIPS 204 KeyGen, so a seed
// gives the same key and address here as the SDK's keys.FromSeed. The expanded
// form is base58check of the full 3,872-byte key pair, what dumpwallet writes.
// A classical 32-byte WIF is refused. CombineSignatures must keep a witness v1
// signature ProduceSignature built, which signrawtransaction and soqucoin-tx
// pass through it.

#include "base58.h"
#include "chainparams.h"
#include "crypto/sha256.h"
#include "key.h"
#include "keystore.h"
#include "policy/policy.h"
#include "primitives/transaction.h"
#include "pubkey.h"
#include "random.h"
#include "script/interpreter.h"
#include "script/script.h"
#include "script/script_error.h"
#include "script/sign.h"
#include "script/standard.h"
#include "test/test_bitcoin.h"
#include "uint256.h"
#include "utilstrencodings.h"

#include <string>
#include <vector>

#include <boost/test/unit_test.hpp>

BOOST_FIXTURE_TEST_SUITE(pqsecret_tests, BasicTestingSetup)

// base58check of the SECRET_KEY prefix and a payload, as CBitcoinSecret decodes.
static std::string SecretString(const std::vector<unsigned char>& payload)
{
    std::vector<unsigned char> data = Params().Base58Prefix(CChainParams::SECRET_KEY);
    data.insert(data.end(), payload.begin(), payload.end());
    return EncodeBase58Check(data);
}

static std::string SeedWIF(const std::vector<unsigned char>& seed)
{
    std::vector<unsigned char> payload = seed;
    payload.push_back(0x02);
    return SecretString(payload);
}

static uint256 WitnessProgram(const CPubKey& pubkey)
{
    uint256 program;
    CSHA256().Write(pubkey.begin(), pubkey.size()).Finalize(program.begin());
    return program;
}

// A seed imports as a WIF, expands to the same key the node makes from it, and
// the SDK's node vector (seed = SHA-256("soqucoin")) pins the witness program.
BOOST_AUTO_TEST_CASE(seed_wif_round_trip_and_sdk_vector)
{
    std::vector<unsigned char> seed(CKey::SEED_SIZE);
    CSHA256().Write((const unsigned char*)"soqucoin", 8).Finalize(seed.data());

    CBitcoinSecret secret;
    BOOST_REQUIRE(secret.SetString(SeedWIF(seed)));
    BOOST_CHECK(secret.IsValid());

    CKey key = secret.GetKey();
    BOOST_REQUIRE(key.IsValid());
    CPubKey pubkey = key.GetPubKey();
    BOOST_REQUIRE(pubkey.IsValid());
    BOOST_REQUIRE_EQUAL(pubkey.size(), 1312u);

    // The SDK's keys.FromSeed(SHA-256("soqucoin")) gives this witness program.
    BOOST_CHECK_EQUAL(HexStr(WitnessProgram(pubkey)),
                      "ec671f444afa19d8ee919c21c76fd2fbda2d17dc173fe75e94c2fdbea5ef366b");

    // SetSeed on a fresh key reproduces the identical key pair: deterministic.
    CKey direct;
    BOOST_REQUIRE(direct.SetSeed(seed.data()));
    BOOST_CHECK(direct == key);
    BOOST_CHECK(direct.GetPubKey() == pubkey);

    // It signs and the public key verifies.
    const uint256 hash = GetRandHash();
    std::vector<unsigned char> sig;
    BOOST_CHECK(key.Sign(hash, sig));
    BOOST_CHECK(pubkey.Verify(hash, sig));
}

// A classical 32-byte WIF, with or without a trailing 0x01, is refused, so a
// pasted classical key is never expanded into a Dilithium key.
BOOST_AUTO_TEST_CASE(classical_wif_refused)
{
    std::vector<unsigned char> body(CKey::SEED_SIZE, 0x11);
    std::vector<unsigned char> compressed = body;
    compressed.push_back(0x01);
    std::vector<unsigned char> wrong_marker = body;
    wrong_marker.push_back(0x03); // not the 0x02 seed marker

    for (const std::vector<unsigned char>& payload : {body, compressed, wrong_marker}) {
        CBitcoinSecret secret;
        BOOST_CHECK(!secret.SetString(SecretString(payload)));
        BOOST_CHECK(!secret.IsValid());
        BOOST_CHECK(!secret.GetKey().IsValid());
    }
}

// The expanded form, what dumpwallet writes, round-trips through CBitcoinSecret.
BOOST_AUTO_TEST_CASE(expanded_form_round_trip)
{
    CKey key;
    key.MakeNewKey(true);
    BOOST_REQUIRE(key.IsValid());

    CBitcoinSecret secret(key); // SetKey writes the expanded 3,872-byte form
    BOOST_CHECK(secret.IsValid());
    const std::string wif = secret.ToString();

    CBitcoinSecret decoded;
    BOOST_REQUIRE(decoded.SetString(wif));
    CKey back = decoded.GetKey();
    BOOST_REQUIRE(back.IsValid());
    BOOST_CHECK(back == key);

    const uint256 hash = GetRandHash();
    std::vector<unsigned char> sig;
    BOOST_CHECK(back.Sign(hash, sig));
    BOOST_CHECK(key.GetPubKey().Verify(hash, sig));
}

// CombineSignatures keeps a witness v1 signature. signrawtransaction and
// soqucoin-tx sign= build the witness with ProduceSignature, then combine it
// against the transaction as given (an empty witness). Before the v1 case the
// default returned empty stacks and the input failed VerifyScript.
BOOST_AUTO_TEST_CASE(combine_signatures_keeps_witness_v1)
{
    CKey key;
    key.MakeNewKey(true);
    const CPubKey pubkey = key.GetPubKey();
    const uint256 program = WitnessProgram(pubkey);
    const CScript scriptPubKey = CScript() << OP_1 << ToByteVector(program);

    CBasicKeyStore keystore;
    BOOST_REQUIRE(keystore.AddKey(key));

    CMutableTransaction tx;
    tx.nVersion = 2;
    CTxIn in;
    in.prevout = COutPoint(GetRandHash(), 0);
    in.nSequence = 0xffffffff;
    tx.vin.push_back(in);
    tx.vout.push_back(CTxOut(900000000LL, CScript() << OP_1 << std::vector<unsigned char>(32, 0x33)));
    const CAmount amount = 1000000000LL;

    SignatureData sigdata;
    BOOST_REQUIRE(ProduceSignature(MutableTransactionSignatureCreator(&keystore, &tx, 0, amount, SIGHASH_ALL),
                                   scriptPubKey, sigdata));
    BOOST_REQUIRE_EQUAL(sigdata.scriptWitness.stack.size(), 2u);

    const CTransaction txConst(tx);
    SignatureData combined = CombineSignatures(scriptPubKey, TransactionSignatureChecker(&txConst, 0, amount),
                                               sigdata, SignatureData());
    // Without the v1 case this stack is empty.
    BOOST_REQUIRE_EQUAL(combined.scriptWitness.stack.size(), 2u);

    tx.vin[0].scriptSig = combined.scriptSig;
    tx.vin[0].scriptWitness = combined.scriptWitness;
    const CTransaction txFinal(tx);
    ScriptError serror = SCRIPT_ERR_OK;
    BOOST_CHECK_MESSAGE(VerifyScript(tx.vin[0].scriptSig, scriptPubKey, &tx.vin[0].scriptWitness,
                                     STANDARD_SCRIPT_VERIFY_FLAGS,
                                     TransactionSignatureChecker(&txFinal, 0, amount), &serror),
                        ScriptErrorString(serror));
}

// About one seed in 256 expands to a public key beginning 0xFF, the node's
// invalid-key marker. Such a seed's WIF is format-valid, so IsValid accepts it,
// but SetSeed refuses it and GetKey returns an invalid key. Every caller that
// loads a key must check IsValid before using it (signrawtransaction, soqucoin-tx
// MutateTxSign, importwallet, importprivkey all do), or GetPubKey asserts.
BOOST_AUTO_TEST_CASE(seed_expanding_to_the_marker_is_refused)
{
    std::vector<unsigned char> seed(CKey::SEED_SIZE, 0);
    CKey key;
    int tries = 0;
    for (; tries < 20000; ++tries) {
        uint256 h;
        CSHA256().Write((const unsigned char*)&tries, sizeof(tries)).Finalize(h.begin());
        std::copy(h.begin(), h.end(), seed.begin());
        if (!key.SetSeed(seed.data())) break; // a seed whose public key begins 0xFF
    }
    BOOST_REQUIRE_MESSAGE(tries < 20000, "no 0xFF-marker seed found in 20000 tries");
    BOOST_CHECK(!key.IsValid());

    // The WIF is format-valid, so a caller that does not re-check IsValid after
    // GetKey would use an invalid key.
    CBitcoinSecret secret;
    BOOST_REQUIRE(secret.SetString(SeedWIF(seed)));
    BOOST_CHECK(secret.IsValid());
    BOOST_CHECK(!secret.GetKey().IsValid());
}

// The expanded form is untrusted on import. A crafted 3,872-byte payload is
// format-valid, but GetKey must return an invalid key unless the public half is
// a real public key and matches the secret key, or GetPubKey (0xFF marker) or
// VerifyPubKey (mismatch) asserts in a caller that only checked IsValid.
BOOST_AUTO_TEST_CASE(crafted_expanded_key_is_refused)
{
    CKey good;
    good.MakeNewKey(true);
    std::vector<unsigned char> expanded(good.begin(), good.end());
    BOOST_REQUIRE_EQUAL(expanded.size(), (size_t)CKey::SIZE);
    const size_t pub = CKey::SIZE - CPubKey::SIZE; // first byte of the public half

    // A sound expanded key round-trips.
    {
        CBitcoinSecret secret;
        BOOST_REQUIRE(secret.SetString(SecretString(expanded)));
        BOOST_CHECK(secret.GetKey().IsValid());
    }
    // Public half begins 0xFF (the invalid marker): format-valid, key refused.
    {
        std::vector<unsigned char> bad = expanded;
        bad[pub] = 0xFF;
        CBitcoinSecret secret;
        BOOST_REQUIRE(secret.SetString(SecretString(bad)));
        BOOST_CHECK(secret.IsValid());
        BOOST_CHECK(!secret.GetKey().IsValid());
    }
    // Public half does not match the secret key: format-valid, key refused.
    {
        std::vector<unsigned char> bad = expanded;
        bad[pub + 1] ^= 0x01;
        CBitcoinSecret secret;
        BOOST_REQUIRE(secret.SetString(SecretString(bad)));
        BOOST_CHECK(secret.IsValid());
        BOOST_CHECK(!secret.GetKey().IsValid());
    }
}

// The wrong network's prefix and every wrong length are refused, and GetKey
// never asserts on a short payload.
BOOST_AUTO_TEST_CASE(wrong_prefix_and_lengths_refused)
{
    CKey key;
    key.MakeNewKey(true);
    const std::vector<unsigned char> expanded(key.begin(), key.end());

    // Mainnet's SECRET_KEY prefix (158) on the regtest chain (239).
    std::vector<unsigned char> mainnet{158};
    mainnet.insert(mainnet.end(), expanded.begin(), expanded.end());
    CBitcoinSecret wrong_net;
    BOOST_CHECK(!wrong_net.SetString(EncodeBase58Check(mainnet)));
    BOOST_CHECK(!wrong_net.IsValid());

    for (size_t n : {size_t(0), size_t(1), size_t(31), size_t(34), size_t(3871), size_t(3873), size_t(3905)}) {
        CBitcoinSecret secret;
        BOOST_CHECK(!secret.SetString(SecretString(std::vector<unsigned char>(n, 0x22))));
        BOOST_CHECK(!secret.GetKey().IsValid());
    }
}

// CombineSignatures keeps a witness v1 signature in every ordering, as the v0
// key-hash case does: the signed stack wins over an empty one from either side,
// two empties stay empty. An implementation that always returned the first
// argument would fail the (empty, signed) ordering.
BOOST_AUTO_TEST_CASE(combine_signatures_v1_orderings)
{
    CKey key;
    key.MakeNewKey(true);
    const CPubKey pubkey = key.GetPubKey();
    const CScript scriptPubKey = CScript() << OP_1 << ToByteVector(WitnessProgram(pubkey));

    CBasicKeyStore keystore;
    BOOST_REQUIRE(keystore.AddKey(key));

    CMutableTransaction tx;
    tx.nVersion = 2;
    CTxIn in;
    in.prevout = COutPoint(GetRandHash(), 0);
    in.nSequence = 0xffffffff;
    tx.vin.push_back(in);
    tx.vout.push_back(CTxOut(900000000LL, CScript() << OP_1 << std::vector<unsigned char>(32, 0x33)));
    const CAmount amount = 1000000000LL;

    SignatureData signed_data;
    BOOST_REQUIRE(ProduceSignature(MutableTransactionSignatureCreator(&keystore, &tx, 0, amount, SIGHASH_ALL),
                                   scriptPubKey, signed_data));
    BOOST_REQUIRE_EQUAL(signed_data.scriptWitness.stack.size(), 2u);
    const SignatureData empty;

    const CTransaction txConst(tx);
    const TransactionSignatureChecker checker(&txConst, 0, amount);
    BOOST_CHECK_EQUAL(CombineSignatures(scriptPubKey, checker, signed_data, empty).scriptWitness.stack.size(), 2u);
    BOOST_CHECK_EQUAL(CombineSignatures(scriptPubKey, checker, empty, signed_data).scriptWitness.stack.size(), 2u);
    BOOST_CHECK_EQUAL(CombineSignatures(scriptPubKey, checker, signed_data, signed_data).scriptWitness.stack.size(), 2u);
    BOOST_CHECK_EQUAL(CombineSignatures(scriptPubKey, checker, empty, empty).scriptWitness.stack.size(), 0u);
}

BOOST_AUTO_TEST_SUITE_END()

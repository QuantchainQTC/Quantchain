// Copyright (c) 2014-2016 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "key.h"
#include "test/test_bitcoin.h"
#include "utilstrencodings.h"
#include "wallet/crypter.h"

#include <vector>

#include <boost/test/unit_test.hpp>

BOOST_FIXTURE_TEST_SUITE(wallet_crypto, BasicTestingSetup)

class TestCrypter
{
public:
static void TestPassphraseSingle(const std::vector<unsigned char>& vchSalt, const SecureString& passphrase, uint32_t rounds,
                 const std::vector<unsigned char>& correctKey = std::vector<unsigned char>(),
                 const std::vector<unsigned char>& correctIV=std::vector<unsigned char>())
{
    CCrypter crypt;
    crypt.SetKeyFromPassphrase(passphrase, vchSalt, rounds, 0);

    if(!correctKey.empty())
        BOOST_CHECK_MESSAGE(memcmp(crypt.vchKey.data(), correctKey.data(), crypt.vchKey.size()) == 0, \
            HexStr(crypt.vchKey.begin(), crypt.vchKey.end()) + std::string(" != ") + HexStr(correctKey.begin(), correctKey.end()));
    if(!correctIV.empty())
        BOOST_CHECK_MESSAGE(memcmp(crypt.vchIV.data(), correctIV.data(), crypt.vchIV.size()) == 0,
            HexStr(crypt.vchIV.begin(), crypt.vchIV.end()) + std::string(" != ") + HexStr(correctIV.begin(), correctIV.end()));
}

static void TestPassphrase(const std::vector<unsigned char>& vchSalt, const SecureString& passphrase, uint32_t rounds,
                 const std::vector<unsigned char>& correctKey = std::vector<unsigned char>(),
                 const std::vector<unsigned char>& correctIV=std::vector<unsigned char>())
{
    TestPassphraseSingle(vchSalt, passphrase, rounds, correctKey, correctIV);
    for(SecureString::const_iterator i(passphrase.begin()); i != passphrase.end(); ++i)
        TestPassphraseSingle(vchSalt, SecureString(i, passphrase.end()), rounds);
}

static void TestDecrypt(const CCrypter& crypt, const std::vector<unsigned char>& vchCiphertext, \
                        const std::vector<unsigned char>& vchPlaintext = std::vector<unsigned char>())
{
    CKeyingMaterial vchDecrypted;
    crypt.Decrypt(vchCiphertext, vchDecrypted);
    if (vchPlaintext.size())
        BOOST_CHECK(CKeyingMaterial(vchPlaintext.begin(), vchPlaintext.end()) == vchDecrypted);
}

static void TestEncryptSingle(const CCrypter& crypt, const CKeyingMaterial& vchPlaintext,
                       const std::vector<unsigned char>& vchCiphertextCorrect = std::vector<unsigned char>())
{
    std::vector<unsigned char> vchCiphertext;
    crypt.Encrypt(vchPlaintext, vchCiphertext);

    if (!vchCiphertextCorrect.empty())
        BOOST_CHECK(vchCiphertext == vchCiphertextCorrect);

    const std::vector<unsigned char> vchPlaintext2(vchPlaintext.begin(), vchPlaintext.end());
    TestDecrypt(crypt, vchCiphertext, vchPlaintext2);
}

static void TestEncrypt(const CCrypter& crypt, const std::vector<unsigned char>& vchPlaintextIn, \
                       const std::vector<unsigned char>& vchCiphertextCorrect = std::vector<unsigned char>())
{
    TestEncryptSingle(crypt, CKeyingMaterial(vchPlaintextIn.begin(), vchPlaintextIn.end()), vchCiphertextCorrect);
    for(std::vector<unsigned char>::const_iterator i(vchPlaintextIn.begin()); i != vchPlaintextIn.end(); ++i)
        TestEncryptSingle(crypt, CKeyingMaterial(i, vchPlaintextIn.end()));
}

};

BOOST_AUTO_TEST_CASE(passphrase) {
    // These are expensive.

    TestCrypter::TestPassphrase(ParseHex("0000deadbeef0000"), "test", 25000, \
                                ParseHex("fc7aba077ad5f4c3a0988d8daa4810d0d4a0e3bcb53af662998898f33df0556a"), \
                                ParseHex("cf2f2691526dd1aa220896fb8bf7c369"));

    std::string hash(GetRandHash().ToString());
    std::vector<unsigned char> vchSalt(8);
    GetRandBytes(&vchSalt[0], vchSalt.size());
    uint32_t rounds = InsecureRand32();
    if (rounds > 30000)
        rounds = 30000;
    TestCrypter::TestPassphrase(vchSalt, SecureString(hash.begin(), hash.end()), rounds);
}

BOOST_AUTO_TEST_CASE(encrypt) {
    std::vector<unsigned char> vchSalt = ParseHex("0000deadbeef0000");
    BOOST_CHECK(vchSalt.size() == WALLET_CRYPTO_SALT_SIZE);
    CCrypter crypt;
    crypt.SetKeyFromPassphrase("passphrase", vchSalt, 25000, 0);
    TestCrypter::TestEncrypt(crypt, ParseHex("22bcade09ac03ff6386914359cfe885cfeb5f77ff0d670f102f619687453b29d"));

    for (int i = 0; i != 100; i++)
    {
        uint256 hash(GetRandHash());
        TestCrypter::TestEncrypt(crypt, std::vector<unsigned char>(hash.begin(), hash.end()));
    }

}

BOOST_AUTO_TEST_CASE(decrypt) {
    std::vector<unsigned char> vchSalt = ParseHex("0000deadbeef0000");
    BOOST_CHECK(vchSalt.size() == WALLET_CRYPTO_SALT_SIZE);
    CCrypter crypt;
    crypt.SetKeyFromPassphrase("passphrase", vchSalt, 25000, 0);

    // Some corner cases the came up while testing
    TestCrypter::TestDecrypt(crypt,ParseHex("795643ce39d736088367822cdc50535ec6f103715e3e48f4f3b1a60a08ef59ca"));
    TestCrypter::TestDecrypt(crypt,ParseHex("de096f4a8f9bd97db012aa9d90d74de8cdea779c3ee8bc7633d8b5d6da703486"));
    TestCrypter::TestDecrypt(crypt,ParseHex("32d0a8974e3afd9c6c3ebf4d66aa4e6419f8c173de25947f98cf8b7ace49449c"));
    TestCrypter::TestDecrypt(crypt,ParseHex("e7c055cca2faa78cb9ac22c9357a90b4778ded9b2cc220a14cea49f931e596ea"));
    TestCrypter::TestDecrypt(crypt,ParseHex("b88efddd668a6801d19516d6830da4ae9811988ccbaf40df8fbb72f3f4d335fd"));
    TestCrypter::TestDecrypt(crypt,ParseHex("8cae76aa6a43694e961ebcb28c8ca8f8540b84153d72865e8561ddd93fa7bfa9"));

    for (int i = 0; i != 100; i++)
    {
        uint256 hash(GetRandHash());
        TestCrypter::TestDecrypt(crypt, std::vector<unsigned char>(hash.begin(), hash.end()));
    }
}

// Makes public the two protected steps that encryptwallet and walletpassphrase call.
class TestCryptoKeyStore : public CCryptoKeyStore
{
public:
    using CCryptoKeyStore::EncryptKeys;
    using CCryptoKeyStore::Unlock;
};

static CKeyingMaterial NewMasterKey()
{
    CKeyingMaterial master(WALLET_CRYPTO_KEY_SIZE);
    GetStrongRandBytes(master.data(), master.size());
    return master;
}

// A key record encrypted the way CCryptoKeyStore encrypts one: the IV is the start of the public key's hash.
static std::vector<unsigned char> EncryptRecord(const CKeyingMaterial& master, const CKeyingMaterial& secret, const CPubKey& ivPubKey)
{
    const uint256 iv = ivPubKey.GetHash();
    CCrypter crypter;
    BOOST_REQUIRE(crypter.SetKey(master, std::vector<unsigned char>(iv.begin(), iv.begin() + WALLET_CRYPTO_IV_SIZE)));
    std::vector<unsigned char> record;
    BOOST_REQUIRE(crypter.Encrypt(secret, record));
    return record;
}

// Whether a locked store holding only this record unlocks with the master key.
static bool Unlocks(const CKeyingMaterial& master, const CPubKey& pubkey, const std::vector<unsigned char>& record)
{
    TestCryptoKeyStore store;
    BOOST_REQUIRE(store.AddCryptedKey(pubkey, record));
    return store.Unlock(master);
}

BOOST_AUTO_TEST_CASE(mldsa_key_record_refused) {
    CKey key, other;
    key.MakeNewKey(true);
    other.MakeNewKey(true);
    const CPubKey pubkey = key.GetPubKey();
    const CKeyingMaterial secret(key.begin(), key.end());
    const CKeyingMaterial master = NewMasterKey();

    // The record as CCryptoKeyStore writes it unlocks; each case below changes one thing.
    BOOST_CHECK(Unlocks(master, pubkey, EncryptRecord(master, secret, pubkey)));

    // A master key that differs in one bit.
    CKeyingMaterial wrong_master(master);
    wrong_master[0] ^= 1;
    BOOST_CHECK(!Unlocks(wrong_master, pubkey, EncryptRecord(master, secret, pubkey)));

    // Another key's record stored under this public key. Decrypting it with this key's IV changes only the
    // first 16-byte block, so the padding and the size pass and VerifyPubKey refuses it.
    BOOST_CHECK(!Unlocks(master, pubkey, EncryptRecord(master, CKeyingMaterial(other.begin(), other.end()), other.GetPubKey())));

    // The right public half after a damaged first byte, which is in rho: VerifyPubKey's signature check refuses it.
    // Damage to K, s2 or t0 can pass that check, since a key damaged there can still sign validly.
    CKeyingMaterial damaged(secret);
    damaged[0] ^= 1;
    BOOST_CHECK(!Unlocks(master, pubkey, EncryptRecord(master, damaged, pubkey)));

    // A 32-byte secret, the size of the keys this crypter was first written for.
    BOOST_CHECK(!Unlocks(master, pubkey, EncryptRecord(master, CKeyingMaterial(secret.begin(), secret.begin() + 32), pubkey)));
}

BOOST_AUTO_TEST_CASE(mldsa_encrypt_keys_then_unlock) {
    TestCryptoKeyStore store;
    std::vector<CKey> keys(3);
    for (CKey& key : keys) {
        key.MakeNewKey(true);
        BOOST_REQUIRE(store.AddKeyPubKey(key, key.GetPubKey()));
    }
    CKeyingMaterial master = NewMasterKey();
    BOOST_REQUIRE(store.EncryptKeys(master));
    BOOST_REQUIRE(store.Lock());

    CKeyingMaterial wrong_master(master);
    wrong_master[0] ^= 1;
    BOOST_CHECK(!store.Unlock(wrong_master));
    BOOST_CHECK(store.IsLocked());

    BOOST_REQUIRE(store.Unlock(master));
    BOOST_CHECK(!store.IsLocked());
    for (const CKey& key : keys) {
        const CPubKey pubkey = key.GetPubKey();
        CKey out;
        BOOST_REQUIRE(store.GetKey(pubkey.GetID(), out));
        // operator== compares the bytes and the compression flag, which CBitcoinSecret writes into an export.
        BOOST_CHECK(out == key);
        const uint256 hash = GetRandHash();
        std::vector<unsigned char> sig;
        BOOST_CHECK(out.Sign(hash, sig) && pubkey.Verify(hash, sig));
    }

    // Locked again, no key comes out until the master key unlocks it.
    BOOST_REQUIRE(store.Lock());
    CKey out;
    BOOST_CHECK(!store.GetKey(keys[0].GetPubKey().GetID(), out));
    BOOST_CHECK(store.Unlock(master));
    BOOST_CHECK(store.GetKey(keys[0].GetPubKey().GetID(), out));
}

BOOST_AUTO_TEST_SUITE_END()

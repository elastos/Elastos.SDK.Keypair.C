#include "Elastos.Wallet.Utility.h"
#include <string>
#include "BTCKey.h"
#include "WalletTool.h"
#include "ElaController.h"
#include "BigIntFormat.h"
#include "CMemBlock.h"
#include "Mnemonic.h"
#include "BRCrypto.h"

#define NID NID_X9_62_prime256v1

static char* getResultStrEx(const char* src, int len)
{
    char* key = (char*)malloc(sizeof(char) * (len + 1));
    if (!key) {
        return nullptr;
    }
    memcpy(key, src, len);
    key[len] = '\0';

    return key;
}

static char* getResultStr(const CMBlock& mblock)
{
    CMemBlock<char> cmblock;
    cmblock = Hex2Str(mblock);

    return getResultStrEx(cmblock, cmblock.GetSize());
}

char* generatePrivateKey()
{
    CMBlock privateKey, publicKey;
    bool ret = BTCKey::generateKey(privateKey, publicKey, NID);
    if (!ret) {
        return nullptr;
    }

    return getResultStr(privateKey);
}

char* getPublicKey(const char* privateKey)
{
    CMemBlock<char> cPrivatekey;
    cPrivatekey.SetMemFixed(privateKey, strlen(privateKey) + 1);
    CMBlock privKey = Str2Hex(cPrivatekey);
    CMBlock publicKey = BTCKey::getPubKeyFromPrivKey(privKey, NID);

    return getResultStr(publicKey);
}

char* getAddress(const char* publicKey)
{
    CMemBlock<char> cPublickey;
    cPublickey.SetMemFixed(publicKey, strlen(publicKey) + 1);
    CMBlock pubKey = Str2Hex(cPublickey);

    std::string address = BTCKey::getAddressFromPublicKey(pubKey);
    return getResultStrEx(address.c_str(), address.length());
}

char* generateMnemonic(const char* language, const char* path)
{
    CMemBlock<uint8_t> seed128 = WalletTool::GenerateSeed128();
    Mnemonic mnemonic(language, path);
    CMemBlock<char> phrase = WalletTool::GeneratePhraseFromSeed(seed128, mnemonic.words());

    return getResultStrEx(phrase, phrase.GetSize());
}

char* getPrivateKey(const char* mmemonic, const char* language, const char* path)
{
    CMBlock seed = BTCKey::getPrivKeySeed(mmemonic, "", path, language);
    CMemBlock<char> mbcSeed = Hex2Str(seed);
    CMBlock privateKey = BTCKey::getMasterPrivkey(seed);

    return getResultStr(privateKey);
}

int sign(const char* privateKey, const void* data, int len, void** signedData)
{
    CMemBlock<char> cPrivatekey;
    cPrivatekey.SetMemFixed(privateKey, strlen(privateKey) + 1);
    CMBlock privKey = Str2Hex(cPrivatekey);

    UInt256 md = UINT256_ZERO;
    BRSHA256(&md, data, len);

    CMBlock mbSignedData;
    bool ret = BTCKey::ECDSA65Sign_sha256(privKey, md, mbSignedData, NID);
    if (ret) {
        int signedlen = mbSignedData.GetSize();
        void* buf = malloc(signedlen);
        if (!buf) return 0;
        memcpy(buf, mbSignedData, len);
        *signedData = buf;
        return len;
    }

    return ret;
}

bool verify(const char* publicKey, const void* data,
            int len, const void* signedData, int signedLen)
{
    CMemBlock<char> cPublickey;
    cPublickey.SetMemFixed(publicKey, strlen(publicKey) + 1);
    CMBlock pubKey = Str2Hex(cPublickey);

    UInt256 md = UINT256_ZERO;
    BRSHA256(&md, data, len);
    CMBlock mbSignedData;
    mbSignedData.Resize((size_t) signedLen);
    memcpy((void *)mbSignedData, signedData, signedLen);

    return BTCKey::ECDSA65Verify_sha256(pubKey, md, mbSignedData, NID);
}

char* generateRawTransaction(const char* transaction)
{
    std::string rawTransaction = ElaController::genRawTransaction(transaction);

    return getResultStrEx(rawTransaction.c_str(), rawTransaction.length());
}

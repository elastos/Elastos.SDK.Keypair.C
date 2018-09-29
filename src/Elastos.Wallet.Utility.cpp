#include "Elastos.Wallet.Utility.h"
#include <string>
#include "BRBIP32Sequence.h"
#include "WalletTool.h"
#include "ElaController.h"
#include "BigIntFormat.h"
#include "CMemBlock.h"
#include "Mnemonic.h"
#include "BRCrypto.h"
#include "Utils.h"
#include "BRBIP39Mnemonic.h"

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

char* getPublicKey(const char* privateKey)
{
    CMemBlock<char> cPrivatekey;
    cPrivatekey.SetMemFixed(privateKey, strlen(privateKey) + 1);
    CMBlock privKey = Str2Hex(cPrivatekey);
    CMBlock publicKey;
    publicKey.Resize(33);
    getPubKeyFromPrivKey(publicKey, (UInt256 *)(uint8_t *)privKey);

    return getResultStr(publicKey);
}

char* getAddress(const char* publicKey)
{
    CMemBlock<char> cPublickey;
    cPublickey.SetMemFixed(publicKey, strlen(publicKey) + 1);
    CMBlock pubKey = Str2Hex(cPublickey);

    CMBlock code = Utils::getCode(pubKey);

    std::string redeedScript = Utils::encodeHex(code, code.GetSize());

    UInt168 hash = Utils::codeToProgramHash(redeedScript);

    std::string address = Utils::UInt168ToAddress(hash);

    return getResultStrEx(address.c_str(), address.length());
}

char* generateMnemonic(const char* language, const char* path)
{
    CMemBlock<uint8_t> seed128 = WalletTool::GenerateSeed128();
    Mnemonic mnemonic(language, path);
    CMemBlock<char> phrase = WalletTool::GeneratePhraseFromSeed(seed128, mnemonic.words());

    return getResultStrEx(phrase, phrase.GetSize());
}

char* getMasterPrivateKey(const char* mmemonic, const char* language, const char* path, const char* password)
{
    CMemBlock<char> phraseData;
    phraseData.SetMemFixed(mmemonic, strlen(mmemonic) + 1);

    Mnemonic* pMnemonic = new Mnemonic(language, path);
    if (!pMnemonic || !WalletTool::PhraseIsValid(phraseData, pMnemonic->words())) {
        return nullptr;
    }

    UInt512 seed;
    BRBIP39DeriveKey(&seed, mmemonic, password);

    BRKey masterKey;
    BRBIP32APIAuthKey(&masterKey, &seed, sizeof(seed));

    CMBlock privateKey(sizeof(UInt256));
    memcpy(privateKey, &masterKey.secret, sizeof(UInt256));

    delete pMnemonic;
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
    mbSignedData.Resize(65);
    bool ret = ECDSA65Sign_sha256(privKey, privKey.GetSize(), &md, mbSignedData, mbSignedData.GetSize());
    if (ret) {
        int signedlen = mbSignedData.GetSize();
        void* buf = malloc(signedlen);
        if (!buf) return 0;
        memcpy(buf, mbSignedData, signedlen);
        *signedData = buf;
        return signedlen;
    }

    return 0;
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

    return ECDSA65Verify_sha256(pubKey, pubKey.GetSize(), &md, mbSignedData, mbSignedData.GetSize());
}

char* generateRawTransaction(const char* transaction)
{
    std::string rawTransaction = ElaController::genRawTransaction(transaction);

    return getResultStrEx(rawTransaction.c_str(), rawTransaction.length());
}

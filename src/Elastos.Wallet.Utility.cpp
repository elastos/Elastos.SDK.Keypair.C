#include "Elastos.Wallet.Utility.h"
#include <string>
#include "BRBIP32Sequence.h"
#include "WalletTool.h"
#include "ElaController.h"
#include "CMemBlock.h"
#include "Mnemonic.h"
#include "BRCrypto.h"
#include "Utils.h"
#include "BRBIP39Mnemonic.h"
#include "BRAddress.h"
#include "BRBase58.h"

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
    std::string str = Utils::encodeHex(mblock);
    return getResultStrEx(str.c_str(), str.size());
}

static char* getPublicKeyFromPrivateKey(const BRKey& key)
{
    CMBlock privKey;
    privKey.SetMemFixed((uint8_t *) &key.secret, sizeof(key.secret));
    CMBlock result;
    result.Resize(33);
    getPubKeyFromPrivKey(result, (UInt256 *) (uint8_t *) privKey);

    return getResultStr(result);
}

static char* getAddressEx(const char* publicKey, int signType)
{
    if (!publicKey) {
        return nullptr;
    }

    CMBlock pubKey = Utils::decodeHex(publicKey);
    CMBlock code = Utils::getCode(pubKey, signType);

    std::string redeedScript = Utils::encodeHex(code, code.GetSize());

    UInt168 hash = Utils::codeToProgramHash(redeedScript);

    std::string address = Utils::UInt168ToAddress(hash);

    return getResultStrEx(address.c_str(), address.length());
}

static MasterPublicKey* getMasterPublicKey(BRKey& key, const UInt256& chainCode)
{
    CMBlock privKey(sizeof(UInt256));
    privKey.SetMemFixed((uint8_t*)&key.secret, sizeof(key.secret));
    CMBlock publicKey;
    publicKey.Resize(33);
    getPubKeyFromPrivKey(publicKey, (UInt256 *) (uint8_t *) privKey);


    MasterPublicKey* masterKey = new MasterPublicKey();
    if (!masterKey) {
        return nullptr;
    }

    masterKey->fingerPrint = BRKeyHash160(&key).u32[0];
    memcpy(masterKey->chainCode, (uint8_t*)&chainCode, sizeof(chainCode));
    memcpy(masterKey->publicKey, (void *)publicKey, publicKey.GetSize());

    return masterKey;
}

static BRMasterPubKey* toBRMasterPubKey(const MasterPublicKey* pubKey)
{
    BRMasterPubKey* brPublicKey = new BRMasterPubKey();
    if (!brPublicKey) {
        return nullptr;
    }

    brPublicKey->fingerPrint = pubKey->fingerPrint;
    memcpy((uint8_t*)&brPublicKey->chainCode, pubKey->chainCode, sizeof(brPublicKey->chainCode));
    memcpy(brPublicKey->pubKey, pubKey->publicKey, sizeof(brPublicKey->pubKey));

    return brPublicKey;
}

char* getSinglePrivateKey(const void* seed, int seedLen)
{
    if (!seed || seedLen <= 0) {
        return nullptr;
    }

    BRKey masterKey;
    BRBIP32APIAuthKey(&masterKey, seed, seedLen);

    CMBlock cbseed(seedLen);
    memcpy(cbseed, seed, seedLen);

    CMBlock privateKey(sizeof(UInt256));
    memcpy(privateKey, &masterKey.secret, sizeof(UInt256));

    return getResultStr(privateKey);
}

char* getSinglePublicKey(const void* seed, int seedLen)
{
    if (!seed || seedLen <= 0) {
        return nullptr;
    }

    BRKey masterKey;
    BRBIP32APIAuthKey(&masterKey, seed, seedLen);

    return getPublicKeyFromPrivateKey(masterKey);
}

MasterPublicKey* getMasterPublicKey(const void* seed, int seedLen, int coinType)
{
    if (!seed || seedLen <= 0) {
        return nullptr;
    }

    UInt256 chainCode;
    BRKey key;
    BRBIP32PrivKeyPath(&key, &chainCode, seed, seedLen, 3, 44 | BIP32_HARD,
                       coinType | BIP32_HARD, 0 | BIP32_HARD);

    MasterPublicKey* masterKey = getMasterPublicKey(key, chainCode);

    var_clean(&chainCode);

    return masterKey;
}

char* getAddress(const char* publicKey)
{
    return getAddressEx(publicKey, ELA_STANDARD);
}

char* generateMnemonic(const char* language, const char* words)
{
    if (!language || !words) {
        return nullptr;
    }

    CMemBlock<uint8_t> seed128 = WalletTool::GenerateSeed128();
    Mnemonic mnemonic(language, words);
    CMemBlock<char> phrase = WalletTool::GeneratePhraseFromSeed(seed128, mnemonic.words());

    return getResultStrEx(phrase, phrase.GetSize());
}

int getSeedFromMnemonic(void** seed, const char* mmemonic, const char* language, const char* words, const char* mnemonicPassword)
{
    if (!seed || !mmemonic || !language || !words) {
        return 0;
    }

    CMemBlock<char> phraseData;
    phraseData.SetMemFixed(mmemonic, strlen(mmemonic) + 1);

    Mnemonic* pMnemonic = new Mnemonic(language, words);
    if (!pMnemonic || !WalletTool::PhraseIsValid(phraseData, pMnemonic->words())) {
        return 0;
    }

    UInt512 useed;
    BRBIP39DeriveKey(&useed, mmemonic, mnemonicPassword);

    delete pMnemonic;

    int len = sizeof(useed);

    void* result = malloc(len);
    if (!result) {
        return 0;
    }
    memcpy(result, &useed, len);
    *seed = result;

    return len;
}

int sign(const char* privateKey, const void* data, int len, void** signedData)
{
    if (!privateKey || !data || len <= 0 || !signedData) {
        return 0;
    }

    CMBlock privKey = Utils::decodeHex(privateKey);
    UInt256 md = UINT256_ZERO;
    BRSHA256(&md, data, len);

    CMBlock mbSignedData;
    mbSignedData.Resize(65);
    bool ret = ECDSA65Sign_sha256(privKey, privKey.GetSize(), &md, mbSignedData, mbSignedData.GetSize());
    if (ret) {
        int signedlen = mbSignedData.GetSize();
        void* buf = malloc(signedlen);
        if (!buf) return 0;

        // The first byte is the length of signed data.
        memcpy(buf, mbSignedData + 1, signedlen - 1);
        *signedData = buf;
        return signedlen - 1;
    }

    return 0;
}

bool verify(const char* publicKey, const void* data,
            int len, const void* signedData, int signedLen)
{
    if (!publicKey || !data || len <= 0 || !signedData || signedLen <= 0) {
        return false;
    }

    CMBlock pubKey = Utils::decodeHex(publicKey);

    UInt256 md = UINT256_ZERO;
    BRSHA256(&md, data, len);
    CMBlock mbSignedData;
    mbSignedData.Resize((size_t) signedLen + 1);

    // The first byte is the length of signed data.
    mbSignedData[0] = (uint8_t)signedLen;
    memcpy(mbSignedData + 1, signedData, signedLen);

    return ECDSA65Verify_sha256(pubKey, pubKey.GetSize(), &md, mbSignedData, mbSignedData.GetSize());
}

char* generateRawTransaction(const char* transaction)
{
    if (!transaction) {
        return nullptr;
    }
    std::string rawTransaction = ElaController::genRawTransaction(transaction);

    return getResultStrEx(rawTransaction.c_str(), rawTransaction.length());
}

char* generateSubPrivateKey(const void* seed, int seedLen, int coinType, int chain, int index)
{
    if (!seed || seedLen <= 0) {
        return nullptr;
    }

    UInt256 chainCode;
    BRKey key;
    BRBIP32PrivKeyPath(&key, &chainCode, seed, seedLen, 5, 44 | BIP32_HARD,
                        coinType | BIP32_HARD, 0 | BIP32_HARD, chain, index);
    var_clean(&chainCode);

    std::string keyStr = Utils::UInt256ToString(key.secret);

    return getResultStrEx(keyStr.c_str(), keyStr.length());
}

char* generateSubPublicKey(const MasterPublicKey* masterPublicKey, int chain, int index)
{
    if (!masterPublicKey) {
        return nullptr;
    }

    BRMasterPubKey* brPublicKey = toBRMasterPubKey(masterPublicKey);
    if (!brPublicKey) {
        return nullptr;
    }

    size_t len = BRBIP32PubKey(NULL, 0, *brPublicKey, chain, index);
    CMBlock subPubKey(len);
    BRBIP32PubKey(subPubKey, subPubKey.GetSize(), *brPublicKey, chain, index);

    delete brPublicKey;

    return getResultStr(subPubKey);
}

void freeBuf(void* buf)
{
    if (!buf) return;

    free(buf);
}

char* getPublicKeyFromPrivateKey(const char* privateKey)
{
    CMBlock cbPrivateKey = Utils::decodeHex(privateKey);
    BRKey key;
    memcpy(&key.secret, cbPrivateKey, cbPrivateKey.GetSize());

    return getPublicKeyFromPrivateKey(key);
}

bool isAddressValid(const char* address)
{
    bool r = false;
    if (strlen(address) <= 1) {
        return r;
    }
    uint8_t data[42];

    if (BRBase58CheckDecode(data, sizeof(data), address) == 21) {
        r = (data[0] == ELA_STAND_ADDRESS || data[0] == ELA_CROSSCHAIN_ADDRESS ||
                data[0] == ELA_MULTISIG_ADDRESS || data[0] == ELA_IDCHAIN_ADDRESS);
    }

    if (r == 0 && strcmp(address, "1111111111111111111114oLvT2") == 0) {
        r = 1;
    }

    return r;
}

MasterPublicKey* getIdChainMasterPublicKey(const void* seed, int seedLen)
{
    if (!seed || seedLen <= 0) {
        return nullptr;
    }

    BRKey idMasterKey;
    UInt256 idChainCode;
    BRBIP32PrivKeyPath(&idMasterKey, &idChainCode, &seed, sizeof(seed), 1, 0 | BIP32_HARD);

    MasterPublicKey* masterKey = getMasterPublicKey(idMasterKey, idChainCode);

    var_clean(&idChainCode);

    return masterKey;
}

char* generateIdChainSubPrivateKey(const void* seed, int seedLen, int purpose, int index)
{
    if (!seed || seedLen <= 0) {
        return nullptr;
    }

    BRKey key;
    UInt256 chainCode;
    BRBIP32PrivKeyPath(&key, &chainCode, seed, seedLen, 3, 0 | BIP32_HARD, purpose, index);

    var_clean(&chainCode);

    std::string keyStr = Utils::UInt256ToString(key.secret);

    return getResultStrEx(keyStr.c_str(), keyStr.length());
}

char* generateIdChainSubPublicKey(const MasterPublicKey* masterPublicKey, int purpose, int index)
{
    if (!masterPublicKey) {
        return nullptr;
    }

    BRMasterPubKey* brPublicKey = toBRMasterPubKey(masterPublicKey);
    if (!brPublicKey) {
        return nullptr;
    }

    uint8_t pubKey[BRBIP32PubKey(NULL, 0, *brPublicKey, purpose, index)];
    size_t len = BRBIP32PubKey(pubKey, sizeof(pubKey), *brPublicKey, purpose, index);

    delete brPublicKey;

    BRKey rawKey;
    BRKeySetPubKey(&rawKey, pubKey, len);
    CMBlock cbPubKey;
    cbPubKey.SetMemFixed(rawKey.pubKey, len);

    return getResultStr(cbPubKey);
}

char* getDid(const char* publicKey)
{
    return getAddressEx(publicKey, ELA_IDCHAIN);
}

static std::string opToString(char* publicKey)
{
    return std::string(publicKey, strlen(publicKey));
}

char* getMultiSignAddress(char** publicKeys, int length, int requiredSignCount)
{
    if (!publicKeys) {
        return nullptr;
    }

    std::vector<std::string> pubKeys;
    std::transform(publicKeys, publicKeys + length, std::back_inserter(pubKeys), opToString);

    // redeem script -> program hash
    UInt168 programHash = Utils::codeToProgramHash(
            ElaController::GenerateRedeemScript(pubKeys, requiredSignCount));

    // program hash -> address
    std::string address = Utils::UInt168ToAddress(programHash);
    return getResultStrEx(address.c_str(), address.length());
}

char* multiSignTransaction(const char* privateKey,
        char** publicKeys, int length, int requiredSignCount, const char* transaction)
{
    if (!privateKey || !transaction) {
        return nullptr;
    }

    std::vector<std::string> pubKeys;
    std::transform(publicKeys, publicKeys + length, std::back_inserter(pubKeys), opToString);

    std::string signedStr = ElaController::MultiSignTransaction(
            privateKey, requiredSignCount, pubKeys, transaction);
    return getResultStrEx(signedStr.c_str(), signedStr.length());
}

char* serializeMultiSignTransaction(const char* transaction)
{
    if (!transaction) {
        return nullptr;
    }

    std::string serialized = ElaController::SerializeTransaction(transaction);
    return getResultStrEx(serialized.c_str(), serialized.length());
}


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
#include "crypto/ecies.h"

const int EXTERNAL_CHAIN    = 0;
const int INTERNAL_CHAIN    = 1;

const int  COIN_TYPE_ELA    = 0;
const int COIN_TYPE_IDCHAIN = 1;

const char* ELA_ASSERT_ID   = "a3d0eaa466df74983b5d7c543de6904f4c9418ead5ffd6d25814234a96db37b0";

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
        throw std::logic_error("Invalid parameter.");
    }

    CMBlock pubKey;
    try {
        pubKey = Utils::decodeHex(publicKey);
    }
    catch (std::logic_error err) {
        printf("decodeHex exception: %s", err.what());
        return nullptr;
    }

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

char* generateSubPrivateKey(const void* seed, int seedLen, int coinType, int chain, int index);

char* getSinglePrivateKey(const void* seed, int seedLen)
{
    if (!seed || seedLen <= 0) {
        throw std::logic_error("Invalid parameter.");
    }

    return generateSubPrivateKey(seed, seedLen, COIN_TYPE_ELA, EXTERNAL_CHAIN, 0);
}

char* getSinglePublicKey(const void* seed, int seedLen)
{
    if (!seed || seedLen <= 0) {
        throw std::logic_error("Invalid parameter.");
    }

    char* privateKey = getSinglePrivateKey(seed, seedLen);
    char* publicKey = getPublicKeyFromPrivateKey(privateKey);
    free(privateKey);
    return publicKey;
}

MasterPublicKey* getMasterPublicKey(const void* seed, int seedLen, int coinType)
{
    if (!seed || seedLen <= 0) {
        throw std::logic_error("Invalid parameter.");
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
        throw std::logic_error("Invalid parameter.");
    }

    CMemBlock<uint8_t> seed128 = WalletTool::GenerateSeed128();
    Mnemonic mnemonic(language, words);
    CMemBlock<char> phrase = WalletTool::GeneratePhraseFromSeed(seed128, mnemonic.words());

    return getResultStrEx(phrase, phrase.GetSize());
}

int getSeedFromMnemonic(void** seed, const char* mnemonic, const char* mnemonicPassword)
{
    if (!seed || !mnemonic || !mnemonicPassword) {
        throw std::logic_error("Invalid parameter.");
    }

    UInt512 useed;
    BRBIP39DeriveKey(&useed, mnemonic, mnemonicPassword);

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

    CMBlock privKey;
    try {
        privKey = Utils::decodeHex(privateKey);
    }
    catch (std::logic_error err) {
        printf("decodeHex exception: %s", err.what());
        return 0;
    }

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

    CMBlock pubKey;
    try {
        pubKey = Utils::decodeHex(publicKey);
    }
    catch (std::logic_error err) {
        printf("decodeHex exception: %s", err.what());
        return false;
    }

    UInt256 md = UINT256_ZERO;
    BRSHA256(&md, data, len);
    CMBlock mbSignedData;
    mbSignedData.Resize((size_t) signedLen + 1);

    // The first byte is the length of signed data.
    mbSignedData[0] = (uint8_t)signedLen;
    memcpy(mbSignedData + 1, signedData, signedLen);

    return ECDSA65Verify_sha256(pubKey, pubKey.GetSize(), &md, mbSignedData, mbSignedData.GetSize());
}

char* generateRawTransaction(const char* transaction, const char* assertId)
{
    if (!transaction) {
        return nullptr;
    }
    std::string rawTransaction = ElaController::genRawTransaction(transaction, assertId);

    return getResultStrEx(rawTransaction.c_str(), rawTransaction.length());
}

char* deserializeRawTransaction(const char* transaction)
{
    if (!transaction) {
        return nullptr;
    }

    std::string json =  ElaController::deserializeRawTransaction(transaction);
    return getResultStrEx(json.c_str(), json.length());
}

char* generateSubPrivateKey(const void* seed, int seedLen, int coinType, int chain, int index)
{
    if (!seed || seedLen <= 0) {
        throw std::logic_error("Invalid parameter.");
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
        throw std::logic_error("Invalid parameter.");
    }

    BRMasterPubKey* brPublicKey = toBRMasterPubKey(masterPublicKey);
    if (!brPublicKey) {
        throw std::logic_error("Out of memory.");
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
    if (!privateKey) {
        throw std::logic_error("Invalid parameter.");
    }

    CMBlock cbPrivateKey;
    try {
        cbPrivateKey = Utils::decodeHex(privateKey);
    }
    catch (std::logic_error err) {
        printf("decodeHex exception: %s", err.what());
        return nullptr;
    }

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
        throw std::logic_error("Invalid parameter.");
    }

    // check public key is valid
    std::vector<std::string> pubKeys;
    std::transform(publicKeys, publicKeys + length, std::back_inserter(pubKeys), opToString);
    for (std::string pubkey : pubKeys) {
        if (!(pubkey.length() == 66 || pubkey.length() == 130)) {
            printf("Invalid public key: %s\n", pubkey.c_str());
            return nullptr;
        }
    }

    // redeem script -> program hash
    UInt168 programHash = Utils::codeToProgramHash(
            ElaController::GenerateRedeemScript(pubKeys, requiredSignCount));

    // program hash -> address
    std::string address = Utils::UInt168ToAddress(programHash);
    return getResultStrEx(address.c_str(), address.length());
}

char* multiSignTransaction(const char* privateKey,
        char** publicKeys, int length, int requiredSignCount, const char* transaction, const char* assertId)
{
    if (!privateKey || !transaction) {
        return nullptr;
    }

    std::vector<std::string> pubKeys;
    std::transform(publicKeys, publicKeys + length, std::back_inserter(pubKeys), opToString);

    std::string signedStr = ElaController::MultiSignTransaction(
            privateKey, requiredSignCount, pubKeys, transaction, assertId);
    return getResultStrEx(signedStr.c_str(), signedStr.length());
}

char** getSignedSigners(const char* transaction, int* outLen, const char* assertId)
{
    if (!outLen) {
        return nullptr;
    }

    std::vector<std::string> signers = ElaController::GetSignedSigners(transaction, assertId);
    int len = signers.size();
    if (len == 0) {
        printf("no one signed\n");
        return nullptr;
    }

    char** result = (char**)malloc(len);
    if (!result) {
        printf("out of memory\n");
        return nullptr;
    }

    int offset = 0;
    for (int i = 0; i < len; i++) {
        result[i] = (char*)malloc(sizeof(char) * (66 + 1));
        strcpy(result[i], signers[i].c_str());
    }

    *outLen = len;
    return result;
}

char* serializeMultiSignTransaction(const char* transaction, const char* assertId)
{
    if (!transaction) {
        return nullptr;
    }

    std::string serialized = ElaController::SerializeTransaction(transaction, assertId);
    return getResultStrEx(serialized.c_str(), serialized.length());
}

char* eciesEncrypt(const char* publicKey, const unsigned char * plainText, int length)
{
    if (!publicKey || !plainText) {
        return nullptr;
    }

    cipher_t* cipher = ecies_encrypt(publicKey, (const unsigned char *)plainText, length);
    if (cipher == nullptr) {
        return nullptr;
    }
    uint64_t keyLen = get_cipher_length(CipherType_Key, cipher);
    uint64_t macLen = get_cipher_length(CipherType_MAC, cipher);
    uint64_t origLen = get_cipher_length(CipherType_Orig, cipher);
    uint64_t bodyLen = get_cipher_length(CipherType_Body, cipher);

    ByteStream ostream;
    ostream.putVarUint(keyLen);
    ostream.putVarUint(macLen);
    ostream.putVarUint(origLen);
    ostream.putVarUint(bodyLen);

    ostream.writeBytes(get_cipher_data(CipherType_Key, cipher), keyLen);
    ostream.writeBytes(get_cipher_data(CipherType_MAC, cipher), macLen);
    ostream.writeBytes(get_cipher_data(CipherType_Body, cipher), bodyLen);

    cipher_free(cipher);

    std::string result = Utils::encodeHex(ostream.getBuffer());

    return getResultStrEx(result.c_str(), result.length());
}

unsigned char* eciesDecrypt(const char* privateKey, const char* cipherText, int* len)
{
    if (!privateKey || !cipherText || !len) {
        return nullptr;
    }

    CMBlock data;
    try {
        data = Utils::decodeHex(cipherText);
    }
    catch (std::logic_error err) {
        printf("decodeHex exception: %s", err.what());
        return nullptr;
    }

    ByteStream ostream(data, data.GetSize(), false);
    uint64_t keyLen = ostream.getVarUint();
    uint64_t macLen = ostream.getVarUint();
    uint64_t origLen = ostream.getVarUint();
    uint64_t bodyLen = ostream.getVarUint();

    cipher_t* cipher = (cipher_t*)cipher_alloc(keyLen, macLen, origLen, bodyLen);
    if (!cipher) {
        return nullptr;
    }

    void* key = get_cipher_data(CipherType_Key, cipher);
    ostream.readBytes(key, keyLen);

    void* mac = get_cipher_data(CipherType_MAC, cipher);
    ostream.readBytes(mac, macLen);

    void* body = get_cipher_data(CipherType_Body, cipher);
    ostream.readBytes(body, bodyLen);

    size_t plainLen = -1;
    unsigned char* plain = ecies_decrypt(privateKey, cipher, &plainLen);
    *len = plainLen;
    cipher_free(cipher);
    return plain;
}

char* getPublicKeyFromXpub(const char* xpub, int chain, int index)
{
    size_t size = BRBase58CheckDecode(NULL, 0, xpub);
    uint8_t* data = (uint8_t*)malloc(size);
    if (!data) return NULL;

    BRBase58CheckDecode(data, size, xpub);

    // 4 byte: version bytes (mainnet: 0x0488B21E public, 0x0488ADE4 private; testnet: 0x043587CF public, 0x04358394 private)
    // 1 byte: depth: 0x00 for master nodes, 0x01 for level-1 derived keys, ....
    // 4 bytes: the fingerprint of the parent's key (0x00000000 if master key)
    // 4 bytes: child number. This is ser32(i) for i in xi = xpar/i, with xi the key being serialized. (0x00000000 if master key)
    // 32 bytes: the chain code
    // 33 bytes: the public key or private key data (serP(K) for public keys, 0x00 || ser256(k) for private keys)
    MasterPublicKey* masterPublicKey = new MasterPublicKey();
    if (!masterPublicKey) {
        free(data);
        return NULL;
    }

    memcpy(&masterPublicKey->fingerPrint, data + 5, 4);
    memcpy(masterPublicKey->chainCode, data + 13, 32);
    memcpy(masterPublicKey->publicKey, data + 45, 33);

    char* pubkey = generateSubPublicKey(masterPublicKey, chain, index);
    free(data);
    delete masterPublicKey;

    return pubkey;
}

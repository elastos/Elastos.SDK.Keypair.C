#include "FileCoin.hpp"

#include <filecoin-signer-ffi.h>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <sstream>

#include "Elastos.Wallet.Utility.h"
#include "Utils.h"

namespace FileCoin {

static std::shared_ptr<ExternError> MakeFileCoinError();
static std::string base64Encode(const uint8_t* data, int size);

int GetSeedFromMnemonic(void** seed, const char* mnemonic, const char* mnemonicPassword)
{
    if (!seed || !mnemonic || !mnemonicPassword) {
        throw std::logic_error("Invalid parameter.");
    }

    return getSeedFromMnemonic(seed, mnemonic, mnemonicPassword);

    // auto fcError = MakeFileCoinError();

    // auto creater = [&]() -> char* {
    //     auto ptr = elastos_filecoin_signer_get_seed_from_mnemonic(mnemonic, mnemonicPassword, fcError.get());
    //     return ptr;
    // };
    // auto deleter = [=](char *ptr) -> void {
    //     filecoin_signer_string_free(ptr);
    // };
    // auto fcSeedHexStr = std::shared_ptr<char>(creater(), deleter);
    // if(fcSeedHexStr.get() == nullptr || fcError->code != 0) {
    //     printf("Failed filecoin-signer get seed from mnemonic: %s\n", fcError->message);
    //     return -1;
    // }

    // int seedLen = strlen(fcSeedHexStr.get()) / 2;
    // *seed = malloc(seedLen);
    // if (!(*seed)) {
    //     return -1;
    // }
    // Utils::decodeHex((uint8_t*)(*seed), seedLen, fcSeedHexStr.get(), seedLen * 2);

    // return seedLen;
}

char* GetSinglePrivateKey(const void* seed, int seedLen)
{
    if (!seed || seedLen <= 0) {
        throw std::logic_error("Invalid parameter.");
    }

    const char* path = "m/44'/461'/0'/0/0";
    auto fcError = MakeFileCoinError();

    auto creater = [&]() -> char* {
        auto ptr = elastos_filecoin_signer_get_privkey_from_seed((uint8_t*)seed, seedLen, path, fcError.get());
        return ptr;
    };
    auto deleter = [=](char *ptr) -> void {
        filecoin_signer_string_free(ptr);
    };
    auto fcPrivateKey = std::shared_ptr<char>(creater(), deleter);
    if(fcPrivateKey.get() == nullptr || fcError->code != 0) {
        printf("Failed filecoin-signer make private key: %s\n", fcError->message);
        return nullptr;
    }

    // printf("%s ret=%s\n", __PRETTY_FUNCTION__, fcPrivateKey.get());
    return strdup(fcPrivateKey.get());
}

char* GetSinglePublicKey(const void* seed, int seedLen)
{
    if (!seed || seedLen <= 0) {
        throw std::logic_error("Invalid parameter.");
    }

    char* privateKey = FileCoin::GetSinglePrivateKey(seed, seedLen);
    char* publicKey = FileCoin::GetPublicKeyFromPrivateKey(privateKey);
    free(privateKey);

    // printf("%s ret=%s\n", __PRETTY_FUNCTION__, publicKey);
    return publicKey;
}

char* GetPublicKeyFromPrivateKey(const char* privateKey)
{
    if (!privateKey) {
        throw std::logic_error("Invalid parameter.");
    }

    auto fcError = MakeFileCoinError();

    auto creater = [&]() -> char* {
        auto ptr = elastos_filecoin_signer_get_pubkey_from_privkey(privateKey, fcError.get());
        return ptr;
    };
    auto deleter = [=](char *ptr) -> void {
        filecoin_signer_string_free(ptr);
    };
    auto fcPublicKey = std::shared_ptr<char>(creater(), deleter);
    if(fcPublicKey.get() == nullptr || fcError->code != 0) {
        printf("Failed filecoin-signer make public key: %s\n", fcError->message);
        return nullptr;
    }

    // printf("%s ret=%s\n", __PRETTY_FUNCTION__, fcPublicKey.get());
    return strdup(fcPublicKey.get());
}

char* GetAddress(const char* publicKey)
{
    if (!publicKey) {
        throw std::logic_error("Invalid parameter.");
    }

    auto fcError = MakeFileCoinError();

    auto creater = [&]() -> char* {
        auto ptr = elastos_filecoin_signer_get_address(publicKey, fcError.get());
        return ptr;
    };
    auto deleter = [=](char *ptr) -> void {
        filecoin_signer_string_free(ptr);
    };
    auto fcAddress = std::shared_ptr<char>(creater(), deleter);
    if(fcAddress.get() == nullptr || fcError->code != 0) {
        printf("Failed filecoin-signer make address: %s\n", fcError->message);
        return nullptr;
    }

    return strdup(fcAddress.get());
}

int Sign(const char* privateKey,
         const void* data, int len,
         void** signedData)
{
    if (!privateKey || !data || !signedData) {
        throw std::logic_error("Invalid parameter.");
    }

    auto fcError = MakeFileCoinError();

    auto creater = [&]() -> char* {
        auto ptr = elastos_filecoin_signer_sign(privateKey, (uint8_t*)data, len, fcError.get());
        return ptr;
    };
    auto deleter = [=](char *ptr) -> void {
        filecoin_signer_string_free(ptr);
    };
    auto fcSignHexStr = std::shared_ptr<char>(creater(), deleter);
    if(fcSignHexStr.get() == nullptr || fcError->code != 0) {
        printf("Failed filecoin-signer sign: %s\n", fcError->message);
        return -1;
    }

    int signedLen = strlen(fcSignHexStr.get()) / 2;
    *signedData = malloc(signedLen);
    if (!(*signedData)) {
        return -1;
    }
    Utils::decodeHex((uint8_t*)(*signedData), signedLen, fcSignHexStr.get(), signedLen * 2);

    return signedLen;
}

bool Verify(const char* publicKey,
            const void* data, int len,
            const void* signedData, int signedLen)
{
    if (!publicKey || !data || !signedData) {
        throw std::logic_error("Invalid parameter.");
    }

    auto fcError = MakeFileCoinError();

    auto creater = [&]() -> char* {
        auto ptr = elastos_filecoin_signer_verify(publicKey, (uint8_t*)signedData, signedLen, (uint8_t*)data, len, fcError.get());
        return ptr;
    };
    auto deleter = [=](char *ptr) -> void {
        filecoin_signer_string_free(ptr);
    };
    auto fcVerifyStr = std::shared_ptr<char>(creater(), deleter);
    if(fcVerifyStr.get() == nullptr || fcError->code != 0) {
        printf("Failed filecoin-signer verify: %s\n", fcError->message);
        return -1;
    }

    return (std::string(fcVerifyStr.get()) == "t");
}

char* GenerateRawTransaction(const char* privateKey, const char* transaction)
{
    if (!privateKey || !transaction) {
        throw std::logic_error("Invalid parameter.");
    }

    auto fcError = MakeFileCoinError();

    auto creater = [&]() -> char* {
        auto ptr = elastos_filecoin_signer_serialize_tx(transaction, fcError.get());
        return ptr;
    };
    auto deleter = [=](char *ptr) -> void {
        filecoin_signer_string_free(ptr);
    };
    auto fcTxHexStr = std::shared_ptr<char>(creater(), deleter);
    if(fcTxHexStr.get() == nullptr || fcError->code != 0) {
        printf("Failed filecoin-signer gen raw tx: %s\n", fcError->message);
        return nullptr;
    }

    int txHexLen = strlen(fcTxHexStr.get()) / 2;
    uint8_t* txHex = (uint8_t*)malloc(txHexLen);
    if (!txHex) {
        return nullptr;
    }
    Utils::decodeHex(txHex, txHexLen, fcTxHexStr.get(), txHexLen * 2);

    uint8_t* signature;
    int signSize = FileCoin::Sign(privateKey, txHex, txHexLen, (void**)&signature);
    // printf("filecoin signed data len: %d\n", signSize);

    auto signBase64 = base64Encode(signature, signSize);
    printf("signature : %s\n", signBase64.c_str());

    std::stringstream signedData;
    signedData << "{";
    signedData <<   "\"Message\": "<< transaction << ",";
    signedData <<   "\"Signature\": {";
    signedData <<       "\"Type\": 1,";
    signedData <<       "\"Data\": \"" << signBase64 << "\"";
    signedData <<   "}";
    signedData << "}";
    // printf("filecoin signed data: %s\n", signedData.str().c_str());

    return strdup(signedData.str().c_str());
}

static std::shared_ptr<ExternError> MakeFileCoinError()
{
    auto creater = [&]() -> ExternError* {
        auto ptr = filecoin_signer_error_new();
        return ptr;
    };
    auto deleter = [=](ExternError *ptr) -> void {
        filecoin_signer_error_free(ptr);
    };
    
    return std::shared_ptr<ExternError>(creater(), deleter);
}

static std::string base64Encode(const uint8_t* data, int size)
{
    BIO* b64 = BIO_new(BIO_f_base64());
    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
    BIO* sink = BIO_new(BIO_s_mem());
    BIO_push(b64, sink);
    BIO_write(b64, data, size);
    BIO_flush(b64);

    const char* encoded;
    const long len = BIO_get_mem_data(sink, &encoded);

    auto ret = std::string(encoded, len);

    BIO_free_all(b64);
    return ret;
}

} // namespace FileCoin

#include "FileCoin.hpp"

#include "Elastos.Wallet.Utility.h"
#include "Utils.h"
#include <filcrypto.h>
#include <core/primitives/address/address_codec.hpp>
#include <vm/message/message_util.hpp>
// #include <vm/actor/actor.hpp>
// #include "crypto/bls/impl/bls_provider_impl.hpp"
#include "Base64.h"
#include "nlohmann/json.hpp"

namespace FileCoin {

static fc::vm::message::UnsignedMessage
parseUnsignedMessage(const char* txStr);

char* GetSinglePrivateKey(const void* seed, int seedLen)
{
    auto resp = fil_private_key_generate_with_seed(*(fil_32ByteArray*)seed);
    if(resp == nullptr) {
        printf("Failed fil priv key with seed\n");
        return nullptr;
    }

    auto str = Utils::encodeHex(resp->private_key.inner, PRIVATE_KEY_BYTES);

    // printf("=== privkey string: %s\n", str.c_str());
    // printf("=== privkey buf: ");
    // for(int idx = 0; idx < PRIVATE_KEY_BYTES; idx++) {
    //     printf(" %x", resp->private_key.inner[idx]);
    // }
    // printf("\n");

    fil_destroy_private_key_generate_response(resp);

    return strdup(str.c_str());
}

char* GetSinglePublicKey(const void* seed, int seedLen)
{
    if (!seed || seedLen <= 0) {
        throw std::logic_error("Invalid parameter.");
    }

    char* privateKey = GetSinglePrivateKey(seed, seedLen);
    char* publicKey = GetPublicKeyFromPrivateKey(privateKey);
    freeBuf(privateKey);

    return publicKey;
}

char* GetPublicKeyFromPrivateKey(const char* privateKey)
{
    uint8_t filPrivKey[PRIVATE_KEY_BYTES];
    try {
        Utils::decodeHex(filPrivKey, sizeof(filPrivKey), privateKey, strlen(privateKey));
    } catch (std::logic_error err) {
        printf("decodeHex exception: %s\n", err.what());
        return nullptr;
    }
    // printf("*** privkey string: %s\n", privateKey);
    // printf("*** privkey buf: ");
    // for(int idx = 0; idx < PRIVATE_KEY_BYTES; idx++) {
    //     printf(" %x", privKeyResp.private_key.inner[idx]);
    // }
    // printf("\n");

    auto resp = fil_private_key_public_key(filPrivKey);
    if(resp == nullptr) {
        printf("Failed fil priv to pub key\n");
        return nullptr;
    }

    auto str = Utils::encodeHex(resp->public_key.inner, PUBLIC_KEY_BYTES);

    fil_destroy_private_key_public_key_response(resp);

    return strdup(str.c_str());
}

char* GetAddress(const char* publicKey)
{
    uint8_t filPubKey[PUBLIC_KEY_BYTES];
    try {
        Utils::decodeHex(filPubKey, sizeof(filPubKey), publicKey, strlen(publicKey));
    } catch (std::logic_error err) {
        printf("decodeHex exception: %s\n", err.what());
        return nullptr;
    }

    fc::primitives::address::BlsPublicKey filBlsPubKey;
    std::copy_n(filPubKey, sizeof(filPubKey), filBlsPubKey.begin());
    // auto filBlsPubKey = BlsPublicKey(std::begin(filPubKey), std::end(filPubKey));
    auto filAddr = fc::primitives::address::Address::makeBls(filBlsPubKey);
    auto addr = fc::primitives::address::encodeToString(filAddr);

    return strdup(addr.c_str());
}

int Sign(const char* privateKey,
         const void* data, int len,
         void** signedData)
{
    uint8_t filPrivKey[PRIVATE_KEY_BYTES];
    try {
        Utils::decodeHex(filPrivKey, sizeof(filPrivKey), privateKey, strlen(privateKey));
    } catch (std::logic_error err) {
        printf("decodeHex exception: %s\n", err.what());
        return -1;
    }

    auto resp = fil_private_key_sign(filPrivKey, (uint8_t*)data, len);
    if(resp == nullptr) {
        printf("Failed fil priv key sign\n");
        return -1;
    }

    int signedLen = sizeof(resp->signature.inner);
    *signedData = malloc(signedLen);
    if(*signedData == nullptr) {
        printf("Failed malloc sign data\n");
        return -1;
    }
    memcpy(*signedData, resp->signature.inner, signedLen);

    fil_destroy_private_key_sign_response(resp);

    return signedLen;
}

bool Verify(const char* publicKey,
            const void* data, int len,
            const void* signedData, int signedLen)
{
    uint8_t filPubKey[PUBLIC_KEY_BYTES];
    try {
        Utils::decodeHex(filPubKey, sizeof(filPubKey), publicKey, strlen(publicKey));
    } catch (std::logic_error err) {
        printf("decodeHex exception: %s\n", err.what());
        return false;
    }

    auto hashResp = fil_hash((uint8_t*)data, len);
    if(hashResp == nullptr) {
        printf("Failed hash origin data\n");
        return -1;
    }

    auto resp = fil_verify((uint8_t*)signedData,
                           hashResp->digest.inner, sizeof(hashResp->digest.inner),
                           filPubKey, sizeof(filPubKey));

    fil_destroy_hash_response(hashResp);

    return resp;
}

char* GenerateRawTransaction(const char* privateKey, const char* transaction)
{
    auto unsignedMsg = parseUnsignedMessage(transaction);
    if(unsignedMsg.version < 0) {
        printf("Failed to parse unsigned message. transaction: %s\n", transaction);
        return nullptr;
    }

    auto unsignedMsgCid = fc::vm::message::cid(unsignedMsg);
    auto unsignedMsgSerialized = unsignedMsgCid.value().toBytes().value();
    printf("unsignedMsgSerialized size: %zu\n", unsignedMsgSerialized.size());

    uint8_t* signature;
    int signSize = FileCoin::Sign(privateKey, (void*)unsignedMsgSerialized.data(), unsignedMsgSerialized.size(), (void**)&signature);
    printf("filecoin signed data len: %d\n", signSize);

    auto signBase64 = Base64::fromBits(signature, signSize);
    printf("signature : %s\n", signBase64.c_str());

    std::stringstream signedData;
    signedData << "{";
    signedData <<   "\"Message\": "<< transaction << ",";
    signedData <<   "\"Signature\": {";
    signedData <<       "\"Type\": 2,";
    signedData <<       "\"Data\": \"" << signBase64 << "\"";
    signedData <<   "}";
    signedData << "}";
    // printf("filecoin signed data: %s\n", signedData.str().c_str());

    return strdup(signedData.str().c_str());
}

static fc::vm::message::UnsignedMessage
parseUnsignedMessage(const char* txStr) {
    fc::vm::message::UnsignedMessage umsg;
    nlohmann::json umsgJson = nlohmann::json::parse(txStr);

    umsg.version = -1;
    try {
        umsg.version = fc::vm::message::kMessageVersion;
        umsg.to = fc::primitives::address::decodeFromString(umsgJson["to"].get<std::string>()).value();
        umsg.from = fc::primitives::address::decodeFromString(umsgJson["from"].get<std::string>()).value();
        umsg.nonce = umsgJson["nonce"];

        umsg.value = std::stoll(umsgJson["value"].get<std::string>());
        umsg.gas_fee_cap = std::stoll(umsgJson["gasFeeCap"].get<std::string>());
        umsg.gas_premium = std::stoll(umsgJson["gasPremium"].get<std::string>());
        umsg.gas_limit = umsgJson["gasLimit"].get<uint64_t>();

        umsg.method = fc::vm::actor::MethodNumber{0};
        umsg.params = fc::vm::actor::MethodParams{};
    } catch (const std::exception &e) {
        printf("Failed parse unsigned message json string.\n");
    }

    return umsg;
}

} // namespace FileCoin

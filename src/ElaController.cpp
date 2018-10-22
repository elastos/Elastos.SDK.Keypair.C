
#include "Utils.h"
#include "nlohmann/json.hpp"
#include "Transaction/Transaction.h"
#include "Transaction/UTXOInput.h"
#include "Transaction/TxOutput.h"
#include "ElaController.h"
#include "BRAddress.h"
#include "secp256k1.h"
#include "BigIntegerLibrary.hh"
#include "BRKey.h"

struct {
    bool operator()(const std::string &a, const std::string &b) const
    {
        secp256k1_pubkey pk;

        CMBlock cbA = Utils::decodeHex(a);
        if (0 == BRKeyPubKeyDecode(&pk, cbA, cbA.GetSize())) {
            printf("Public key: %s decode error\n", a.c_str());
        }
        BigInteger bigIntA = dataToBigInteger(pk.data, sizeof(pk.data) / 2, BigInteger::Sign::positive);

        CMBlock cbB = Utils::decodeHex(b);
        if (0 == BRKeyPubKeyDecode(&pk, cbB, cbB.GetSize())) {
            printf("Public key: %s decode error\n", b.c_str());
        }
        BigInteger bigIntB = dataToBigInteger(pk.data, sizeof(pk.data) / 2, BigInteger::Sign::positive);

        return bigIntA <= bigIntB;
    }
} CustomCompare;

Transaction* ElaController::GenTransactionFromJson(const std::string json)
{
    nlohmann::json txJson = nlohmann::json::parse(json);
    std::vector<nlohmann::json> transactions = txJson["Transactions"];

    nlohmann::json jTransaction = transactions[0];

    Transaction* transaction = new Transaction();
    if (!transaction) {
        return nullptr;
    }

    transaction->FromJson(jTransaction);

    return transaction;
}

std::string ElaController::genRawTransaction(const std::string jsonStr)
{
    Transaction* transaction = GenTransactionFromJson(jsonStr);
    if (!transaction) {
        return nullptr;
    }

    std::vector<CMBlock> privateKeys = transaction->GetPrivateKeys();
    for (CMBlock privateKey : privateKeys) {
        transaction->Sign(privateKey);
    }

    ByteStream ostream;
    transaction->Serialize(ostream);
    delete transaction;

    return Utils::encodeHex(ostream.getBuffer());
}

CMBlock ElaController::GenerateRedeemScript(std::vector<std::string> publicKeys, int requiredSignCount)
{
    std::vector<std::string> sortedSigners(publicKeys.begin(), publicKeys.end());
    std::sort(sortedSigners.begin(), sortedSigners.end(), CustomCompare);

    ByteStream stream;
    stream.writeUint8(uint8_t(OP_1 + requiredSignCount - 1));
    for (size_t i = 0; i < sortedSigners.size(); i++) {
        CMBlock pubKey = Utils::decodeHex(sortedSigners[i]);
        stream.writeUint8(uint8_t(pubKey.GetSize()));
        stream.writeBytes(pubKey, pubKey.GetSize());
    }

    stream.writeUint8(uint8_t(OP_1 + sortedSigners.size() - 1));
    stream.writeUint8(ELA_MULTISIG);

    return stream.getBuffer();
}

std::string ElaController::SerializeTransaction(const std::string json)
{
    Transaction* transaction = GenTransactionFromJson(json);
    if (!transaction) {
        return nullptr;
    }

    ByteStream ostream;
    transaction->Serialize(ostream);
    delete transaction;

    return Utils::encodeHex(ostream.getBuffer());
}

std::string ElaController::MultiSignTransaction(const std::string privateKey,
        int requiredSignCount, std::vector<std::string> publicKeys, const std::string json)
{
    Transaction* transaction = GenTransactionFromJson(json);
    if (!transaction) {
        return nullptr;
    }

    CMBlock redeemScript = GenerateRedeemScript(publicKeys, requiredSignCount);
    CMBlock cbPrivateKey = Utils::decodeHex(privateKey);
    transaction->MultiSign(cbPrivateKey, redeemScript);

    nlohmann::json transactionJson = transaction->ToJson();
    delete transaction;

    nlohmann::json jsonData;
    std::vector<nlohmann::json> transactions;
    transactions.push_back(transactionJson);
    jsonData["Transactions"] = transactions;

    return jsonData.dump();
}


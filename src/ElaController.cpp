
#include "Utils.h"
#include "nlohmann/json.hpp"
#include "Transaction/Transaction.h"
#include "Transaction/UTXOInput.h"
#include "Transaction/TxOutput.h"
#include "ElaController.h"

using json = nlohmann::json;


std::string ElaController::genRawTransaction(std::string jsonStr)
{
    json txJson = json::parse(jsonStr);
    std::vector<json> transactions = txJson["Transactions"];

    json jTransaction = transactions[0];
    std::vector<json> jUtxoInputs = jTransaction["UTXOInputs"];

    std::vector<UTXOInput*> utxoInputs;
    for (json utxoInput : jUtxoInputs) {
        std::string txid = utxoInput["txid"].get<std::string>();
        uint32_t index = utxoInput["index"].get<uint32_t>();
        std::string privateKey = utxoInput["privateKey"].get<std::string>();
        std::string address = utxoInput["address"].get<std::string>();

        UTXOInput* input = new UTXOInput(txid, index, privateKey, address);
        if (input) {
            utxoInputs.push_back(input);
        }
    }

    std::vector<json> jTxOuputs = jTransaction["Outputs"];
    std::vector<TxOutput*> outputs;
    for(json txOutput : jTxOuputs) {
        std::string address = txOutput["address"].get<std::string>();
        uint64_t amount = txOutput["amount"].get<uint64_t>();

        TxOutput* output = new TxOutput(address, amount);
        if (output) {
            outputs.push_back(output);
        }
    }

    //TODO: add memo

    Transaction* transaction = new Transaction(utxoInputs, outputs);
    if (!transaction)
    {

        for (UTXOInput* input : utxoInputs) {
            delete input;
        }
        utxoInputs.clear();

        for (TxOutput* output : outputs) {
            delete output;
        }
        outputs.clear();

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

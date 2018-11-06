
#include "UTXOInput.h"
#include "log.h"

void UTXOInput::Serialize(ByteStream& ostream)
{
    ostream.writeBytes(mReferTxid.u8, sizeof(UInt256));
    ostream.writeUint16((uint16_t)mReferTxOutputIndex);
    ostream.writeUint32(mSequence);
}

void UTXOInput::FromJson(const nlohmann::json &jsonData)
{
    std::string txid = jsonData["txid"].get<std::string>();
    mReferTxid = Utils::UInt256FromString(txid, true);

    mReferTxOutputIndex = jsonData["index"].get<uint32_t>();
    auto jPrivateKey = jsonData.find("privateKey");
    if (jPrivateKey != jsonData.end()) {
        std::string privateKey = jsonData["privateKey"].get<std::string>();
        mPrivateKey = Utils::decodeHex(privateKey);
    }
    else {
        WALLET_C_LOG("input do not include private key.\n");
    }

    mAddress = jsonData["address"].get<std::string>();
    Utils::UInt168FromAddress(mProgramHash, mAddress);
}

nlohmann::json UTXOInput::ToJson()
{
    nlohmann::json jsonData;
    jsonData["txid"] = Utils::UInt256ToString(mReferTxid, true);
    jsonData["index"] = mReferTxOutputIndex;
    if (mPrivateKey.GetSize() != 0) {
        jsonData["privateKey"] = Utils::encodeHex(mPrivateKey);
    }
    jsonData["address"] = mAddress;

    return jsonData;
}

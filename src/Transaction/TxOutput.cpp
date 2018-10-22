
#include "TxOutput.h"


void TxOutput::Serialize(ByteStream& ostream)
{
    ostream.writeBytes(mAssetId.u8, sizeof(mAssetId));
    ostream.writeUint64(mAmount);
    ostream.writeUint32(mOutputLock);
    ostream.writeBytes(mProgramHash.u8, sizeof(mProgramHash));
}

void TxOutput::FromJson(const nlohmann::json &jsonData)
{
    mAddress = jsonData["address"].get<std::string>();
    mAmount = jsonData["amount"].get<uint64_t>();

    if (!mAddress.compare(DESTROY_ADDRESS)) {
        mProgramHash = UINT168_ZERO;
    }
    else {
        Utils::UInt168FromAddress(mProgramHash, mAddress);
    }
}

nlohmann::json TxOutput::ToJson()
{
    nlohmann::json jsonData;
    jsonData["address"] = mAddress;
    jsonData["amount"] = mAmount;

    return jsonData;
}

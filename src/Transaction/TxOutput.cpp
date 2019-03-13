
#include "TxOutput.h"


void TxOutput::Serialize(ByteStream& ostream, uint8_t txVersion)
{
    ostream.writeBytes(mAssetId.u8, sizeof(mAssetId));
    ostream.writeUint64(mAmount);
    ostream.writeUint32(mOutputLock);
    ostream.writeBytes(mProgramHash.u8, sizeof(mProgramHash));

    if (txVersion >= 9) {
        ostream.writeBytes(&mOutputType, 1);
        if (mVotePayload) {
            mVotePayload->Serialize(ostream);
        }
    }
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

    auto jPayload = jsonData.find("payload");
    if (jPayload != jsonData.end()) {
        nlohmann::json payload = jsonData["payload"];

        mOutputType = 0x01;
        mVotePayload = new VoteOutputPayload();
        if (!mVotePayload) return;
        mVotePayload->FromJson(payload);
    }
}

nlohmann::json TxOutput::ToJson()
{
    nlohmann::json jsonData;
    jsonData["address"] = mAddress;
    jsonData["amount"] = mAmount;
    if (mVotePayload) {
        jsonData["payload"] = mVotePayload->ToJson();
    }

    return jsonData;
}

int TxOutput::GetVersion()
{
    switch (mOutputType) {
    case 0:
        return 0;
    case 1:
        return 9;
    default:
        return -1;
    }
}


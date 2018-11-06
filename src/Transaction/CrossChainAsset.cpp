
#include "CrossChainAsset.h"

void CrossChainAsset::Serialize(ByteStream& ostream)
{
    ostream.writeVarString(mAddress);
    ostream.writeVarUint(mIndex);
    ostream.writeUint64(mAmount);
}

void CrossChainAsset::FromJson(const nlohmann::json &jsonData)
{
    mAddress = jsonData["address"].get<std::string>();
    mAmount = jsonData["amount"].get<uint64_t>();
}

nlohmann::json CrossChainAsset::ToJson()
{
    nlohmann::json jsonData;
    jsonData["address"] = mAddress;
    jsonData["amount"] = mAmount;

    return jsonData;
}

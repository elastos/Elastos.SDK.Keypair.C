
#include "Program.h"
#include "../Utils.h"


void Program::Serialize(ByteStream &ostream)
{
    ostream.putVarUint(mParameter.GetSize());
    ostream.putBytes(mParameter, mParameter.GetSize());

    ostream.putVarUint(mCode.GetSize());
    ostream.putBytes(mCode, mCode.GetSize());
}

void Program::FromJson(const nlohmann::json &jsonData)
{
    mParameter = Utils::decodeHex(jsonData["parameter"].get<std::string>());
    mCode = Utils::decodeHex(jsonData["code"].get<std::string>());
}

nlohmann::json Program::ToJson()
{
    nlohmann::json jsonData;

    jsonData["parameter"] = Utils::encodeHex(mParameter);
    jsonData["code"] = Utils::encodeHex(mCode);

    return jsonData;
}

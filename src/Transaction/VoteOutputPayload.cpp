
#include "VoteOutputPayload.h"

void VoteOutputPayload::Serialize(ByteStream& ostream)
{
    ostream.writeBytes(&mVersion, 1);
    ostream.putVarUint(mVoteContents.size());

    for (VoteContent content : mVoteContents){
        content.Serialize(ostream);
    }
}

void VoteOutputPayload::Deserialize(ByteStream& ostream)
{
    ostream.readUint8(mVersion);
    uint64_t len = ostream.getVarUint();
    for (uint64_t i = 0; i < len; i++) {
        VoteContent content(0);
        content.Deserialize(ostream);
        mVoteContents.push_back(content);
    }
}

void VoteOutputPayload::FromJson(const nlohmann::json &jsonData)
{
    auto jSuperNode = jsonData.find("candidatePublicKeys");
    if (jSuperNode != jsonData.end()) {
        auto candidates = jsonData["candidatePublicKeys"].get<std::vector<nlohmann::json>>();
        VoteContent content(0);
        content.FromJson(candidates);
        mVoteContents.push_back(content);
    }

    auto jCrc = jsonData.find("candidateCrcs");
    if (jCrc != jsonData.end()) {
        auto candidates = jsonData["candidateCrcs"].get<std::vector<nlohmann::json>>();
        VoteContent content(1);
        content.FromJson(candidates);
        mVoteContents.push_back(content);
    }
}

nlohmann::json VoteOutputPayload::ToJson()
{
    nlohmann::json jsonData;
    jsonData["type"] = "vote";
    for (VoteContent content : mVoteContents) {
        if (content.GetVoteType() == 0) {
            jsonData["candidatePublicKeys"] = content.ToJson();
        }
        else {
            jsonData["candidateCrcs"] = content.ToJson();
        }
    }

    return jsonData;
}

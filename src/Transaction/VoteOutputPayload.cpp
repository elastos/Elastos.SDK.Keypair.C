
#include "VoteOutputPayload.h"

void VoteOutputPayload::Serialize(ByteStream& ostream)
{
    ostream.writeBytes(&mVersion, 1);
    ostream.putVarUint(mVoteContents.size());

    for (VoteContent content : mVoteContents){
        content.Serialize(ostream);
    }
}

void VoteOutputPayload::FromJson(const nlohmann::json &jsonData)
{
    std::string type = jsonData["type"].get<std::string>();
    uint8_t voteType;
    if (!type.compare("delegate")) {
        voteType = 0;
    }
    else voteType = 1;


    std::vector<std::string> candidates = jsonData["candidatePublicKeys"].get<std::vector<std::string>>();
    VoteContent content(voteType, candidates);
    mVoteContents.push_back(content);
}

nlohmann::json VoteOutputPayload::ToJson()
{
    nlohmann::json jsonData;
    jsonData["type"] = mVoteContents[0].GetVoteType() == 0 ? "delegate" : "crc";
    jsonData["candidatePublicKeys"] = mVoteContents[0].GetCandidates();

    return jsonData;
}

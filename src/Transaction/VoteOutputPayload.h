
#ifndef __VOTE_OUTPUT_PAYLOAD__
#define __VOTE_OUTPUT_PAYLOAD__

#include "../ByteStream.h"
#include "nlohmann/json.hpp"
#include <vector>
#include "VoteContent.h"

class VoteOutputPayload
{
public:
    VoteOutputPayload()
        : mVersion(0)
    {}

    void Serialize(ByteStream& ostream);

    void FromJson(const nlohmann::json &jsonData);

    nlohmann::json ToJson();

private:
    uint8_t mVersion;
    std::vector<VoteContent> mVoteContents;
};

#endif //__VOTE_OUTPUT_PAYLOAD__

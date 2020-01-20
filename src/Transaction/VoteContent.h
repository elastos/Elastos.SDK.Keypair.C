
#ifndef __VOTE_CONTENT_H__
#define __VOTE_CONTENT_H__

#include "../ByteStream.h"
#include "nlohmann/json.hpp"
#include <vector>

class VoteContent
{
private:
    class Candidate {
    public:
        Candidate(const std::string& cadidate, uint64_t amount)
            : mCandidate(cadidate)
            , mAmount(amount)
        {}

        std::string mCandidate;
        uint64_t mAmount;
    };

public:
    VoteContent(uint8_t voteType)
        : mVoteType(voteType)
    {}

    void Serialize(ByteStream& ostream);

    uint8_t GetVoteType();

    void FromJson(const std::vector<nlohmann::json>& array);

    std::vector<nlohmann::json> ToJson();

private:
    uint8_t mVoteType;
    std::vector<std::shared_ptr<Candidate>> mCandidates;
};

#endif //__VOTE_CONTENT_H__

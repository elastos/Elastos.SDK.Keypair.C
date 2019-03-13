
#ifndef __VOTE_CONTENT_H__
#define __VOTE_CONTENT_H__

#include "../ByteStream.h"
#include <vector>

class VoteContent
{
public:
    VoteContent(uint8_t voteType, const std::vector<std::string>& candidates)
        : mVoteType(voteType)
        , mCandidates(candidates)
    {}

    void Serialize(ByteStream& ostream);

    std::vector<std::string> GetCandidates();

    uint8_t GetVoteType();

private:
    uint8_t mVoteType;
    std::vector<std::string> mCandidates;
};

#endif //__VOTE_CONTENT_H__

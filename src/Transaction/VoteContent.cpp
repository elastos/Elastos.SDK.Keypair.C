
#include "VoteContent.h"
#include "../Utils.h"

void VoteContent::Serialize(ByteStream& ostream)
{
    ostream.writeBytes(&mVoteType, 1);
    ostream.putVarUint(mCandidates.size());
    for (std::string candidate : mCandidates){
        CMBlock pubKey = Utils::decodeHex(candidate);
        ostream.putVarUint(pubKey.GetSize());
        ostream.putBytes(pubKey, pubKey.GetSize());
    }
}

std::vector<std::string> VoteContent::GetCandidates()
{
    return mCandidates;
}

uint8_t VoteContent::GetVoteType()
{
    return mVoteType;
}

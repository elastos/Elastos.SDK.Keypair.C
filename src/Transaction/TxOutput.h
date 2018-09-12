
#ifndef __TX_OUTPUT_H__
#define __TX_OUTPUT_H__

#include "../BRInt.h"
#include "../ByteStream.h"
#include "../Utils.h"
#include <string>

#define DESTROY_ADDRESS "0000000000000000000000000000000000"

class TxOutput
{
public:
    TxOutput(const std::string& address, uint64_t amount)
    {
        mAddress = address;
        mAssetId = Utils::UInt256FromString("a3d0eaa466df74983b5d7c543de6904f4c9418ead5ffd6d25814234a96db37b0", true);
        mAmount = amount;
        mOutputLock = 0;
        if (!address.compare(DESTROY_ADDRESS)) {
            mProgramHash = UINT168_ZERO;
        }
        else {
            Utils::UInt168FromAddress(mProgramHash, address);
        }
    }

    void Serialize(ByteStream& ostream);

public:
    std::string mAddress;

    UInt256 mAssetId;
    uint64_t mAmount;
    uint32_t mOutputLock;

    UInt168 mProgramHash;
};

#endif //__TX_OUTPUT_H__

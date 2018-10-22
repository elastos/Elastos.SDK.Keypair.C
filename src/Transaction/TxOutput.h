
#ifndef __TX_OUTPUT_H__
#define __TX_OUTPUT_H__

#include "../BRInt.h"
#include "../ByteStream.h"
#include "../Utils.h"
#include <string>
#include "nlohmann/json.hpp"

#define DESTROY_ADDRESS "0000000000000000000000000000000000"

class TxOutput
{
public:
    TxOutput()
        : mAmount(0)
        , mOutputLock(0)
    {
        mAssetId = Utils::UInt256FromString("a3d0eaa466df74983b5d7c543de6904f4c9418ead5ffd6d25814234a96db37b0", true);
    }

    TxOutput(const std::string& address, uint64_t amount)
        : mAddress(address)
        , mAmount(amount)
        , mOutputLock(0)
    {
        mAssetId = Utils::UInt256FromString("a3d0eaa466df74983b5d7c543de6904f4c9418ead5ffd6d25814234a96db37b0", true);
        if (!address.compare(DESTROY_ADDRESS)) {
            mProgramHash = UINT168_ZERO;
        }
        else {
            Utils::UInt168FromAddress(mProgramHash, address);
        }
    }

    void Serialize(ByteStream& ostream);

    void FromJson(const nlohmann::json &jsonData);

    nlohmann::json ToJson();

public:
    std::string mAddress;

    UInt256 mAssetId;
    uint64_t mAmount;
    uint32_t mOutputLock;

    UInt168 mProgramHash;
};

#endif //__TX_OUTPUT_H__

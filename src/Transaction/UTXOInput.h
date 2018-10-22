
#ifndef __UTXO_INPUT_H__
#define __UTXO_INPUT_H__

#include "../CMemBlock.h"
#include "../BRInt.h"
#include "../ByteStream.h"
#include "../Utils.h"
#include <string>
#include "nlohmann/json.hpp"

class UTXOInput
{
public:
    UTXOInput()
        : mReferTxOutputIndex(0)
        , mSequence(0)
    {}

    UTXOInput(const std::string& txid, uint32_t index,
        const std::string& privateKey, const std::string& address)
        : mReferTxOutputIndex(index)
        , mAddress(address)
        , mSequence(0)
    {
        mReferTxid = Utils::UInt256FromString(txid, true);
        mPrivateKey = Utils::decodeHex(privateKey);
        Utils::UInt168FromAddress(mProgramHash, address);
    }

    void Serialize(ByteStream& ostream);

    void FromJson(const nlohmann::json &jsonData);

    nlohmann::json ToJson();

public:
    //Indicate the previous Tx which include the UTXO output for usage
    UInt256 mReferTxid;
    //The index of output in the referTx output list
    uint32_t mReferTxOutputIndex;
    CMBlock mPrivateKey;
    std::string mAddress;

    // Sequence number
    int mSequence;

    UInt168 mProgramHash;
};

#endif //__UTXO_INPUT_H__

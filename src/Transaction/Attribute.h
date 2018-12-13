
#ifndef __ATTRIBUTE_H__
#define __ATTRIBUTE_H__

#include "../Utils.h"
#include "../CMemBlock.h"
#include "../ByteStream.h"
#include "nlohmann/json.hpp"

class Attribute
{
public:
    enum Usage {
        Nonce = 0x00,
        Script = 0x20,
        DescriptionUrl = 0x81,
        Description = 0x90,
        Memo = 0x91,
        Confirmations = 0x92
    };

public:
    Attribute(const std::string& memo)
    {
        if (memo.empty()) {
            mUsage = Usage::Nonce;
            mData = Utils::convertToMemBlock(std::to_string(std::rand()));
        }
        else {
            mUsage = Usage::Memo;
            mData = Utils::convertToMemBlock(memo);
        }
    }

    void Serialize(ByteStream& ostream);

    void FromJson(const nlohmann::json &jsonData);

    nlohmann::json ToJson();

public:
    Usage mUsage;
    CMBlock mData;
};

#endif //__ATTRIBUTE_H__

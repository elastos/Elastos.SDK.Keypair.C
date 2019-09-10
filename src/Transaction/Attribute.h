
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
        Memo = 0x81,
        Description = 0x90,
        DescriptionUrl = 0x91,
        Confirmations = 0x92
    };

public:
    Attribute(Usage usage, const std::string& content)
    {
        mUsage = usage;
        if (usage == Nonce)
        {
            mData = Utils::convertToMemBlock(std::to_string(std::rand()));
        }
        else
        {
            mData = Utils::convertToMemBlock(content);
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

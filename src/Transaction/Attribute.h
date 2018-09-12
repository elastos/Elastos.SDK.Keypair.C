
#ifndef __ATTRIBUTE_H__
#define __ATTRIBUTE_H__

#include "../Utils.h"
#include "../CMemBlock.h"
#include "../ByteStream.h"

class Attribute
{
public:
    Attribute()
    {
        mUsage = 0;
        mData = Utils::convertToMemBlock(std::to_string(std::rand()));
    }

    void Serialize(ByteStream& ostream);

public:
    uint8_t mUsage;
    CMBlock mData;
};

#endif //__ATTRIBUTE_H__


#ifndef __ATTRIBUTE_H__
#define __ATTRIBUTE_H__

#include "../Utils.h"
#include "../CMemBlock.h"
#include "../ByteStream.h"
#include "../BigIntFormat.h"

class Attribute
{
public:
    Attribute(std::string memo)
    {
        if (memo.empty()) {
             mUsage = 0;
            mData = Utils::convertToMemBlock(std::to_string(std::rand()));
        }
        else {
            mUsage = 0x81;
            CMemBlock<char> cMemo;
            cMemo.SetMemFixed(memo.c_str(), memo.size() + 1);
            mData = Str2Hex(cMemo);
        }
    }

    void Serialize(ByteStream& ostream);

public:
    uint8_t mUsage;
    CMBlock mData;
};

#endif //__ATTRIBUTE_H__

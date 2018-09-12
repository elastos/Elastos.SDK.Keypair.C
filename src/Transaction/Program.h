
#ifndef __PROGRAM_H__
#define __PROGRAM_H__

#include "../CMemBlock.h"
#include "../ByteStream.h"

class Program
{
public:
    Program(const CMBlock &code, const CMBlock &parameter)
        : mCode(code)
        , mParameter(parameter)
        {}

    void Serialize(ByteStream &ostream);

public:
    CMBlock mCode;
    CMBlock mParameter;

};

#endif //__PROGRAM_H__

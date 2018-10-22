
#ifndef __PROGRAM_H__
#define __PROGRAM_H__

#include "../CMemBlock.h"
#include "../ByteStream.h"
#include "nlohmann/json.hpp"

class Program
{
public:
    Program()
    {}

    Program(const CMBlock &code, const CMBlock &parameter)
        : mCode(code)
        , mParameter(parameter)
        {}

    void Serialize(ByteStream &ostream);

    void FromJson(const nlohmann::json &jsonData);

    nlohmann::json ToJson();

public:
    CMBlock mCode;
    CMBlock mParameter;

};

#endif //__PROGRAM_H__

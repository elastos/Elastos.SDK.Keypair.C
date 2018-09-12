
#include "Program.h"


void Program::Serialize(ByteStream &ostream)
{
    ostream.putVarUint(mParameter.GetSize());
    ostream.putBytes(mParameter, mParameter.GetSize());

    ostream.putVarUint(mCode.GetSize());
    ostream.putBytes(mCode, mCode.GetSize());
}

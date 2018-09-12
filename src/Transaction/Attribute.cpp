
#include "Attribute.h"

void Attribute::Serialize(ByteStream& ostream)
{
    ostream.put(mUsage);

    ostream.putVarUint(mData.GetSize());
    ostream.putBytes(mData, mData.GetSize());
}


#include "UTXOInput.h"

void UTXOInput::Serialize(ByteStream& ostream)
{
    ostream.writeBytes(mReferTxid.u8, sizeof(UInt256));
    ostream.writeUint16((uint16_t)mReferTxOutputIndex);
    ostream.writeUint32(mSequence);
}

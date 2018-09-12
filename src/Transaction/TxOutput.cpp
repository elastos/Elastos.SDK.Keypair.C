
#include "TxOutput.h"


void TxOutput::Serialize(ByteStream& ostream)
{
    ostream.writeBytes(mAssetId.u8, sizeof(mAssetId));
    ostream.writeUint64(mAmount);
    ostream.writeUint32(mOutputLock);
    ostream.writeBytes(mProgramHash.u8, sizeof(mProgramHash));
}

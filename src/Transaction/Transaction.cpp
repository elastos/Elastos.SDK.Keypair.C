
#include "Transaction.h"
#include "../BRCrypto.h"
#include "../BRBIP32Sequence.h"
#include "../BigIntFormat.h"

Transaction::Transaction()
    : mType(TransferAsset)
    , mPayloadVersion(0)
    , mPayload(nullptr)
    , mLockTime(TX_LOCKTIME)
    , mFee(0)
    , mTxHash(UINT256_ZERO)
{
    std::string memo;
    Attribute* pAttr = new Attribute(memo);
    if (pAttr) {
        mAttributes.push_back(pAttr);
    }
}

Transaction::Transaction(std::vector<UTXOInput*> inputs, std::vector<TxOutput*> outputs, std::string memo)
    : mType(TransferAsset)
    , mPayloadVersion(0)
    , mPayload(nullptr)
    , mInputs(inputs)
    , mOutputs(outputs)
    , mLockTime(TX_LOCKTIME)
    , mFee(0)
    , mTxHash(UINT256_ZERO)
{
    Attribute* pAttr = new Attribute(memo);
    if (pAttr) {
        mAttributes.push_back(pAttr);
    }

}

Transaction::~Transaction()
{
    for(UTXOInput* input : mInputs) {
        delete input;
    }
    mInputs.clear();

    for(TxOutput* output : mOutputs) {
        delete output;
    }
    mOutputs.clear();

    for (Attribute* attr : mAttributes) {
        delete attr;
    }
    mAttributes.clear();

    for(Program* program : mPrograms) {
        delete program;
    }
    mPrograms.clear();
}

UInt256 Transaction::GetHash()
{
    UInt256 emptyHash = UINT256_ZERO;
    if (UInt256Eq(&mTxHash, &emptyHash)) {
        ByteStream ostream;
        SerializeUnsigned(ostream);
        CMBlock buff = ostream.getBuffer();
        BRSHA256_2(&mTxHash, buff, buff.GetSize());
    }
    return mTxHash;
}

void Transaction::Serialize(ByteStream &ostream)
{
    SerializeUnsigned(ostream);

    ostream.writeVarUint(mPrograms.size());
    for (size_t i = 0; i < mPrograms.size(); i++) {
        mPrograms[i]->Serialize(ostream);
    }
}

void Transaction::Sign(const CMBlock & privteKey)
{
    ByteStream ostream;
    SerializeUnsigned(ostream);
    CMBlock data = ostream.getBuffer();
    CMBlock shaData(sizeof(UInt256));
    BRSHA256(shaData, data, data.GetSize());

    CMBlock md32;
    md32.SetMemFixed(shaData, shaData.GetSize());

    CMBlock signedData;
    signedData.Resize(65);
    ECDSA65Sign_sha256(privteKey, privteKey.GetSize(), (UInt256 *) &md32[0], signedData, signedData.GetSize());

    CMBlock publicKey;
    publicKey.Resize(33);
    getPubKeyFromPrivKey(publicKey, (UInt256 *)(uint8_t *)privteKey);

    CMemBlock<char> cPrivkey, cPubkey;
    cPrivkey = Hex2Str(privteKey);
    cPubkey = Hex2Str(publicKey);
    printf("private key: %s\n", (const char *)cPrivkey);
    printf("public key: %s\n", (const char *)cPubkey);

    CMBlock code = Utils::getCode(publicKey);

    Program* program = new Program(code, signedData);
    if (program) {
        mPrograms.push_back(program);
    }
}

std::vector<CMBlock> Transaction::GetPrivateKeys()
{
    std::vector<CMBlock> privateKeys;
    for (UTXOInput* input : mInputs)
    {
        privateKeys.push_back(input->mPrivateKey);
    }

    return privateKeys;
}

void Transaction::SerializeUnsigned(ByteStream &ostream) const
{
    ostream.writeBytes(&mType, 1);

    ostream.writeBytes(&mPayloadVersion, 1);

    // TODO: payload is null
    // if (mPayload == nullptr) {
    //     Log::getLogger()->error("payload should not be null, payload type = {}, version = {}", _transaction->type, _transaction->payloadVersion);
    //     throw std::logic_error("payload should not be null");
    // }
    // mPayload->Serialize(ostream);

    ostream.writeVarUint(mAttributes.size());
    for (size_t i = 0; i < mAttributes.size(); i++) {
        mAttributes[i]->Serialize(ostream);
    }

    ostream.writeVarUint(mInputs.size());
    for (size_t i = 0; i < mInputs.size(); i++) {
        mInputs[i]->Serialize(ostream);
    }

    ostream.writeVarUint(mOutputs.size());
    for (size_t i = 0; i < mOutputs.size(); i++) {
        mOutputs[i]->Serialize(ostream);
    }

    ostream.writeUint32(mLockTime);
}

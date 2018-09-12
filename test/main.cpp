
#include "BTCKey.h"
#include "BRCrypto.h"
#include "WalletTool.h"
#include "Mnemonic.h"
#include "ElaController.h"
#include "BigIntFormat.h"

#include <iostream>

void TestGenerateKey()
{
    printf("============= start TestGenerateKey ===========\n");
    printf("============= generate key ===========\n");

    int nid = NID_X9_62_prime256v1;

    CMBlock privateKey, publicKey;
    bool ret = BTCKey::generateKey(privateKey, publicKey, nid);
    if (ret) {
        CMemBlock<char> cPrivkey, cPubkey;
        cPrivkey = Hex2Str(privateKey);
        cPubkey = Hex2Str(publicKey);
        printf("private key: %s\n", (const char *)cPrivkey);
        printf("public key: %s\n", (const char *)cPubkey);
    }
    else {
        printf("============= generate key failed ===========\n");
        return;
    }

    uint8_t data[] = {0, 1, 2, 3, 4, 5};
    UInt256 md = UINT256_ZERO;
    BRSHA256(&md, data, sizeof(data));

    printf("============= sign by private key ===========\n");
    CMBlock mbSignedData;
    ret = BTCKey::ECDSA65Sign_sha256(privateKey, md, mbSignedData, nid);
    if (ret) {
        printf("============= verify by public key ===========\n");
        bool bVerify = BTCKey::ECDSA65Verify_sha256(publicKey, md, mbSignedData, nid);
        if (bVerify) {
            printf("============= verify succeeded ===========\n");
        }
        else {
            printf("============= verify failed ===========\n");
        }
    }
    else {

        printf("============= sign failed ===========\n");
    }
    printf("============= end TestGenerateKey ===========\n\n");
}

std::string GenerateMnemonic(const std::string &language, const std::string &rootPath)
{
    CMemBlock<uint8_t> seed128 = WalletTool::GenerateSeed128();
    Mnemonic mnemonic(language, rootPath);
    printf("=== words length: %d\n", (int)mnemonic.words().size());
    CMemBlock<char> phrase = WalletTool::GeneratePhraseFromSeed(seed128, mnemonic.words());
    return (const char *) phrase;
}

void TestGenrateMnemonic()
{
    printf("============= start TestGenrateMnemonic ===========\n");
    std::string mnemonic = GenerateMnemonic("chinese", "/home/zuo/work/Elastos.RT/Sources/Sample/TestOpenssl/Data/");
    printf("mnemonic: %s\n", mnemonic.c_str());

    CMBlock seed = BTCKey::getPrivKeySeed(mnemonic, "", "/home/zuo/work/Elastos.RT/Sources/Sample/TestOpenssl/Data/", "chinese");
    CMemBlock<char> mbcSeed = Hex2Str(seed);
    printf("seed: %s\n", (const char*)mbcSeed);

    int nid = NID_X9_62_prime256v1;
    CMBlock privKey = BTCKey::getMasterPrivkey(seed);
    CMBlock pubKey = BTCKey::getPubKeyFromPrivKey(privKey, nid);
    CMemBlock<char> cPrivkey, cPubkey;
    cPrivkey = Hex2Str(privKey);
    cPubkey = Hex2Str(pubKey);
    printf("private key: %s\n", (const char *)cPrivkey);
    printf("public key: %s\n", (const char *)cPubkey);

    std::string address = BTCKey::getAddressFromPublicKey(pubKey);
    printf("address: %s\n", address.c_str());

    printf("============= end TestGenrateMnemonic ===========\n\n");
}

void signTxData(std::string data)
{
    printf("============= start signTxData ===========\n");
    printf("data: %s\n\n", data.c_str());
    std::string signedData = ElaController::genRawTransaction(data);
    printf("signedData: %s\n", signedData.c_str());

    printf("============= end signTxData ===========\n\n");
}

int main(int argc, char *argv[])
{
    std::cout << "input command: ";
    while(1)
    {
        std::string command;
        std::getline(std::cin, command);
        if (!command.compare("genkey"))
        {
            TestGenrateMnemonic();
        }
        else if (!command.compare("sign"))
        {
            std::string json;
            std::cout << "input trasaction data: ";
            std::getline(std::cin, json);
            signTxData(json);
        }
        else if (!command.compare("exit"))
        {
            break;
        }
    }

    return 0;
}

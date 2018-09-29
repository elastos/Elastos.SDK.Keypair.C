
#include "../src/Elastos.Wallet.Utility.h"

#include <iostream>


void TestGenrateMnemonic()
{
    printf("============= start TestGenrateMnemonic ===========\n");
    char* mnemonic = generateMnemonic("chinese", "/home/zuo/work/Elastos.ORG.Wallet.Utility/src/Data/");
    printf("mnemonic: %s\n", mnemonic);

    char* privateKey = getMasterPrivateKey(mnemonic, "chinese", "/home/zuo/work/Elastos.ORG.Wallet.Utility/src/Data/", "");
    char* publicKey = getPublicKey(privateKey);

    printf("private key: %s\n", privateKey);
    printf("public key: %s\n", publicKey);

    char* address = getAddress(publicKey);
    printf("address: %s\n", address);

    uint8_t data[] = {0, 1, 2, 3, 4, 5};
    uint8_t* signedData;
    int signedLen = sign(privateKey, data, sizeof(data), (void**)&signedData);
    printf("signed len: %d\n", signedLen);
    if (signedLen > 0) {
        printf("============= verify by public key ===========\n");
        bool bVerify = verify(publicKey, data, sizeof(data), signedData, signedLen);
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

    free(mnemonic);
    free(privateKey);
    free(publicKey);
    free(address);

    printf("============= end TestGenrateMnemonic ===========\n\n");
}

void signTxData(const char* data)
{
    printf("============= start signTxData ===========\n");
    printf("data: %s\n\n", data);
    char* signedData = generateRawTransaction(data);
    printf("signedData: %s\n", signedData);

    free(signedData);
    printf("============= end signTxData ===========\n\n");
}

const char *c_help = \
    "genmne    test generate mnemonic, get private key, public key, address.\n" \
    "sign      test generate raw transaction.\n" \
    "help      show help message.\n" \
    "exit      exit the test program.\n" \
    "\n";

int main(int argc, char *argv[])
{
    std::cout << "input command: ";
    while(1)
    {
        std::string command;
        std::getline(std::cin, command);
        if (!command.compare("genmne")) {
            TestGenrateMnemonic();
        }
        else if (!command.compare("sign")) {
            std::string json;
            std::cout << "input trasaction data: ";
            std::getline(std::cin, json);
            signTxData(json.c_str());
        }
        else if (!command.compare("help")) {
            std::cout << c_help;
        }
        else if (!command.compare("exit")) {
            break;
        }
    }

    return 0;
}

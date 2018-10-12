
#include "../src/Elastos.Wallet.Utility.h"

#include <iostream>
#include <stdio.h>
#include <stdlib.h>

char* readMnemonicFile(const char* path)
{
    FILE* file = fopen(path, "r");
    if (!file) {
        return nullptr;
    }
    char* buf = (char*)malloc(1024 * 10);
    if (!buf) {
        fclose(file);
        return nullptr;
    }
    int count = 0;
    char c;

    while ( (c = fgetc(file)) != EOF) {
        buf[count++] = c;
    }

    buf[count] = '\0';
    fclose(file);

    return buf;
}

void TestGenrateMnemonic()
{
    printf("============= start TestGenrateMnemonic ===========\n");

    const char* path = "/home/zuo/work/Elastos.ORG.Wallet.Lib.C/src/Data/mnemonic_chinese.txt";
    char* words = readMnemonicFile(path);
    if (!words) {
        printf("read file failed\n");
        printf("============= end TestGenrateMnemonic ===========\n\n");
    }

    char* mnemonic = generateMnemonic("chinese", words);
    printf("mnemonic: %s\n", mnemonic);

    void* seed;
    int seedLen = getSeedFromMnemonic(&seed, mnemonic, "chinese", words, "");
    char* privateKey = getSinglePrivateKey(seed, seedLen);
    char* publicKey = getSinglePublicKey(seed, seedLen);

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
    free(seed);
    free(words);

    printf("============= end TestGenrateMnemonic ===========\n\n");
}

void TestHDWalletAddress()
{
    printf("============= start TestHDWalletAddress ===========\n");

    const char* path = "/home/zuo/work/Elastos.ORG.Wallet.Lib.C/src/Data/mnemonic_chinese.txt";
    char* words = readMnemonicFile(path);
    if (!words) {
        printf("read file failed\n");
        printf("============= end TestHDWalletAddress ===========\n\n");
    }

    const char* mnemonic = "督 辉 稿 谋 速 壁 阿 耗 瓷 仓 归 说";
    void* seed;
    int seedLen = getSeedFromMnemonic(&seed, mnemonic, "chinese", words, "");
    printf("=========== seed length: %d\n", seedLen);

    char* privateKey = getSinglePrivateKey(seed, seedLen);
    char* publicKey = getSinglePublicKey(seed, seedLen);
    char* address = getAddress(publicKey);

    printf("single private key: %s\n", privateKey);
    printf("single public key: %s\n", publicKey);
    printf("single address: %s\n\n", address);

    free(privateKey);
    free(publicKey);
    free(address);
    free(words);


    MasterPublicKey* masterPublicKey = getMasterPublicKey(seed, seedLen, COIN_TYPE_ELA);
    int count = 10;
    char* privateKeys[count];
    char* publicKeys[count];
    char* addresses[count];
    for (int i = 0; i < count; i++) {
        privateKeys[i] = generateSubPrivateKey(seed, seedLen, COIN_TYPE_ELA, INTERNAL_CHAIN, i);
        publicKeys[i] = generateSubPublicKey(masterPublicKey, INTERNAL_CHAIN, i);
        addresses[i] = getAddress(publicKeys[i]);

        printf("private key %d: %s\n", i, privateKeys[i]);
        printf("public key %d: %s\n", i, publicKeys[i]);
        printf("address %d: %s\n\n", i, addresses[i]);
    }

    for (int i = 0; i < count; i++) {
        free(privateKeys[i]);
        free(publicKeys[i]);
        free(addresses[i]);
    }
    delete masterPublicKey;

    printf("============= end TestHDWalletAddress ===========\n");
}

void TestDid()
{
    printf("============= start TestDid ===========\n");

    const char* path = "/home/zuo/work/Elastos.ORG.Wallet.Lib.C/src/Data/mnemonic_chinese.txt";
    char* words = readMnemonicFile(path);
    if (!words) {
        printf("read file failed\n");
        printf("============= end TestDid ===========\n\n");
    }

    const char* mnemonic = "督 辉 稿 谋 速 壁 阿 耗 瓷 仓 归 说";
    void* seed;
    int seedLen = getSeedFromMnemonic(&seed, mnemonic, "chinese", words, "");
    printf("=========== seed length: %d\n", seedLen);
    free(words);


    MasterPublicKey* masterPublicKey = getIdChainMasterPublicKey(seed, seedLen);
    int count = 10;
    char* privateKeys[count];
    char* publicKeys[count];
    char* addresses[count];
    for (int i = 0; i < count; i++) {
        privateKeys[i] = generateIdChainSubPrivateKey(seed, seedLen, 0, i);
        publicKeys[i] = generateIdChainSubPublicKey(masterPublicKey, 0, i);
        addresses[i] = getDid(publicKeys[i]);

        printf("private key %d: %s\n", i, privateKeys[i]);
        printf("public key %d: %s\n", i, publicKeys[i]);
        printf("DID %d: %s\n\n", i, addresses[i]);
    }

    for (int i = 0; i < count; i++) {
        free(privateKeys[i]);
        free(publicKeys[i]);
        free(addresses[i]);
    }
    delete masterPublicKey;

    printf("============= end TestDid ===========\n");
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
    "hd        test generate hd wallet address.\n" \
    "did       test generate did.\n"
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
        else if (!command.compare("hd")) {
            TestHDWalletAddress();
        }
        else if (!command.compare("did")) {
            TestDid();
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

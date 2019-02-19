
#include "../src/Elastos.Wallet.Utility.h"

#include <iostream>
#include <stdio.h>
#include <stdlib.h>

#include "../src/Utils.h"

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

void SignMemo()
{
    // const char* memo = "{\"userId\":\"clark\",\"phone\":\"13809011232\"}";
    const char* memo = "68656C6C6F776F726C64";
    const char* privateKey = "1615CC0AB02168680354E07048F9CE54B2921847F68453586C4A2DBC23BA2C9D";

    CMBlock data = Utils::decodeHex(memo);

    // CMBlock data = Utils::convertToMemBlock(memo);
    uint8_t* signedData;
    int signedLen = sign(privateKey, (void*)data, data.GetSize(), (void**)&signedData);

    CMBlock cmSigned;
    cmSigned.SetMemFixed(signedData, signedLen);
    std::string signedStr = Utils::encodeHex(cmSigned);

    printf("signed: %s\n", signedStr.c_str());
}

void verifyMemo()
{
    const char* memo = "68656C6C6F776F726C64";
    CMBlock data = Utils::decodeHex(memo);

    const char* signedMemo = "1dd38b5678622a1e8614450d2995c01a75897c50aeb88d271689f57a68ba8b6f8c05305af2cc8bc98a7c53192004777050f40b996101d7bed51a25f5aed75579";
    CMBlock signedData = Utils::decodeHex(signedMemo);

    bool pass = verify("028971D6DA990971ABF7E8338FA1A81E1342D0E0FD8C4D2A4DF68F776CA66EA0B1",
            data, data.GetSize(), signedData, signedData.GetSize());

    printf("verify: %d\n", pass);
}

void TestGenrateMnemonic()
{
    printf("============= start TestGenrateMnemonic ===========\n");

    const char* path = "/home/hostuser/Elastos.SDK.Keypair.C/src/Data/mnemonic_chinese.txt";
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

    const char* path = "/home/hostuser/Elastos.SDK.Keypair.C/src/Data/mnemonic_chinese.txt";
    char* words = readMnemonicFile(path);
    if (!words) {
        printf("read file failed\n");
        printf("============= end TestHDWalletAddress ===========\n\n");
        return;
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
        privateKeys[i] = generateSubPrivateKey(seed, seedLen, COIN_TYPE_ELA, EXTERNAL_CHAIN, i);
        publicKeys[i] = generateSubPublicKey(masterPublicKey, EXTERNAL_CHAIN, i);
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

    const char* path = "/Users/huahua/repo/Elastos.SDK.Keypair.C/src/Data/mnemonic_chinese.txt";
    char* words = readMnemonicFile(path);
    if (!words) {
        printf("read file failed\n");
        printf("============= end TestDid ===========\n\n");
        return;
    }

    const char* mnemonic = "督 辉 稿 谋 速 壁 阿 耗 瓷 仓 归 说";
    void* seed;
    int seedLen = getSeedFromMnemonic(&seed, mnemonic, "chinese", words, "");
    printf("=========== seed length: %d\n", seedLen);
    free(words);


    MasterPublicKey* masterPublicKey = getMasterPublicKey(seed, seedLen, COIN_TYPE_ELA);
    int count = 10;
    char* privateKeys[count];
    char* publicKeys[count];
    char* addresses[count];
    for (int i = 0; i < count; i++) {
        privateKeys[i] = generateSubPrivateKey(seed, seedLen, COIN_TYPE_ELA, EXTERNAL_CHAIN, i);
        publicKeys[i] = generateSubPublicKey(masterPublicKey, EXTERNAL_CHAIN, i);
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
    // const char* transaction = "{\"Transactions\":[{\"UTXOInputs\":[{\
    //                 \"txid\":\"f176d04e5980828770acadcfc3e2d471885ab7358cd7d03f4f61a9cd0c593d54\",\
    //                 \"privateKey\":\"b6f010250b6430b2dd0650c42f243d5445f2044a9c2b6975150d8b0608c33bae\",\
    //                 \"index\":0,\"address\":\"EeniFrrhuFgQXRrQXsiM1V4Amdsk4vfkVc\"}],\
    //                 \"Outputs\":[{\"address\":\"EbxU18T3M9ufnrkRY7NLt6sKyckDW4VAsA\",\
    //                 \"amount\":2000000}]}]}";
    char* signedData = generateRawTransaction(data);
    printf("signedData: %s\n", signedData);

    free(signedData);
    printf("============= end signTxData ===========\n\n");
}

void cosignTxData()
{
    printf("============= start cosignTxData ===========\n");

    const char* data = "{\"Transactions\":[{\"UTXOInputs\":[{\
                    \"txid\":\"c20d577997a6036683e1a88925eaa4c2e4ca2f34db95a3fe85ad3787da017bec\",\
                    \"index\":0,\"address\":\"8NJ7dbKsG2NRiBqdhY6LyKMiWp166cFBiG\"}],\
                    \"Outputs\":[{\"address\":\"EbxU18T3M9ufnrkRY7NLt6sKyckDW4VAsA\",\
                    \"amount\":2000000}]}]}";

    char* publicKeys[3] = {
        "02bc11aa5c35acda6f6f219b94742dd9a93c1d11c579f98f7e3da05ad910a48306",
        "031a9d45859da69dbc444723048932b8f56bb9937c5260238b4821a3b1ccfd78b6",
        "02746aa551414e16921a3249ddd5e49923299c97102c7e7c5b9c6e81dd3949556d"
    };

    const char* private1 = "543c241f89bebb660157bcd12d7ab67cf69f3158240a808b22eb98447bad205d";
    const char* private2 = "fe7bb62ad9bed0a572bd9428574eba8d038b68ea3004d37eb7bcf3f297a2c48f";
    const char* private3 = "404a282fec850e7b880ad65f40ffd0bdddc50d8cf3217ca65d30f5378d377991";

    char* address = getMultiSignAddress(publicKeys, 3, 2);
    printf("cosign address: %s\n", address);
    free(address);

    char* signedData1 = multiSignTransaction(private2, publicKeys, 3, 2, data);
    printf("signed data1: %s\n", signedData1);
    char* signedData2 = multiSignTransaction(private3, publicKeys, 3, 2, signedData1);
    printf("signed data2: %s\n", signedData2);

    char* serialize = serializeMultiSignTransaction(signedData2);
    printf("serialize data: %s\n", serialize);

    free(signedData1);
    free(signedData2);
    free(serialize);

    printf("============= end cosignTxData ===========\n\n");
}

const char *c_help = \
    "genmne    test generate mnemonic, get private key, public key, address.\n" \
    "hd        test generate hd wallet address.\n" \
    "did       test generate did.\n"
    "sign      test generate raw transaction.\n" \
    "cosign    test cosign raw transaction.\n" \
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
        else if (!command.compare("cosign")) {
            cosignTxData();
        }
        else if (!command.compare("help")) {
            std::cout << c_help;
        }
        else if (!command.compare("exit")) {
            break;
        }
        else if (!command.compare("memo")) {
            SignMemo();
        }
        else if (!command.compare("vmemo")) {
            verifyMemo();
        }
        else if (command.length() != 0){
            std::cout << "not support command\n";
        }
    }

    return 0;
}

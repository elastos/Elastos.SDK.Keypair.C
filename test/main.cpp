
#include "../src/Elastos.Wallet.Utility.h"

#include <iostream>
#include <stdio.h>
#include <stdlib.h>

#include <sstream>
#include "../src/Utils.h"
#include "../wrapper/filecoin/FileCoin.hpp"
#include "../src/Base64.h"

char* readMnemonicFile(const char* path)
{
    long lSize;
    char * buffer;
    size_t result;

    FILE* pFile = fopen (path, "rb");
    if (pFile == NULL) {
        return nullptr;
    }

    // obtain file size:
    fseek (pFile , 0 , SEEK_END);
    lSize = ftell (pFile);
    rewind (pFile);

    // allocate memory to contain the whole file:
    buffer = (char*) malloc(sizeof(char) * (lSize + 1));
    if (buffer == NULL) {
        fclose (pFile);
        return nullptr;
    }

    // copy the file into the buffer:
    result = fread(buffer, 1, lSize, pFile);
    fclose (pFile);
    if (result != lSize) {
        return nullptr;
    }

    buffer[lSize] = '\0';

    return buffer;
}

void SignMemo()
{
    const char* memo = "test";
    const char* privateKey = "6c07a2510bc2ce9401607a669ed986cc78765e14515f17cfd0fa86344ff3fa31";

    uint8_t* signedData;
    int signedLen = sign(privateKey, (void*)memo, strlen(memo), (void**)&signedData);

    CMBlock cmSigned;
    cmSigned.SetMemFixed(signedData, signedLen);
    std::string signedStr = Utils::encodeHex(cmSigned);

    printf("signed: %s\n", signedStr.c_str());
}

void verifyMemo()
{
    const char* memo = "test";

    const char* signedMemo = "C7003C5AF54C6CB36FEC8E811D29C3B97E6C067C1B64108728678762D4338A7C57DBBAD5DF59290EB51B6E22C70DE3F591440BC55FE04EE1711BCE9145B64759";
    CMBlock signedData = Utils::decodeHex(signedMemo);

    bool pass = verify("03c21524ff3fd2029b944ade939c99d66a78f2db8cca8add7492b7f06b7c767cda",
            memo, strlen(memo), signedData, signedData.GetSize());

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
    int seedLen = getSeedFromMnemonic(&seed, mnemonic, "");
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

    const char* mnemonic = "督 辉 稿 谋 速 壁 阿 耗 瓷 仓 归 说";
    void* seed;
    int seedLen = getSeedFromMnemonic(&seed, mnemonic, "");
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

    const char* mnemonic = "督 辉 稿 谋 速 壁 阿 耗 瓷 仓 归 说";
    void* seed;
    int seedLen = getSeedFromMnemonic(&seed, mnemonic, "");
    printf("=========== seed length: %d\n", seedLen);

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
    const char* transaction = "{\"Transactions\":[{\"UTXOInputs\":[{\
                    \"txid\":\"f176d04e5980828770acadcfc3e2d471885ab7358cd7d03f4f61a9cd0c593d54\",\
                    \"privateKey\":\"b6f010250b6430b2dd0650c42f243d5445f2044a9c2b6975150d8b0608c33bae\",\
                    \"index\":0,\"address\":\"EeniFrrhuFgQXRrQXsiM1V4Amdsk4vfkVc\"}],\
                    \"Outputs\":[{\"address\":\"EbxU18T3M9ufnrkRY7NLt6sKyckDW4VAsA\",\
                    \"amount\":2000000}]}]}";

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
        "031ed85c1a56e912de5562657c6d6a03cfe974aab8b62d484cea7f090dac9ff1cf",
        "0306ee2fa3fb66e21b61ac1af9ce95271d9bb5fc902f92bd9ff6333bda552ebc64",
        "03b8d95fa2a863dcbd44bf288040df4c6cb9d674a61c4c1e3638ac515994c777e5"
    };

    const char* private1 = "79b442f402a50c1f3026edfa160a6555c0f9c48a86d85ab103809008a913f07b";
    const char* private2 = "37878ce7b4b509aee357996a7d0a0e0e478759be034503b7b6438356d2200973";
    const char* private3 = "0c2e640e0e025d58f6630a0fecea2419f26bb7fea6c67cd9c32aa4f1116ef74e";

    char* address = getMultiSignAddress(publicKeys, 3, 2);
    printf("cosign address: %s\n", address);
    free(address);

    char* signedData1 = multiSignTransaction(private2, publicKeys, 3, 2, data);
    printf("signed data1: %s\n", signedData1);
    char* signedData2 = multiSignTransaction(private3, publicKeys, 3, 2, signedData1);
    printf("signed data2: %s\n", signedData2);

    int len = 0;
    char** signedSigners = getSignedSigners(signedData1, &len);
    if (signedSigners != nullptr) {
        for (int i = 0; i < len; i++) {
            printf("signed public key: %s\n", signedSigners[i]);
            free(signedSigners[i]);
        }
        free(signedSigners);
    }

    char* serialize = serializeMultiSignTransaction(signedData2);
    printf("serialize data: %s\n", serialize);

    free(signedData1);
    free(signedData2);
    free(serialize);

    printf("============= end cosignTxData ===========\n\n");
}

void Crypto(const char* plainText)
{
    const char* publicKey = "02bc11aa5c35acda6f6f219b94742dd9a93c1d11c579f98f7e3da05ad910a48306";
    const char* privateKey = "543c241f89bebb660157bcd12d7ab67cf69f3158240a808b22eb98447bad205d";

    char* cipher = eciesEncrypt(publicKey, (unsigned char*)plainText, strlen(plainText));
    if (cipher == NULL) {
        printf("ecies encrypt error\n");
        return;
    }

    printf("cipher: %s\n", cipher);

    int len;
    char* decrypted = (char*)eciesDecrypt(privateKey, cipher, &len);
    if (decrypted == NULL) {
        printf("ecies decrypt error\n");
        free(cipher);
        return;
    }

    printf("plain: %s\n", decrypted);
    free(cipher);
    free(decrypted);
}

void deserializeTx()
{
    printf("============= start deserializeTx ===========\n\n");
    const char* rawTx = "090200010005313638303702b9e978386c5344275943696b2d7708432dea03a8890d0c17c41b2ab7f781cfc2000000000000b9e978386c5344275943696b2d7708432dea03a8890d0c17c41b2ab7f781cfc201000000000002b037db964a231458d2d6ffd5ea18944c4f90e63d547c5d3b9874df66a4ead0a3140000000000000000000000215e2b96666a1df75eaf238cd05a65bad37f3e56c90101020002210368044f3b3582000597d40c9293ea894237a88b2cd55f79a18193399937d2266414000000000000002103d55285f06683c9e5c6b5892a688affd046940c7161571611ea3a98330f72459f1400000000000000010215676988a6d7cbaf839ca6e584ddd4dd6cb7065633b80900000000000000156728c8229adfe265ed2b87fcd288b2452a0fe527cb0900000000000000b037db964a231458d2d6ffd5ea18944c4f90e63d547c5d3b9874df66a4ead0a37c85f0080000000000000000215e2b96666a1df75eaf238cd05a65bad37f3e56c9000000000001414020ca1dc3ef929e26e968a18c53b7f0667b033d1a0ab38a9017fdb9ee6b0ee5e612aaa8daae7442e0adf1c5532cda719a039602a0843c912b49bf538276d6ba8c2321020bf079596d7c4e2cd66bb21bb2ad49ecc7757cde5c710042aebfb6874b7c7d69ac";
    char* tx = deserializeRawTransaction(rawTx);
    if (tx == nullptr) {
        printf("deserialized failed\n");
    }
    else {
        printf("deserialized tx: %s\n", tx);
        free(tx);
    }

    printf("============= end deserializeTx ===========\n\n");
}

void testInfoAddress(const char* info)
{
    if (info == nullptr) return;
    printf("============= start deserializeTx ===========\n\n");

    char* address = getAddressByInfo(info);
    printf("address: %s\n", address);
    free(address);

    char* did = getDidByInfo(info);
    printf("did: %s\n", did);
    free(did);

    printf("============= end deserializeTx ===========\n\n");
}

#ifdef CFG_WITH_FILECOIN
void TestFileCoin()
{
    printf("============= start TestFileCoin ===========\n");

    //const char* mnemonic = "voice kingdom wall sword pair unusual artefact opera keen aware stay game";
    const char* mnemonic = "equip will roof matter pink blind book anxiety banner elbow sun young";

    //char* mnemonic = generateMnemonic("english", "");
    //printf("mnemonic: %s\n", mnemonic);

    void* seed;
    int seedLen = getSeedFromMnemonic(&seed, mnemonic, "");
    printf("seed length: %d\n", seedLen);

    char* privateKey = FileCoin::GetSinglePrivateKey(seed, seedLen);
    printf("filecoin single private key: %s\n", privateKey);

    char* publicKey = FileCoin::GetSinglePublicKey(seed, seedLen);
    printf("filecoin single public key: %s\n", publicKey);

    char* address = FileCoin::GetAddress(publicKey);
    printf("filecoin single address: %s\n\n", address);

    std::string unsignedData = 
        "{"
        "\"to\": \"t3xcnpgqifiwjivr65ylnxrvk3qjxb2hu5wz5b26z6kzr7z5shu4bicfwhv5vyoxyfiy6pjpj44cwndtmwe4ka\","
        "\"from\": \"t3s7px2ud2iajvsuxnynq4dvf4wbxrey4ipt3csk444irrgsorq5ctrknrtqml5kwewifbgqikecgdgnmbpq5a\","
        "\"value\": \"1\","
        "\"gasPremium\": \"1000000\","
        "\"gasFeeCap\": \"1000000\","
        "\"gasLimit\": 80000000,"
        "\"method\": 0,"
        "\"nonce\": 0,"
        "\"params\": \"\""
        "}";
    printf("filecoin unsigned data: %s\n", unsignedData.c_str());

    uint8_t* signature;
    int signSize = FileCoin::Sign(privateKey, (void*)unsignedData.c_str(), unsignedData.length(), (void**)&signature);
    printf("filecoin signed data len: %d\n", signSize);

    bool bVerify = FileCoin::Verify(publicKey, (void*)unsignedData.c_str(), unsignedData.length(), signature, signSize);
    printf("filecoin verify data result: %d\n", bVerify);

    auto signBase64 = Base64::fromBits(signature, signSize);

    std::stringstream signedData;
    signedData << "{";
    signedData <<   "\"Message\": "<< unsignedData << ",";
    signedData <<   "\"Signature\": {";
    signedData <<       "\"Type\": 1,";
    signedData <<       "\"Data\": \"" << signBase64 << "\"";
    signedData <<   "}";
    signedData << "}";
    printf("filecoin signed data: %s\n", signedData.str().c_str());

    free(signature);
    free(privateKey);
    free(publicKey);
    free(address);

    printf("============= end TestFileCoin ===========\n");
}

void TestFileCoinTransaction()
{
    printf("============= start TestFileCoinTransaction ===========\n");

    const char* mnemonic = "voice kingdom wall sword pair unusual artefact opera keen aware stay game";

    //char* mnemonic = generateMnemonic("english", "");
    //printf("mnemonic: %s\n", mnemonic);

    void* seed;
    int seedLen = getSeedFromMnemonic(&seed, mnemonic, "");
    printf("seed length: %d\n", seedLen);

    char* privateKey = FileCoin::GetSinglePrivateKey(seed, seedLen);
    printf("filecoin single private key: %s\n", privateKey);
    char* publicKey = FileCoin::GetSinglePublicKey(seed, seedLen);
    printf("filecoin single public key: %s\n", publicKey);
    char* address = FileCoin::GetAddress(publicKey);
    printf("filecoin single address: %s\n\n", address);

    std::string unsignedData = std::string()
        +"{"
        +"\"Version\": 0,"
        +"\"To\": \"t3xcnpgqifiwjivr65ylnxrvk3qjxb2hu5wz5b26z6kzr7z5shu4bicfwhv5vyoxyfiy6pjpj44cwndtmwe4ka\","
        +"\"From\": \"t3s7px2ud2iajvsuxnynq4dvf4wbxrey4ipt3csk444irrgsorq5ctrknrtqml5kwewifbgqikecgdgnmbpq5a\","
        +"\"Nonce\": 10,"
        +"\"Value\": \"1\","
        +"\"GasPremium\": \"1000000\","
        +"\"GasFeeCap\": \"1000000\","
        +"\"GasLimit\": 80000000,"
        +"\"Method\": 0,"
        +"\"Params\": \"\""
        +"}";
        //+ "{"
        //+ "\"to\": \"t3xcnpgqifiwjivr65ylnxrvk3qjxb2hu5wz5b26z6kzr7z5shu4bicfwhv5vyoxyfiy6pjpj44cwndtmwe4ka\","
        //+ "\"from\": \"" + address + "\","
        //+ "\"value\": \"1\","
        //+ "\"gasPremium\": \"1000000\","
        //+ "\"gasFeeCap\": \"1000000\","
        //+ "\"gasLimit\": 80000000,"
        //+ "\"method\": 0,"
        //+ "\"nonce\": 0,"
        //+ "\"params\": \"\""
        //+ "}";
    printf("filecoin unsigned data: %s\n", unsignedData.c_str());
    char* signedData = FileCoin::GenerateRawTransaction(privateKey, unsignedData.c_str());
    printf("filecoin signed data: %s\n", signedData);

    free(signedData);
    free(privateKey);
    free(publicKey);
    free(address);

    printf("============= end TestFileCoinTransaction ===========\n");
}
#endif

const char *c_help = \
    "genmne    test generate mnemonic, get private key, public key, address.\n" \
    "hd        test generate hd wallet address.\n" \
    "did       test generate did.\n"
    "sign      test generate raw transaction.\n" \
    "cosign    test cosign raw transaction.\n" \
    "crypto    test encrytion and decryption.\n" \
    "de        test deserialize the transaction.\n" \
    "info      test address and did from personal info.\n" \
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
        else if (!command.compare("crypto")) {
            std::string text;
            std::cout << "input data: ";
            std::getline(std::cin, text);
            Crypto(text.c_str());
        }
        else if (!command.compare("de")) {
            deserializeTx();
        }
        else if (!command.compare("vmemo")) {
            verifyMemo();
        }
        else if (!command.compare("info")) {
            std::string text;
            std::cout << "input data: ";
            std::getline(std::cin, text);
            testInfoAddress(text.c_str());
        }
        else if (command == "fc") {
            TestFileCoin();
        }
        else if (command == "fc-tx") {
            TestFileCoinTransaction();
        }
        else if (command.length() != 0){
            std::cout << "not support command\n";
        }
    }

    return 0;
}

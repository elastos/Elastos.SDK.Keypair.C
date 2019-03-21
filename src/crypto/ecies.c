

#include "ecies.h"

EC_GROUP *eliptic = NULL;

static void printErrorMsg(const char* func)
{
    printf("%s failed. error msg: %s}\n", func, ERR_error_string(ERR_get_error(), NULL));
}

void ecies_group_init(void) {

    EC_GROUP *group;

    if (!(group = EC_GROUP_new_by_curve_name(ECIES_CURVE))) {
        printErrorMsg("EC_GROUP_new_by_curve_name");
    }

    if (EC_GROUP_precompute_mult(group, NULL) != 1) {
        printErrorMsg("EC_GROUP_precompute_mult");
        EC_GROUP_free(group);
    }

    EC_GROUP_set_point_conversion_form(group, POINT_CONVERSION_COMPRESSED);
    eliptic = group;

    return;
}

void ecies_group_free(void) {
    if (!eliptic) return;

    EC_GROUP *group = eliptic;
    eliptic = NULL;

    EC_GROUP_free(group);
}

EC_GROUP * ecies_group(void) {
    if (eliptic) {
        return EC_GROUP_dup(eliptic);
    }

    EC_GROUP *group;
    if (!(group = EC_GROUP_new_by_curve_name(ECIES_CURVE))) {
        printErrorMsg("EC_GROUP_new_by_curve_name");
        return NULL;
    }

    if (EC_GROUP_precompute_mult(group, NULL) != 1) {
        printErrorMsg("EC_GROUP_precompute_mult");
        EC_GROUP_free(group);
        return NULL;
    }

    EC_GROUP_set_point_conversion_form(group, POINT_CONVERSION_COMPRESSED);

    return EC_GROUP_dup(group);
}

void ecies_key_free(EC_KEY *key) {
    EC_KEY_free(key);
    return;
}

EC_KEY * ecies_key_create(void) {

    EC_GROUP* group = NULL;
    EC_KEY *key = NULL, *ret = NULL;

    if (!(key = EC_KEY_new())) {
        printErrorMsg("EC_KEY_new");
        goto exit;
    }

    if (!(group = ecies_group())) {
        goto exit;
    }

    if (EC_KEY_set_group(key, group) != 1) {
        printErrorMsg("EC_KEY_set_group");
        goto exit;
    }

    if (EC_KEY_generate_key(key) != 1) {
        printErrorMsg("EC_KEY_generate_key");
        goto exit;
    }

    ret = key;

exit:
    if (group != NULL) {
        EC_GROUP_free(group);
    }
    if (ret == NULL && key != NULL) {
        EC_KEY_free(key);
    }
    return ret;
}

EC_KEY * ecies_create_key_by_public_octets(unsigned char *octets, size_t length) {

    EC_GROUP *group = NULL;
    EC_KEY *key = NULL, *ret = NULL;
    EC_POINT *point = NULL;

    if (!(key = EC_KEY_new())) {
        printErrorMsg("EC_KEY_new");
        goto exit;
    }

    if (!(group = ecies_group())) {
        EC_KEY_free(key);
        goto exit;
    }

    if (EC_KEY_set_group(key, group) != 1) {
        printErrorMsg("EC_KEY_set_group");
        goto exit;
    }

    if (!(point = EC_POINT_new(group))) {
        printErrorMsg("EC_POINT_new");
        goto exit;
    }

    if (EC_POINT_oct2point(group, point, octets, length, NULL) != 1) {
        printErrorMsg("EC_POINT_oct2point");
        goto exit;
    }

    if (EC_KEY_set_public_key(key, point) != 1) {
        printErrorMsg("EC_KEY_set_public_key");
        goto exit;
    }

    if (EC_KEY_check_key(key) != 1) {
        printErrorMsg("EC_KEY_check_key");
        goto exit;
    }

    ret = key;

exit:
    if (group != NULL) {
        EC_GROUP_free(group);
    }
    if (point != NULL) {
        EC_POINT_free(point);
    }
    if (ret == NULL && key != NULL) {
        EC_KEY_free(key);
    }
    return ret;
}

EC_KEY * ecies_create_key_by_public_hex(const char* hex) {

    EC_GROUP *group = NULL;
    EC_KEY *key = NULL, *ret = NULL;
    EC_POINT *point = NULL;

    if (!(key = EC_KEY_new())) {
        printErrorMsg("EC_KEY_new");
        goto exit;
    }

    if (!(group = EC_GROUP_new_by_curve_name(ECIES_CURVE))) {
        printErrorMsg("EC_GROUP_new_by_curve_name");
        goto exit;
    }

    EC_GROUP_set_point_conversion_form(group, POINT_CONVERSION_COMPRESSED);

    if (EC_KEY_set_group(key, group) != 1) {
        printErrorMsg("EC_KEY_set_group");
        goto exit;
    }

    if (!(point = EC_POINT_hex2point(group, hex, NULL, NULL))) {
        printErrorMsg("EC_POINT_hex2point");
        goto exit;
    }

    if (EC_KEY_set_public_key(key, point) != 1) {
        printErrorMsg("EC_KEY_set_public_key");
        goto exit;
    }

    if (EC_KEY_check_key(key) != 1) {
        printErrorMsg("EC_KEY_check_key");
        goto exit;
    }

    ret = key;

exit:
    if (group != NULL) {
        EC_GROUP_free(group);
    }
    if (point != NULL) {
        EC_POINT_free(point);
    }
    if (ret == NULL && key != NULL) {
        EC_KEY_free(key);
    }
    return ret;
}

char * ecies_get_public_hex(EC_KEY *key) {

    char *hex;
    const EC_POINT *point;
    const EC_GROUP *group;

    if (!(point = EC_KEY_get0_public_key(key))) {
        printErrorMsg("EC_KEY_get0_public_key");
        return NULL;
    }

    if (!(group = EC_KEY_get0_group(key))) {
        printErrorMsg("EC_KEY_get0_group");
        return NULL;
    }

    if (!(hex = EC_POINT_point2hex(group, point, POINT_CONVERSION_COMPRESSED, NULL))) {
        printErrorMsg("EC_POINT_point2hex");
        return NULL;
    }

    return hex;
}

EC_KEY * ecies_create_key_by_private_hex(const char *hex) {

    EC_GROUP *group = NULL;
    BIGNUM *bn = NULL;
    EC_KEY *key = NULL, *ret = NULL;

    if (!(key = EC_KEY_new())) {
        printErrorMsg("EC_KEY_new");
        goto exit;
    }

    if (!(group = EC_GROUP_new_by_curve_name(ECIES_CURVE))) {
        printErrorMsg("EC_GROUP_new_by_curve_name");
        goto exit;
    }

    EC_GROUP_set_point_conversion_form(group, POINT_CONVERSION_COMPRESSED);

    if (EC_KEY_set_group(key, group) != 1) {
        printErrorMsg("EC_KEY_set_group");
        goto exit;
    }

    if (!(BN_hex2bn(&bn, hex))) {
        printErrorMsg("BN_hex2bn");
        goto exit;
    }

    if (EC_KEY_set_private_key(key, bn) != 1) {
        printErrorMsg("EC_KEY_set_private_key");
        goto exit;
    }

    ret = key;

exit:
    if (group != NULL) {
        EC_GROUP_free(group);
    }
    if (bn != NULL) {
        BN_free(bn);
    }
    if (ret == NULL && key != NULL) {
        EC_KEY_free(key);
    }
    return ret;
}

char * ecies_get_private_hex(EC_KEY *key) {

    char *hex;
    const BIGNUM *bn;

    if (!(bn = EC_KEY_get0_private_key(key))) {
        printErrorMsg("EC_KEY_get0_private_key");
        return NULL;
    }

    if (!(hex = BN_bn2hex(bn))) {
        printErrorMsg("BN_bn2hex");
        return NULL;
    }

    return hex;
}

cipher_t * cipher_alloc(uint64_t key, uint64_t mac, uint64_t orig, uint64_t body) {
    cipher_t* cryptex = malloc(sizeof(cipher_head) + key + mac + body);
    cipher_head* head = (cipher_head*)cryptex;
    head->key = key;
    head->mac = mac;
    head->orig = orig;
    head->body = body;
    return cryptex;
}

void cipher_free(cipher_t* cryptex) {
    free(cryptex);
    return;
}

cipher_t* get_cipher_data(CipherType type, cipher_t* cipher)
{
    cipher_head* head = (cipher_head*)cipher;
    switch(type) {
    case CipherType_Key:
        return cipher + sizeof(cipher_head);
    case CipherType_MAC:
        return cipher + (sizeof(cipher_head) + head->key);
    case CipherType_Body:
        return cipher + (sizeof(cipher_head) + head->key + head->mac);
    default:
        return NULL;
    }
}

uint64_t get_cipher_length(CipherType type, cipher_t* cipher)
{
    cipher_head* head = (cipher_head*)cipher;
    switch(type) {
    case CipherType_Key:
        return head->key;
    case CipherType_MAC:
        return head->mac;
    case CipherType_Orig:
        return head->orig;
    case CipherType_Body:
        return head->body;
    default:
        return sizeof(cipher_head) + (head->key + head->mac + head->body);
    }
}

static void * KDF1_SHA512(const void *in, size_t inlen, void *out, size_t *outlen) {
#ifndef OPENSSL_NO_SHA
    if (*outlen < SHA512_DIGEST_LENGTH) {
        return NULL;
    }

    *outlen = SHA512_DIGEST_LENGTH;
    return SHA512(in, inlen, out);
#else
    return NULL;
#endif  // OPENSSL_NO_SHA
}

cipher_t * ecies_encrypt(const char* publickey, const unsigned char *data, size_t length) {
    if (!publickey || !data || !length) {
        printf("Invalid parameters.\n");
        return NULL;
    }

    cipher_t* body;
    int body_length;
    cipher_t* cryptex = NULL, *ret = NULL;
    EVP_CIPHER_CTX* cipher = EVP_CIPHER_CTX_new();
    HMAC_CTX* hmac = HMAC_CTX_new();
    EC_KEY *user = NULL, *ephemeral = NULL;
    size_t envelope_length, block_length, key_length;
    unsigned char envelope_key[SHA512_DIGEST_LENGTH], iv[EVP_MAX_IV_LENGTH], block[EVP_MAX_BLOCK_LENGTH];


    // Make sure we are generating enough key material for the symmetric ciphers.
    if ((key_length = EVP_CIPHER_key_length(ECIES_CIPHER)) * 2 > SHA512_DIGEST_LENGTH) {
        printf("The key derivation method will not produce enough envelope key material for the chosen ciphers. \
            envelope = %i, required = %zu", SHA512_DIGEST_LENGTH / 8, (key_length * 2) / 8);
        goto exit;
    }

    // Convert the input public key from hex to EC_KEY.
    if (!(user = ecies_create_key_by_public_hex(publickey))) {
        printf("Invalid public key.\n");
        goto exit;
    }

    // Create the ephemeral key used specifically for this block of data.
    if (!(ephemeral = ecies_key_create())) {
        printf("Generate the ephemeral key failed.\n");
        goto exit;
    }

    // Generate the envelope data used by the ciphers below.
    if (ECDH_compute_key(envelope_key, SHA512_DIGEST_LENGTH,
            EC_KEY_get0_public_key(user), ephemeral, KDF1_SHA512) != SHA512_DIGEST_LENGTH) {
        printErrorMsg("ECDH_compute_key");
        goto exit;
    }

    // Determine the envelope and block lengths so we can allocate a buffer for the result.
    if ((block_length = EVP_CIPHER_block_size(ECIES_CIPHER)) == 0 || block_length > EVP_MAX_BLOCK_LENGTH ||
             (envelope_length = EC_POINT_point2oct(EC_KEY_get0_group(ephemeral), EC_KEY_get0_public_key(ephemeral),
                                                   POINT_CONVERSION_COMPRESSED, NULL, 0, NULL)) == 0) {
        printf("Invalid block or envelope length. block = %zu, envelope = %zu\n", block_length, envelope_length);
        goto exit;
    }

    body_length = length + (length % block_length ? (block_length - (length % block_length)) : 0);
    if (!(cryptex = cipher_alloc(envelope_length, EVP_MD_size(ECIES_HASHER), length, body_length))) {
        printf("cipher_alloc failed.\n");
        goto exit;
    }

    // Store the ephemeral public key.
    if (EC_POINT_point2oct(EC_KEY_get0_group(ephemeral), EC_KEY_get0_public_key(ephemeral),
            POINT_CONVERSION_COMPRESSED, (unsigned char *)get_cipher_data(CipherType_Key, cryptex),
            envelope_length, NULL) != envelope_length) {
        printErrorMsg("store the ephemeral public key");
        goto exit;
    }

    // Initialize vector.
    memset(iv, 0, EVP_MAX_IV_LENGTH);

    // Setup the cipher context, the body length, and store a pointer to the body buffer location.
    EVP_CIPHER_CTX_init(cipher);
    body = get_cipher_data(CipherType_Body, cryptex);

    // Initialize the cipher with the envelope key.
    if (EVP_EncryptInit_ex(cipher, ECIES_CIPHER, NULL, envelope_key, iv) != 1
        || EVP_CIPHER_CTX_set_padding(cipher, 0) != 1
        || EVP_EncryptUpdate(cipher, (unsigned char *)body, &body_length, data, length - (length % block_length)) != 1) {
        printErrorMsg("encrypt data");
        goto exit;
    }

    // Check whether all of the data was encrypted.
    if (body_length != length) {

        // Make sure all that remains is a partial block, and their wasn't an error.
        if (length - body_length >= block_length) {
            printErrorMsg("encrypt data");
            goto exit;
        }

        // Copy the remaining data into block buffer.
        memset(block, 0, EVP_MAX_BLOCK_LENGTH);
        memcpy(block, data + body_length, length - body_length);

        // move body pointer to the location of the remaining space, and check the space is still available.
        body += body_length;
        if ((body_length = get_cipher_length(CipherType_Body, cryptex) - body_length) < 0) {
            printf("The symmetric cipher overflowed!\n");
            goto exit;
        }

        // Encrypt the final block data as a complete block.
        if (EVP_EncryptUpdate(cipher, (unsigned char *)body, &body_length, block, block_length) != 1) {
            printErrorMsg("EVP_EncryptUpdate");
            goto exit;
        }
    }

    // Check whether all of the data was encrypted.
    body += body_length;
    if (get_cipher_length(CipherType_Body, cryptex) - (body - get_cipher_data(CipherType_Body, cryptex)) < 0) {
        printf("The symmetric cipher overflowed!\n");
        goto exit;
    }

    if (EVP_EncryptFinal_ex(cipher, (unsigned char *)body, &body_length) != 1) {
        printErrorMsg("EVP_EncryptFinal_ex");
        goto exit;
    }


    // Generate the hash using encrypted data which can be used to validate the data during decryption.
    if (HMAC_Init_ex(hmac, envelope_key + key_length, key_length, ECIES_HASHER, NULL) != 1
        || HMAC_Update(hmac, (unsigned char *)get_cipher_data(CipherType_Body, cryptex), get_cipher_length(CipherType_Body, cryptex)) != 1
        || HMAC_Final(hmac, (unsigned char *)get_cipher_data(CipherType_MAC, cryptex), NULL) != 1) {
        printErrorMsg("Generate data authentication code");
        goto exit;
    }

    ret = cryptex;

exit:
    EVP_CIPHER_CTX_free(cipher);
    HMAC_CTX_free(hmac);

    if (ephemeral != NULL) {
        EC_KEY_free(ephemeral);
    }

    if (user != NULL) {
        EC_KEY_free(user);
    }

    if (!ret && cryptex != NULL) {
        cipher_free(cryptex);
    }

    return ret;
}

unsigned char * ecies_decrypt(const char* privateKey, cipher_t *cryptex, size_t *length) {

    if (!privateKey || !cryptex || !length) {
        printf("Invalid parameters.\n");
        return NULL;
    }

    HMAC_CTX* hmac = HMAC_CTX_new();
    size_t key_length;
    int output_length;
    EVP_CIPHER_CTX *cipher = EVP_CIPHER_CTX_new();
    EC_KEY *user = NULL, *ephemeral = NULL;
    unsigned int mac_length = EVP_MAX_MD_SIZE;
    unsigned char envelope_key[SHA512_DIGEST_LENGTH], iv[EVP_MAX_IV_LENGTH], md[EVP_MAX_MD_SIZE];
    unsigned char *block, *output = NULL, *ret = NULL;

    // Make sure we are generating enough key material for the symmetric ciphers.
    if ((key_length = EVP_CIPHER_key_length(ECIES_CIPHER)) * 2 > SHA512_DIGEST_LENGTH) {
        printf("The key derivation method will not produce enough envelope key material for the chosen ciphers. \
            envelope = %i, required = %zu", SHA512_DIGEST_LENGTH / 8, (key_length * 2) / 8);
        goto exit;
    }

    // Convert the input private key from hex to EC_KEY.
    if (!(user = ecies_create_key_by_private_hex(privateKey))) {
        printf("Invalid private key.\n");
        goto exit;
    }

    // Create the ephemeral key.
    if (!(ephemeral =
               ecies_create_key_by_public_octets((unsigned char *)get_cipher_data(CipherType_Key, cryptex),
               get_cipher_length(CipherType_Key, cryptex)))) {
        printf("Recreate the ephemeral key failed.\n");
        goto exit;
    }


    // Generate the envelope data used by the ciphers below.
    if (ECDH_compute_key(envelope_key, SHA512_DIGEST_LENGTH,
            EC_KEY_get0_public_key(ephemeral), user, KDF1_SHA512) != SHA512_DIGEST_LENGTH) {
        printErrorMsg("ECDH_compute_key");
        goto exit;
    }

    // Generate the hash using encrypted data.
    if (HMAC_Init_ex(hmac, envelope_key + key_length, key_length, ECIES_HASHER, NULL) != 1
        || HMAC_Update(hmac, (unsigned char *)get_cipher_data(CipherType_Body, cryptex), get_cipher_length(CipherType_Body, cryptex))!= 1
        || HMAC_Final(hmac, md, &mac_length) != 1) {
        printErrorMsg("Generate authentication code");
        goto exit;
    }

    // Verify the hash.
    if (mac_length != get_cipher_length(CipherType_MAC, cryptex)
        || memcmp(md, get_cipher_data(CipherType_MAC, cryptex), mac_length)) {
        printf("The authentication code was invalid! The ciphered data has been corrupted!\n");
        goto exit;
    }

    output_length = get_cipher_length(CipherType_Body, cryptex);
    if (!(block = output = malloc(output_length + 1))) {
        goto exit;
    }

    // Initialize vector, clear out the result buffer.
    memset(iv, 0, EVP_MAX_IV_LENGTH);
    memset(output, 0, output_length + 1);

    EVP_CIPHER_CTX_init(cipher);

    // Decrypt the data using the chosen symmetric cipher.
    if (EVP_DecryptInit_ex(cipher, ECIES_CIPHER, NULL, envelope_key, iv)!= 1
        || EVP_CIPHER_CTX_set_padding(cipher, 0) != 1
        || EVP_DecryptUpdate(cipher, block, &output_length,
            (unsigned char *)get_cipher_data(CipherType_Body, cryptex), get_cipher_length(CipherType_Body, cryptex)) != 1) {
        printErrorMsg("Decrypt data");
        goto exit;
    }

    block += output_length;
    if (get_cipher_length(CipherType_Body, cryptex) - output_length != 0) {
        goto exit;
    }

    if (EVP_DecryptFinal_ex(cipher, block, &output_length) != 1) {
        printErrorMsg("EVP_DecryptFinal_ex");
        goto exit;
    }

    *length = get_cipher_length(CipherType_Orig, cryptex);
    ret = output;

exit:
    HMAC_CTX_free(hmac);
    EVP_CIPHER_CTX_free(cipher);

    if (ephemeral != NULL) {
        EC_KEY_free(ephemeral);
    }

    if (user != NULL) {
        EC_KEY_free(user);
    }

    if (!ret && output != NULL) {
        free(output);
    }

    return ret;
}

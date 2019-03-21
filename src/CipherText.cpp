
#include <string>

#include <openssl/evp.h>
#include <openssl/ssl.h>
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/stack.h>

static void* ecies_key_derivation(const void* input, size_t ilen, void *output,
                            size_t *olen) {

    if (*olen < SHA512_DIGEST_LENGTH) {
        return NULL;
    }

    *olen = SHA512_DIGEST_LENGTH;
    return SHA512((const unsigned char*)input, ilen, (unsigned char*)output);
}

static EC_KEY* ecies_create_key(const EC_GROUP* group)
{
    EC_KEY *key = EC_KEY_new();
    if (key == NULL) {
        printf("EC_KEY_new failed. {error = %s}\n", ERR_error_string(ERR_get_error(), NULL));
        return NULL;
    }

    if (EC_KEY_set_group(key, group) != 1) {
        printf("EC_KEY_set_group failed. {error = %s}\n", ERR_error_string(ERR_get_error(), NULL));
        EC_KEY_free(key);
        return NULL;
    }

    if (EC_KEY_generate_key(key) != 1) {
        printf("EC_KEY_generate_key failed. {error = %s}\n", ERR_error_string(ERR_get_error(), NULL));
        EC_KEY_free(key);
        return NULL;
    }

    return key;
}

int ecies_encrypt(const void *pubKey, size_t pubKeyLen, const char* plainText, unsigned char* cipherText, size_t* cipherLen)
{
    int ret = -1;
    if (0 == pubKeyLen || NULL == plainText || NULL == cipherText) {
        return ret;
    }


    BIGNUM *_pubkey = NULL;
    EVP_CIPHER_CTX *ctx = NULL;
    EC_KEY* key = NULL;
    EC_KEY* ephemeral = NULL;
    int len;
    size_t envelope_length;
    unsigned char envelope_key[SHA512_DIGEST_LENGTH], iv[EVP_MAX_IV_LENGTH];

    // _pubkey = BN_bin2bn((const unsigned char *) (uint8_t *) pubKey, (int) pubKeyLen, NULL);
    // key = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
    // if (_pubkey == NULL || key == NULL) goto exit;

    // const EC_GROUP *curve = EC_KEY_get0_group(key);
    // EC_POINT *ec_p = EC_POINT_bn2point(curve, _pubkey, NULL, NULL);
    // if (ec_p == NULL) goto exit;

    // EC_KEY_set_public_key(key, ec_p);


    // if (!(ephemeral = ecies_create_key(curve))) {
    //     goto exit;
    // }

    if (ECDH_compute_key(envelope_key, SHA512_DIGEST_LENGTH, EC_KEY_get0_public_key(key),
        ephemeral, ecies_key_derivation) != SHA512_DIGEST_LENGTH) {
        printf("ECDH_compute_key failed. {error = %s}\n", ERR_error_string(ERR_get_error(), NULL));
        goto exit;
    }

    /* For now we use an empty initialization vector.*/
    memset(iv, 0, EVP_MAX_IV_LENGTH);

    /* Create and initialise the context */
    if(!(ctx = EVP_CIPHER_CTX_new())) {
        goto exit;
    }

    /* Initialise the envelope seal operation. This operation generates
     * a key for the provided cipher, and then encrypts that key a number
     * of times (one for each public key provided in the pub_key array). In
     * this example the array size is just one. This operation also
     * generates an IV and places it in iv. */
    // if(1 != EVP_SealInit(ctx, EVP_aes_256_cbc(), envelope_key, SHA512_DIGEST_LENGTH, iv, pub_key, 1)) {
    //     goto exit;
    // }

    // /* Provide the message to be encrypted, and obtain the encrypted output.
    //  * EVP_SealUpdate can be called multiple times if necessary
    //  */
    // if(1 != EVP_SealUpdate(ctx, cipherText, &len, plainText, strlen(plainText))) {
    //     goto exit;
    // }
    // *cipherLen = len;

    // /* Finalise the encryption. Further ciphertext bytes may be written at
    //  * this stage.
    //  */
    // if(1 != EVP_SealFinal(ctx, cipherText + len, &len)) {
    //     ret = -1;
    //     goto exit;
    // }
    // *cipherLen += len;

exit:
    /* Clean up */
    if (NULL != _pubkey) {
        BN_free(_pubkey);
    }
    if (NULL != key) {
        EC_KEY_free(key);
    }
    if (NULL != ephemeral) {
        EC_KEY_free(ephemeral);
    }
    if (NULL != ctx) {
        EVP_CIPHER_CTX_free(ctx);
    }

    return ret;
}

int ecies_decrypt(const void *privKey, size_t privKeyLen, const char* cipherText, char* plainText, size_t* plainLen)
{
    // EVP_CIPHER_CTX *ctx;

    // int len;

    // int plaintext_len;


    // /* Create and initialise the context */
    // if(!(ctx = EVP_CIPHER_CTX_new())) handleErrors();

    // /* Initialise the decryption operation. The asymmetric private key is
    //  * provided and priv_key, whilst the encrypted session key is held in
    //  * encrypted_key */
    // if(1 != EVP_OpenInit(ctx, EVP_aes_256_cbc(), encrypted_key,
    //     encrypted_key_len, iv, priv_key))
    //     handleErrors();

    //  Provide the message to be decrypted, and obtain the plaintext output.
    //  * EVP_OpenUpdate can be called multiple times if necessary

    // if(1 != EVP_OpenUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len))
    //     handleErrors();
    // plaintext_len = len;

    // /* Finalise the decryption. Further plaintext bytes may be written at
    //  * this stage.
    //  */
    // if(1 != EVP_OpenFinal(ctx, plaintext + len, &len)) handleErrors();
    // plaintext_len += len;

    // /* Clean up */
    // EVP_CIPHER_CTX_free(ctx);

    // return plaintext_len;

    return 0;
}


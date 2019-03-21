
#ifndef __ECIES_H__
#define __ECIES_H__

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <inttypes.h>

#include <openssl/ssl.h>
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/stack.h>


#ifdef __cplusplus
extern "C" {
#endif


#define ECIES_CURVE NID_X9_62_prime256v1
#define ECIES_CIPHER EVP_aes_256_cbc()
#define ECIES_HASHER EVP_sha512()

typedef struct {
    uint64_t key;
    uint64_t mac;
    uint64_t orig;
    uint64_t body;
} cipher_head;

typedef char cipher_t;

typedef enum {
    CipherType_Key = 0,
    CipherType_MAC,
    CipherType_Orig,
    CipherType_Body
} CipherType;

cipher_t * cipher_alloc(uint64_t key, uint64_t mac, uint64_t orig, uint64_t body);
void cipher_free(cipher_t* cryptex);

cipher_t* get_cipher_data(CipherType type, cipher_t* cipher);
uint64_t get_cipher_length(CipherType type, cipher_t* cipher);

void ecies_group_init(void);
void ecies_group_free(void);
EC_GROUP * ecies_group(void);

void ecies_key_free(EC_KEY *key);

EC_KEY * ecies_key_create(void);
EC_KEY * ecies_create_key_by_public_hex(const char *hex);
EC_KEY * ecies_create_key_by_private_hex(const char *hex);
EC_KEY * ecies_create_key_by_public_octets(unsigned char *octets, size_t length);

char * ecies_get_public_hex(EC_KEY *key);
char * ecies_get_private_hex(EC_KEY *key);

cipher_t * ecies_encrypt(const char* publickey, const unsigned char *data, size_t length);
unsigned char * ecies_decrypt(const char* privatekey, cipher_t *cryptex, size_t *length);


#ifdef __cplusplus
}
#endif

#endif // __ECIES_H__

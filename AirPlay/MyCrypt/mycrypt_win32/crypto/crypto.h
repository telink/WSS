/*
 * Copyright (c) 2007, Cameron Rich
 * 
 * All rights reserved.
 * 
 * Redistribution and use in source and binary forms, with or without 
 * modification, are permitted provided that the following conditions are met:
 *
 * * Redistributions of source code must retain the above copyright notice, 
 *   this list of conditions and the following disclaimer.
 * * Redistributions in binary form must reproduce the above copyright notice, 
 *   this list of conditions and the following disclaimer in the documentation 
 *   and/or other materials provided with the distribution.
 * * Neither the name of the axTLS project nor the names of its contributors 
 *   may be used to endorse or promote products derived from this software 
 *   without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR
 * CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
 * EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
 * PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
 * PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
 * LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
 * NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

/**
 * @file crypto.h
 */

#ifndef HEADER_CRYPTO_H
#define HEADER_CRYPTO_H

#ifdef __cplusplus
extern "C" {
#endif

#if defined(WIN32)
#if defined(MYCRYPT_EXPORTS)
#define EXP_FUNC __declspec(dllexport)
#define STDCALL
#else
#define EXP_FUNC __declspec(dllimport)
#define STDCALL
#endif
#else
#define EXP_FUNC
#endif

#ifndef STDCALL
#define STDCALL
#endif
#ifndef EXP_FUNC
#define EXP_FUNC
#endif

/**************************************************************************
 * AES declarations 
 **************************************************************************/

#define AES_MAXROUNDS			14
#define AES_BLOCKSIZE           16
#define AES_IV_SIZE             16

typedef struct aes_key_st 
{
    uint16_t rounds;
    uint16_t key_size;
    uint32_t ks[(AES_MAXROUNDS+1)*8];
    uint8_t iv[AES_IV_SIZE];
} AES_CTX;

typedef enum
{
    AES_MODE_128,
    AES_MODE_256
} AES_MODE;

EXP_FUNC void STDCALL AES_set_key(AES_CTX *ctx, const uint8_t *key, const uint8_t *iv, AES_MODE mode);
EXP_FUNC void STDCALL AES_cbc_encrypt(AES_CTX *ctx, const uint8_t *msg, uint8_t *out, int length);
EXP_FUNC void STDCALL AES_cbc_decrypt(AES_CTX *ks, const uint8_t *in, uint8_t *out, int length);
EXP_FUNC void STDCALL AES_convert_key(AES_CTX *ctx);

/**************************************************************************
 * New AES(openssl-1.01h) declarations with slight modifications
 **************************************************************************/
#define AES_ENCRYPT	1
#define AES_DECRYPT	0

/* Because array size can't be a const in C, the following two are macros.
   Both sizes are in bytes. */
#define AES_MAXNR 14
#define AES_BLOCK_SIZE 16

/* This should be a hidden type, but EVP requires that the size be known */
struct new_aes_key_st {
#ifdef AES_LONG
    unsigned long rd_key[4 *(AES_MAXNR + 1)];
#else
    unsigned int rd_key[4 *(AES_MAXNR + 1)];
#endif
    int rounds; 
    uint8_t iv[AES_IV_SIZE];
    uint8_t in[AES_BLOCK_SIZE];
    uint8_t out[AES_BLOCK_SIZE];
    unsigned int remain_bytes;
    unsigned int remain_flags;
};
typedef struct new_aes_key_st AES_KEY;

//EXP_FUNC const char* STDCALL AES_options(void);
EXP_FUNC int STDCALL AES_set_encrypt_key(const unsigned char *userKey, const int bits, AES_KEY *key);
EXP_FUNC int STDCALL AES_set_decrypt_key(const unsigned char *userKey, const int bits, AES_KEY *key);
EXP_FUNC int STDCALL private_AES_set_encrypt_key(const unsigned char *userKey, const int bits, AES_KEY *key);
EXP_FUNC int STDCALL private_AES_set_decrypt_key(const unsigned char *userKey, const int bits, AES_KEY *key);
EXP_FUNC void STDCALL new_AES_encrypt(const unsigned char *in, unsigned char *out, const AES_KEY *key);
EXP_FUNC void STDCALL new_AES_decrypt(const unsigned char *in, unsigned char *out, const AES_KEY *key);
EXP_FUNC void STDCALL new_AES_ecb_encrypt(const unsigned char *in, unsigned char *out, const AES_KEY *key, const int enc);
EXP_FUNC void STDCALL new_AES_cbc_encrypt(const unsigned char *in, unsigned char *out, size_t len, const AES_KEY *key, unsigned char *ivec, const int enc);
 

/**************************************************************************
 * RC4 declarations 
 **************************************************************************/

typedef struct 
{
    uint8_t x, y, m[256];
} RC4_CTX;

EXP_FUNC void STDCALL RC4_setup(RC4_CTX *s, const uint8_t *key, int length);
EXP_FUNC void STDCALL RC4_crypt(RC4_CTX *s, const uint8_t *msg, uint8_t *data, int length);

/**************************************************************************
 * SHA1 declarations 
 **************************************************************************/

#define SHA1_SIZE   20

/*
 *  This structure will hold context information for the SHA-1
 *  hashing operation
 */
typedef struct 
{
    uint32_t Intermediate_Hash[SHA1_SIZE/4]; /* Message Digest */
    uint32_t Length_Low;            /* Message length in bits */
    uint32_t Length_High;           /* Message length in bits */
    uint16_t Message_Block_Index;   /* Index into message block array   */
    uint8_t Message_Block[64];      /* 512-bit message blocks */
} SHA1_CTX;

EXP_FUNC void STDCALL SHA1_Init(SHA1_CTX *);
EXP_FUNC void STDCALL SHA1_Update(SHA1_CTX *, const uint8_t * msg, int len);
EXP_FUNC void STDCALL SHA1_Final(uint8_t *digest, SHA1_CTX *);
EXP_FUNC int STDCALL sha1(const unsigned char *message, size_t message_len, unsigned char *out);

/**************************************************************************
 * MD5 declarations 
 **************************************************************************/

#define MD5_SIZE    16

typedef struct 
{
  uint32_t state[4];        /* state (ABCD) */
  uint32_t count[2];        /* number of bits, modulo 2^64 (lsb first) */
  uint8_t buffer[64];       /* input buffer */
} MD5_CTX;

EXP_FUNC void STDCALL MD5_Init(MD5_CTX *);
EXP_FUNC void STDCALL MD5_Update(MD5_CTX *, const uint8_t *msg, int len);
EXP_FUNC void STDCALL MD5_Final(uint8_t *digest, MD5_CTX *);

/**************************************************************************
 * HMAC declarations 
 **************************************************************************/
EXP_FUNC void STDCALL hmac_md5(const uint8_t *msg, int length, const uint8_t *key, 
        int key_len, uint8_t *digest);
EXP_FUNC void STDCALL hmac_sha1(const uint8_t *msg, int length, const uint8_t *key, 
        int key_len, uint8_t *digest);

#ifdef __cplusplus
}
#endif

#endif 

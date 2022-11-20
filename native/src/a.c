#include <stdio.h>
#include <assert.h>
#include <string.h>

#include <secp256k1/include/secp256k1.h>
#include <secp256k1/include/secp256k1_ecdh.h>

#include "a.h"

void ecdh(unsigned char *secret_key, unsigned char *pub_key, unsigned char *shared_secret)
{
    int return_val;

    secp256k1_pubkey public_key;
    memcpy(public_key.data, pub_key, 64);

    secp256k1_context *ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN);

    return_val = secp256k1_ecdh(ctx, shared_secret, &public_key, secret_key, NULL, NULL);

    if (!return_val)
    {
        printf("Error while creating ECDH Secret");
    }
}
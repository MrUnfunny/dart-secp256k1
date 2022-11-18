#include <stdio.h>
#include <assert.h>
#include <string.h>

#include <secp256k1/include/secp256k1.h>
#include <secp256k1/include/secp256k1_ecdh.h>

#include "random.h"
#include "a.h"

void tryFunc(unsigned char *seckey1, unsigned char *seckey2, unsigned char *shared_secret)
{
    int return_val;

    secp256k1_pubkey pubkey1;
    secp256k1_pubkey pubkey2;

    secp256k1_context *ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN);

    return_val = secp256k1_ec_pubkey_create(ctx, &pubkey1, seckey1);
    return_val = secp256k1_ec_pubkey_create(ctx, &pubkey2, seckey2);

    return_val = secp256k1_ecdh(ctx, shared_secret, &pubkey2, seckey1, NULL, NULL);

    printf("Secret Key1: ");
    print_hex(seckey1, 32);
    printf("\nSecret Key2: ");
    print_hex(seckey2, 32);
    printf("\nShared Secret: ");
    print_hex(shared_secret, sizeof(shared_secret));
    printf("return val is $i", return_val);
}

void print_hello()
{
    printf("Hello World");
}
#include <stdio.h>
#include <assert.h>
#include <string.h>

#include <secp256k1/include/secp256k1.h>
#include <secp256k1/include/secp256k1_ecdh.h>
#include <secp256k1/include/secp256k1_recovery.h>

#include "a.hpp"

extern "C"
{
    void ecdh(unsigned char *secretKey, unsigned char *pubKey, unsigned char *sharedSecret)
    {
        int return_val;

        secp256k1_pubkey public_key;
        memcpy(public_key.data, pubKey, 64);

        secp256k1_context *ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN);

        return_val = secp256k1_ecdh(ctx, sharedSecret, &public_key, secretKey, NULL, NULL);

        if (!return_val)
        {
            printf("Error while creating ECDH Secret");
        }
    }
}

extern "C"
{
    int ecdsaRecover(unsigned char *resPubKey, unsigned char *msgHash, unsigned char *signature, int rec_id)
    {
        int sig_parse_return_val;
        int recover_return_val;
        int serialize_return_val;

        secp256k1_context *ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
        secp256k1_ecdsa_recoverable_signature ecsig;

        sig_parse_return_val = secp256k1_ecdsa_recoverable_signature_parse_compact(ctx, &ecsig, signature, rec_id);
        if (!sig_parse_return_val)
        {
            sig_parse_return_val = 11;
            printf("CT_sig_to_pubkey fail ecdsa recoverable signature\n");
        }

        secp256k1_pubkey ecpub;
        recover_return_val = secp256k1_ecdsa_recover(ctx, &ecpub, &ecsig, msgHash);
        if (!recover_return_val)
        {
            recover_return_val = 22;
            printf("CT_sig_to_pubkey fail ecdsa recover\n");
        }

        size_t output_len = 33;
        serialize_return_val = secp256k1_ec_pubkey_serialize(ctx, resPubKey, &output_len, &ecpub, SECP256K1_EC_COMPRESSED);
        if (!serialize_return_val)
        {
            serialize_return_val = 33;
            printf("CT_sig_to_pubkey ec pubkey serialize\n");
        }
        return sig_parse_return_val + recover_return_val + serialize_return_val;
    }
}

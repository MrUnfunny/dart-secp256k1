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
    void CT_sig_to_pubkey(unsigned char *resPubKey, unsigned char *msgHash, unsigned char *signature)
    {
        const auto rec_id_from_header = [](int header) -> int
        {
            int header_num = header & 0xff;
            if (header_num >= 39)
            {
                header_num -= 12;
            }
            else if (header_num >= 35)
            {
                header_num -= 8;
            }
            else if (header_num >= 31)
            {
                header_num -= 4;
            }
            int rec_id = header_num - 27;
            return rec_id;
        };
        printf("CT_sig_to_pubkey fail ecdsa recoverable signature");

        secp256k1_context *ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN);
        int rec_id = rec_id_from_header(signature[0]);
        secp256k1_ecdsa_recoverable_signature ecsig;
        if (!secp256k1_ecdsa_recoverable_signature_parse_compact(
                ctx, &ecsig, signature + 1, rec_id))
        {
            printf("CT_sig_to_pubkey fail ecdsa recoverable signature");
        }
        secp256k1_pubkey ecpub;
        if (!secp256k1_ecdsa_recover(ctx, &ecpub, &ecsig, msgHash))
        {
            printf("CT_sig_to_pubkey fail ecdsa recover");
        }
        size_t output_len = 33;
        if (!secp256k1_ec_pubkey_serialize(ctx, resPubKey, &output_len, &ecpub, SECP256K1_EC_COMPRESSED))
        {
            printf("CT_sig_to_pubkey ec pubkey serialize");
        }
    }
}

int main()
{
    unsigned char sig[] = {0x20, 0xaa, 0x14, 0xea, 0x57, 0x40, 0x75, 0xba, 0x59, 0x7b, 0x8c, 0x4, 0x51, 0xba, 0xe7, 0xef, 0xc2, 0x7, 0xca, 0x4c, 0x6f, 0x10, 0x2, 0xf7, 0xa8, 0xf7, 0x2d, 0x76, 0xc1, 0x32, 0x4b, 0x14, 0x64, 0x66, 0x1b, 0x53, 0xbb, 0x8e, 0xa6, 0x55, 0xe3, 0x7d, 0x43, 0x80, 0xe9, 0x7b, 0x2, 0xae, 0xc9, 0xba, 0x44, 0x3, 0x18, 0xe, 0xb6, 0xa, 0x66, 0xd8, 0x6f, 0x45, 0x15, 0xc5, 0x52, 0x45, 0x3c};
    unsigned char msg[] = {
        0x44,
        0x5f,
        0xc,
        0x7f,
        0xcd,
        0x9b,
        0x4f,
        0x31,
        0xb8,
        0xee,
        0xa8,
        0x5b,
        0xd5,
        0xb7,
        0x8c,
        0x48,
        0x23,
        0x60,
        0x9c,
        0x85,
        0xa0,
        0xd3,
        0x54,
        0xbd,
        0x45,
        0x84,
        0x69,
        0x31,
        0x2f,
        0x90,
        0x77,
        0xe4,
    };

    unsigned char res[33];

    CT_sig_to_pubkey(res, msg, sig);

    for (int i = 0; i < 33; i++)
    {
        printf("%02x, ", res[i]);
    }
}
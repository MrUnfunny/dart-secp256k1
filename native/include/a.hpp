extern "C"
{
    void ecdh(unsigned char *secretKey, unsigned char *pubKey, unsigned char *sharedSecret);
}
extern "C"
{
    void CT_sig_to_pubkey(unsigned char *resPubKey, unsigned char *msgHash, unsigned char *signature);
}
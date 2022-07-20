#include"openssl/evp.h"
#include"_OpenSSl_sm3.h"
#include<iostream>
using namespace std;

int sm3_hash(const unsigned char* message, size_t len, unsigned char* hash, unsigned int* hash_len)
{
    EVP_MD_CTX* md_ctx;
    const EVP_MD* md;

    md = EVP_sm3();
    md_ctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(md_ctx, md, NULL);
    EVP_DigestUpdate(md_ctx, message, len);
    EVP_DigestFinal_ex(md_ctx, hash, hash_len);
    EVP_MD_CTX_free(md_ctx);
    return 0;
}

int main()
{
    unsigned char input[256] = "abc";
    int ilen = 3;
    unsigned char output[32];
    int i;
    cout << "Demo:" << endl << endl;

    sm3_hash(input, ilen, output,(unsigned int*)32);
    cout << "Hash of " << input << ":" << endl;

    for (i = 0; i < 32; i++)
    {
        printf("%02x", output[i]);
        if (((i + 1) % 4) == 0) printf(" ");
    }

    cout << endl << endl;
    return 0;
}
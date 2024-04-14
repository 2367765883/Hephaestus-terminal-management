#include "RC4Function.h"
void rc4Encrypt(unsigned char* plaintext, int plaintextLength, unsigned char* key, int keyLength)
{
    unsigned char S[256];
    unsigned char T[256];
    int i, j = 0, k;
    unsigned char temp;

    for (i = 0; i < 256; i++) {
        S[i] = i;
        T[i] = key[i % keyLength];
    }

    for (i = 0; i < 256; i++) {
        j = (j + S[i] + T[i]) % 256;
        temp = S[i];
        S[i] = S[j];
        S[j] = temp;
    }

    i = 0;
    j = 0;
    for (int m = 0; m < plaintextLength; m++) {
        i = (i + 1) % 256;
        j = (j + S[i]) % 256;
        temp = S[i];
        S[i] = S[j];
        S[j] = temp;
        k = S[(S[i] + S[j]) % 256];
        plaintext[m] ^= k;
    }
}

void rc4Decrypt(unsigned char* ciphertext, int ciphertextLength, unsigned char* key, int keyLength)
{
    rc4Encrypt(ciphertext, ciphertextLength, key, keyLength); 
}


/*

    unsigned char plaintext[] = "Hello, world!";
    unsigned char key[] = "secret";
    int plaintextLength = strlen((char*)plaintext);
    int keyLength = strlen((char*)key);

    // 加密
    rc4Encrypt(plaintext, plaintextLength, key, keyLength);

    // 解密
    rc4Decrypt(plaintext, plaintextLength, key, keyLength);

    // 输出结果
    std::cout << "Plaintext: " << plaintext << std::endl;

*/
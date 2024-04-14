#pragma once
#include "headers.h"


void rc4Encrypt(unsigned char* plaintext, int plaintextLength, unsigned char* key, int keyLength);
void rc4Decrypt(unsigned char* ciphertext, int ciphertextLength, unsigned char* key, int keyLength);

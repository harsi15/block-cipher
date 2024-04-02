//fscrypt.h
#ifndef FSCRYPT_H
#define FSCRYPT_H

#include <openssl/blowfish.h>

# define BLOCKSIZE 8 // Block size for Blowfish

void *fs_encrypt(void *plaintext, int bufsize, char *keystr, int *resultlen);
void *fs_decrypt(void *ciphertext, int bufsize, char *keystr, int *resultlen);

#endif // FSCRYPT_H
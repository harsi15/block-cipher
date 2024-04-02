#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <cstring>
#include <cstdlib>
#include "fscrypt.h"

// Encryption function
void *fs_encrypt(void *plaintext, int bufsize, char *keystr, int *resultlen) {

	BF_KEY *key = (BF_KEY *)malloc(sizeof(BF_KEY));                                 // Allocating the memory for the key
	unsigned char iv[] = "\x00\x00\x00\x00\x00\x00\x00\x00";                        // Initializing the iv with 0's
	unsigned char *cipherText, *previousCipherTextBlock, *intermediateCipher;
    int padding, encryptionSize, flagSize;
    
    // Initializing the flagsize and encryptionSize to bufsize
    flagSize = bufsize;
    encryptionSize = bufsize;

    // Checking if the bufsize obtained is a mulitple of BLOCKSIZE = 8
    if (bufsize % BLOCKSIZE != 0) {
        encryptionSize = bufsize + (bufsize % BLOCKSIZE);
    }

    // Allocate memory for result buffer and temporary units
    unsigned char *plainText = (unsigned char *) plaintext;                                 // Creating an instance of plaintext
    cipherText = (unsigned char *) malloc(sizeof(unsigned char) * encryptionSize);          // Resulting cipherText
    previousCipherTextBlock = (unsigned char *) malloc(sizeof(unsigned char) * BLOCKSIZE);  // Modified plaintext 
    intermediateCipher = (unsigned char *) malloc(sizeof(unsigned char) * BLOCKSIZE);       // Intermediate cipherText for respective plain text block

    // Initializing value of resultant cipherText 
    for (int i = 0; i < encryptionSize; i++) {
        cipherText[i] = '0';
    }

    // Initializing the previousCipherTextBlock to have the value of the initialization vector and intermediateCipher text to 0
    for (int i = 0; i < BLOCKSIZE; i++) {
        previousCipherTextBlock[i] = iv[i];
        intermediateCipher[i] = '0';
    }

    // Calling the Blowfish Set Key function to set the encryption key
    BF_set_key(key, strlen(keystr), (const unsigned char *) keystr);

    // Checking our flagSize if it is greater than the BLOCKSIZE=8, then we need to modify the index to copy the contents from plaintext to previousCipherTextBlock
    while (flagSize >= BLOCKSIZE) {

        // Performing the XOR of plaintext with previous cipher text value
        for (int i = 0; i < BLOCKSIZE; i++) {
            previousCipherTextBlock[i] ^= (unsigned char) (plainText[bufsize - flagSize + i]);      
        }

        // Calling the Blowfish ECB encrypt function to encrypt the message using Modified plaintext to get the resultant encrypted message which will be stored in intermediateCipherText
        BF_ecb_encrypt(previousCipherTextBlock, intermediateCipher, key, BF_ENCRYPT);

        // Updating the previousCipherTextBlock to have the value of the previous ciphertext value and the value of the intermediateCipher text will be stored in cipherText
        for (int i = 0; i < BLOCKSIZE; i++) {
            previousCipherTextBlock[i] = intermediateCipher[i];
            cipherText[bufsize - flagSize + i] = intermediateCipher[i];
        }

        flagSize = flagSize - BLOCKSIZE;                        // Updating the flagSize
    }

    // Calculating the padding size value and the resultlen
    padding = BLOCKSIZE - flagSize;
    *resultlen = bufsize - flagSize;


    while (flagSize > 0) {
        // Performing the XOR of plaintext with previous cipher text value and if flagSize == 0 then we will XOR padding
        for (int i = 0; i < BLOCKSIZE; i++) {
            if (flagSize != 0) {
                previousCipherTextBlock[i] ^= (unsigned char) plainText[bufsize - flagSize];
                flagSize--;
            } else {
                previousCipherTextBlock[i] ^= (unsigned char) (padding & 0xFF);
            }
        }

        // Calling the Blowfish ECB encrypt function to encrypt the message using Modified plaintext to get the resultant encrypted message which will be stored in intermediateCipherText
        BF_ecb_encrypt(previousCipherTextBlock, intermediateCipher, key, BF_ENCRYPT);


        // Updating the value of the cipherText according to the previous obtained intermediate Cipher Values
        for (int i = 0; i < BLOCKSIZE; i++) {
            cipherText[bufsize - BLOCKSIZE + padding + i] = intermediateCipher[i];
        }

        *resultlen += BLOCKSIZE;
    }

    return cipherText;
}



// Decrypt Function
void *fs_decrypt(void *ciphertext, int bufsize, char *keystr, int *resultlen) {

    BF_KEY *key= (BF_KEY *)malloc(sizeof(BF_KEY));                              // Allocating the memory for the key
    unsigned char iv[] = "\x00\x00\x00\x00\x00\x00\x00\x00";                    // Initializing the iv with 0's
    unsigned char *plainText = (unsigned char *)malloc(bufsize);                // Resulting plainText
    unsigned char *previousCipherTextBlock = iv;                                 // Initializing previousCipherTextBlock with iv
    int blocks, padding;
    blocks = bufsize / BLOCKSIZE;                                               // Calculating the number of blocks


    // Calling the Blowfish Set Key function to set decryption key
    BF_set_key(key, strlen(keystr), (unsigned char *)keystr);

    // Decrypting each block 
    for (int i = 0; i < blocks; i++) {
        
        // Initializing the values of the block
        unsigned char modifiedCipherText[BLOCKSIZE];                                    // To store modified value of the cipher
        unsigned char *cipherTextBlock = (unsigned char *)ciphertext + i * BLOCKSIZE;   // Contains the cipher text of each block
        unsigned char *intermediatePlainText = plainText + i * BLOCKSIZE;               // To store intermediatePlainText result

        // Calling the Blowfish ECB encrypt function to decrypt the message using cipherTextBlock to get the resultant decrypted message which will be stored in modifiedCipherText
        BF_ecb_encrypt(cipherTextBlock, modifiedCipherText, key, BF_DECRYPT);

        // Performing XOR of the modifiedCipherText obtained after Encryption with the previousCipherTextBlock to obtain the intermediatePlainText value
        for (int j = 0; j < BLOCKSIZE; j++) {
            intermediatePlainText[j] = modifiedCipherText[j] ^ previousCipherTextBlock[j];  
        }

        // Using the memcpy function to save the cipherTextBlock as the previousCipherTextBlock for the next iteration
        memcpy(previousCipherTextBlock, cipherTextBlock, BLOCKSIZE);
    }


    // Removing the padding from the plaintext if there are any padding present
    padding = plainText[bufsize - 1];
    *resultlen = bufsize - padding;

    return plainText;
}

#include <stdio.h>
#include <gcrypt.h>

//function definition to print errors to stderr for gcrypt functions
void printGcryErr(char *function, gcry_error_t err);

//function defintion for function that checks if a file is a file and that it exists
int checkIfFile(char *filename);

//function definition to setup cipher includeing the bitsize and mode of the cipher setting of the iv and the key *iv and key must be generated before hand cannot pass in null
int setupCipher(gcry_cipher_hd_t *h, char *mode, int bitsize, void *iv, void *key);

//generate key for use to provide to setupCipher
void *genKey(char *password, void *salt);

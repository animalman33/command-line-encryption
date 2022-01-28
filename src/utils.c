#include "utils.h"
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
// function to print out any errors created by libgcrypt
void printGcryErr(char *function, gcry_error_t err) {
  fprintf(stderr, "%s has error %s\n", function, gcry_strerror(err));
}

// checks that a file is a file and that it exists and provides a proper error
// message
int checkIfFile(char *filename) {
  struct stat sb;
  if (stat(filename, &sb) == -1) {
    fprintf(stderr, "Failed to check if file is a file or directory\n");
    return -1;
  }
  // checks if file exists
  if (access(filename, F_OK) != 0) {
    fprintf(stderr, "file does not exist\n");
    return -1;
  }
  // checks to make sure file is file
  if ((sb.st_mode & S_IFMT) != S_IFREG) {
    fprintf(stderr, "File is not a file\n");
    return -1;
  }
  return 0;
}
// does most of the heavy lifting to setup the cipher handle
int setupCipher(gcry_cipher_hd_t *hd, char *mode, int bitsize, void *iv,
                void *key) {
  int algo;
  // determine the bit size that will be used
  switch (bitsize) {
  case 256:
    algo = GCRY_CIPHER_AES256;
    break;
  case 192:
    algo = GCRY_CIPHER_AES192;
    break;
  case 128:
    algo = GCRY_CIPHER_AES;
    break;
  default:
    fprintf(stderr, "Unrecognized bit size must be either 128, 192, 256\n");
    return -1;
  }
  // list of currently supported mode of opertation
  char *supMode[] = {"GCM"};
  // complementary list of mode to above
  int modeType[] = {GCRY_CIPHER_MODE_GCM};
  // mode int that will be used to determine if mode of operation
  int modeNum = -1;
  // compares mode of operation to mode variable and sets the modeNum variable
  // to correct value
  for (int i = 0; i < 1; i++) {
    if (!strcmp(supMode[i], mode)) {
      modeNum = modeType[i];
      break;
    }
  }
  // checks to make sure that the provided mode exists
  if (modeNum == -1) {
    fprintf(stderr, "Unknown mode please provide a proper mode eg. GCM\n");
    exit(EXIT_FAILURE);
  }
  // opens the cipher up for operation
  gcry_error_t err = gcry_cipher_open(hd, algo, modeNum, 0);
  if (err) {
    printGcryErr("gcry_cipher_open", err);
    exit(EXIT_FAILURE);
  }
  // sets the key that will be used for encryption
  err = gcry_cipher_setkey(*hd, key, 32);
  if (err) {
    printGcryErr("gcry_cipher_setkey", err);
    exit(EXIT_FAILURE);
  }
  // sets the iv that will be used for encryption
  err = gcry_cipher_setiv(*hd, iv, 32);
  if (err) {
    printGcryErr("gcry_cipher_setiv", err);
    exit(EXIT_FAILURE);
  }
  return 0;
}
// generates they key that will later be used for encryption
void *genKey(char *password, void *salt) {
  void *key = malloc(32);
  if (key == NULL) {
    perror("unable to allocate memory for key");
    exit(EXIT_FAILURE);
  }
  // derive key from given password and salt using PBKDF2 and SHA256
  gcry_kdf_derive(password, strlen(password), GCRY_KDF_PBKDF2, GCRY_MD_SHA256,
                  salt, 32, 10000, 32, key);
  return key;
}

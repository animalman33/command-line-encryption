#include "utils.h"
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

void printGcryErr(char *function, gcry_error_t err) {
  fprintf(stderr, "%s has error %s\n", function, gcry_strerror(err));
}

//checks that a file is a file and that it exists and provides a proper error message
int checkIfFile(char *filename) {
  struct stat sb;
  if(stat(filename, &sb) == -1) {
    fprintf(stderr, "Failed to check if file is a file or directory\n");
    return -1;
  }
  //checks if file exists
  if(access(filename, F_OK) != 0) {
    fprintf(stderr, "file does not exist\n");
    return -1;
  }
  //checks to make sure file is file
  if((sb.st_mode & S_IFMT) != S_IFREG) {
    fprintf(stderr, "File is not a file\n");
    return -1;
  }
  return 0;
}

int setupCipher(gcry_cipher_hd_t *hd, char *mode, int bitsize, void *iv, void *key) {
  int algo;
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

  char *supMode[] = { "GCM" };
  int modeType[] = { GCRY_CIPHER_MODE_GCM };
  int modeNum = -1;
  for(int i = 0; i < 1; i++) {
    if(!strcmp(supMode[i], mode)) {
      modeNum = modeType[i];
      break;
    }
  }
  if(modeNum == -1) {
    fprintf(stderr, "Unknown mode please provide a proper mode eg. GCM\n");
    return -1;
  }
  gcry_error_t err = gcry_cipher_open(hd, algo, modeNum, 0);
  if(err) {
    printGcryErr("gcry_cipher_open", err);
  }
  err = gcry_cipher_setkey(*hd, key, 32);
  if(err) {
    printGcryErr("gcry_cipher_setkey", err);
    return -1;
  }
  err = gcry_cipher_setiv(*hd, iv, 32);
  if(err) {
    printGcryErr("gcry_cipher_setiv", err);
  }
  return 0;
}

void *genKey(char *password, void *salt) {
  void *key = malloc(32);
  if(key == NULL) {
    return NULL;
  }
  gcry_kdf_derive(password, strlen(password), GCRY_KDF_PBKDF2, GCRY_MD_SHA256, salt, 32, 10000, 32, key);
  return key;
}

#include <stdio.h>
#include <sys/types.h>
#include <unistd.h>
#include <sys/stat.h>
#include <gcrypt.h>
#include "encfile.h"


//checks that a file is a file and that it exists and provides a proper error message
static int checkIfFile(char *filename) {
  struct stat sb;
  if(stat(filename, &sb) == -1) {
    fprintf(stderr, "Failed to check if file is a file or directory");
    return 0;
  }
  //checks if file exists
  if(!(sb.st_mode & F_OK)) {
    fprintf(stderr, "file does not exist");
    return -1;
  }
  //checks to make sure file is file
  if((sb.st_mode & S_IFMT) != S_IFREG) {
    fprintf(stderr, "File is not a file");
    return -1;
  }
}

static int checkIfExists(char *filename) {
  struct stat sb;
  stat(filename, &sb);
  if(!sb.st_mode & F_OK) {
    return 0;
  }
  return 1;
}

static int setupCipher(gcry_cipher_hd_t *h, char *mode, int bitsize);
static void *genKey(char *password);

int encrypt(char *filename, char *mode, char *password, char *outfile, int bitsize) {
  //checks to make sure filename is not null and provides error message
  if(filename == NULL) {
    fprintf(stderr, "File Does not exist");
    return -1;
  }
  //checks that filename provided is actually a file and that it exists
  if(!checkIfFile(filename)) {
    return -1;
  }
  if(password == NULL) {
    password = getpass("Password to use for encryption: ");
  }
  if(!*password) {
    fprintf(stderr, "Empty password is invalid");
    return -1;
  }
  if(checkIfExists(outfile)) {
    fprintf(stderr, "Outfile exist cannont continue");
    return -1;
  }
  gcry_cipher_hd_t *hd = malloc(sizeof(gcry_cipher_hd_t));
  if (setupCipher(hd, mode, bitsize)) {
    return -1;
  }
  FILE *fd;
  if((fd = fopen(filename, "r")) == NULL) {
    fprintf(stderr, "file failed to open");
    return -1;
  }
  void *key = genKey(password);
  if(key == NULL) {
    fprintf(stderr, "could not generate key");
    return -1;
  }
  gcry_cipher_setkey(*hd, key, 32);
  void *iv = gcry_random_bytes(32, GCRY_STRONG_RANDOM);
  gcry_cipher_setiv(*hd, iv, 32);
  return 0;
}


static int setupCipher(gcry_cipher_hd_t *h, char *mode, int bitsize) {
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
      fprintf(stderr, "Unrecognized bit size must be either 128, 192, 256");
      return -1;
  }

  char *supMode[] = { "GCM" };
  int modeType[] = { GCRY_CIPHER_MODE_GCM };
  int modeNum;
  for(int i = 0; i < 1; i++) {
    if(strcmp(supMode[i], mode)) {
      modeNum = modeType[i];
      break;
    }
  }
  gcry_cipher_open(h, algo, modeNum, 0);
  return 0;
}

static void *genKey(char *password) {
  void *salt = gcry_random_bytes_secure(32, GCRY_STRONG_RANDOM);
  void *key = malloc(32);
  if(key == NULL) {
    return NULL;
  }
  gcry_kdf_derive(password, strlen(password), GCRY_KDF_SCRYPT, GCRY_MD_SHA256, salt, 32, 1<<14, 32, key);
  return key;
}

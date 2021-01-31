#include <stdio.h>
#include <sys/types.h>
#include <unistd.h>
#include <sys/stat.h>
#include <gcrypt.h>
#include "encfile.h"

#define READSIZE 1<<10

static void printGcryErr(char *function, gcry_error_t err) {
  fprintf(stderr, "%s has error %s\n", function, gcry_strerror(err));
}


//checks that a file is a file and that it exists and provides a proper error message
static int checkIfFile(char *filename) {
  struct stat sb;
  if(stat(filename, &sb) == -1) {
    fprintf(stderr, "Failed to check if file is a file or directory\n");
    return -1;
  }
  //checks if file exists
  puts(filename);
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

/*static int checkIfExists(char *filename) {
  struct stat sb;
  stat(filename, &sb);
  if(!sb.st_mode & F_OK) {
    return 0;
  }
  return 1;
  }*/

static int setupCipher(gcry_cipher_hd_t *h, char *mode, int bitsize);
static void *genKey(char *password, FILE *fdOut);

int encrypt(char *filename, char *mode, char *password, char *outfile, int bitsize) {
  //checks to make sure filename is not null and provides error message
  if(filename == NULL) {
    fprintf(stderr, "Filename is NULL please provide a filename for encryption\n");
    return -1;
  }
  //checks that filename provided is actually a file and that it exists
  if(checkIfFile(filename)) {
    return -1;
  }
  //gets password for encryption
  if(password == NULL) {
    password = getpass("Password to use for encryption: ");
  }
  //checks to make sure password is not empty
  if(!*password) {
    fprintf(stderr, "Empty password is invalid\n");
    return -1;
  }
  if(access(outfile, F_OK) == 0) {
    fprintf(stderr, "Outfile exist cannont continue\n");
    return -1;
  }
  gcry_cipher_hd_t *hd = malloc(sizeof(gcry_cipher_hd_t));
  if(hd == NULL) {
    fprintf(stderr, "Unable to allocate memory for hd\n");
  }
  if (setupCipher(hd, mode, bitsize)) {
    return -1;
  }
  FILE *fdIn;
  FILE *fdOut;
  if((fdIn = fopen(filename, "r")) == NULL) {
    fprintf(stderr, "input file failed to open\n");
    return -1;
  }
  if((fdOut = fopen(outfile, "w")) == NULL) {
    fprintf(stderr, "output file failed to open\n");
    return -1;
  }
  void *key = genKey(password, fdOut);
  if(key == NULL) {
    fprintf(stderr, "could not generate key\n");
    return -1;
  }
  gcry_error_t err;
  err = gcry_cipher_setkey(*hd, key, 32);
  if(err) {
    printGcryErr("gcry_cipher_setkey", err);
    return -1;
  }
  void *iv = gcry_random_bytes(32, GCRY_STRONG_RANDOM);
  fwrite(fdOut, 1, 32, fdOut);
  err = gcry_cipher_setiv(*hd, iv, 32);
  if(err) {
    printGcryErr("gcry_random_bytes", err);
  }
  char *loc = malloc(READSIZE);
  size_t readAmnt = 0;
  while(!feof(fdIn) && (readAmnt = fread(loc, 1, READSIZE, fdIn)) > 0) {
    err = gcry_cipher_encrypt(*hd, loc, readAmnt, NULL, 0);
    if(err) {
      printGcryErr("gcry_cipher_encrypt", err);
    }
    fwrite(loc, 1, READSIZE, fdOut);
  }
  return 0;
}


static int setupCipher(gcry_cipher_hd_t *h, char *mode, int bitsize) {
  int algo;
  printf("%d\n", bitsize);
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
  gcry_error_t err = gcry_cipher_open(h, algo, modeNum, 0);
  if(err) {
    printGcryErr("gcry_cipher_open", err);
  }

  return 0;
}

static void *genKey(char *password, FILE *fdOut) {
  void *salt = gcry_random_bytes_secure(32, GCRY_STRONG_RANDOM);
  void *key = malloc(32);
  fwrite(salt, 1, 32, fdOut);
  if(key == NULL) {
    return NULL;
  }
  puts("here");
  gcry_kdf_derive(password, strlen(password), GCRY_KDF_PBKDF2, GCRY_MD_SHA256, salt, 32, 10000, 32, key);
  puts("here");
  return key;
}

#include <stdio.h>
#include <sys/types.h>
#include <unistd.h>
#include <sys/stat.h>
#include <gcrypt.h>
#include "encfile.h"
#include "utils.h"


int encrypt(char *filename, char *mode, char *password, char *outfile, int bitsize, int readsize) {
  //checks to make sure filename is not null and provides error message
  if(filename == NULL || outfile == NULL) {
    fprintf(stderr, "input or output file is NULL please provide a filename for encryption\n");
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
    fprintf(stderr, "Outfile exist cannot continue\n");
    return -1;
  }
  gcry_cipher_hd_t *hd = malloc(sizeof(gcry_cipher_hd_t));
  if(hd == NULL) {
    fprintf(stderr, "Unable to allocate memory for hd\n");
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
  void *iv = gcry_random_bytes(32, GCRY_STRONG_RANDOM);
  void *salt = gcry_random_bytes_secure(32, GCRY_STRONG_RANDOM);
  fwrite(iv, 1, 32, fdOut);
  fwrite(salt, 1, 32, fdOut);
  void *key = genKey(password, salt);
  if(key == NULL) {
    fprintf(stderr, "could not generate key\n");
    return -1;
  }
  if (setupCipher(hd, mode, bitsize, iv, key)) {
    return -1;
  }
  gcry_error_t err;
  char *loc = malloc(readsize);
  size_t readAmnt = 0;
  fseek(fdIn, 0, SEEK_END);
  size_t filesize = ftell(fdIn);
  rewind(fdIn);
  while(!feof(fdIn) && filesize % readsize == 0 && (readAmnt = fread(loc, 1, readsize, fdIn)) > 0) {
    filesize -= readsize;
    err = gcry_cipher_encrypt(*hd, loc, readAmnt, NULL, 0);
    if(err) {
      printGcryErr("gcry_cipher_encrypt", err);
    }
    if(fwrite(loc, 1, readsize, fdOut) == 0) {
      return -1;
    }
  }
  if(filesize != 0) {
    if(feof(fdIn)) {
      fprintf(stderr, "EOF reached but file size is larger\n");
    }
    if((readAmnt = fread(loc, 1, filesize, fdIn)) > 0) {
      err = gcry_cipher_encrypt(*hd, loc, filesize, NULL, 0);
      if(err) {
	printGcryErr("gcry_cipher_encrypt", err);
      }
      if(fwrite(loc, 1, filesize, fdOut) == 0) {
	return -1;
      }
    }
  }
  return 0;
}

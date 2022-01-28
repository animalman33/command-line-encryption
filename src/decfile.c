#include "decfile.h"
#include "utils.h"
#include <gcrypt.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
// storage of error number
extern int errno;

int decrypt(char *infile, char *mode, char *password, char *outfile,
            int bitsize, size_t readsize) {
  int inLine = 0;
  FILE *fdIn;
  FILE *fdOut;
  // opens up the encrypted file for decryption
  if ((fdIn = fopen(infile, "r+")) == NULL) {
    perror("unable to open input file");
    exit(EXIT_FAILURE);
  }
  // opens up the output file
  if (outfile != NULL && !strcmp(outfile, infile)) {
    if ((fdOut = fopen(outfile, "w")) == NULL) {
      perror("unable to open output file");
      exit(EXIT_FAILURE);
    }
  } else {
    int len = strlen(infile);
    outfile = malloc((len + 5));
    strcpy(outfile, infile);
    strcpy(outfile + len, ".dec");
    inLine = 1;
    if ((fdOut = fopen(outfile, "w")) == NULL) {
      perror("could not create/open output file");
      exit(EXIT_FAILURE);
    }
  }
  // gets the password
  if (password == NULL) {
    password = getpass("Password to use for decryption: ");
  }
  // checks to make sure password is valid (not empty)
  if (!*password) {
    fprintf(stderr, "Empty password is invalid\n");
    exit(EXIT_FAILURE);
  }

  void *iv = malloc(32);
  void *salt = malloc(32);
  // gets the iv value and checks to make sure that the files is valid for
  // decryption
  if (fread(iv, 1, 32, fdIn) != 32) {
    fprintf(stderr, "invalid or corrupted file\n");
    exit(EXIT_FAILURE);
  }
  if (feof(fdIn)) {
    fprintf(stderr, "invalid or corrputed file\n");
    exit(EXIT_FAILURE);
  }
  // gets the salt value and does another check to make sure files is valid
  if (fread(salt, 1, 32, fdIn) != 32) {
    fprintf(stderr, "invalid or corrupted file\n");
    exit(EXIT_FAILURE);
  }
  if (feof(fdIn)) {
    fprintf(stderr, "invalid or corrupted file\n");
    exit(EXIT_FAILURE);
  }
  // generates the key from the password and salt
  void *key = genKey(password, salt);
  // allocates cipher handle
  gcry_cipher_hd_t *hd = malloc(sizeof(gcry_cipher_hd_t));
  // sets up cipher handle for decryption
  setupCipher(hd, mode, bitsize, iv, key);
  char *buf = malloc(readsize);
  // keeps track of the amount read and ready for decryption
  size_t readAmnt = 0;
  gcry_error_t err;
  // location to store tag saved at the end of the file
  void *tag = calloc(1, 16);
  // loops until entire file is read and decrypts then writes out
  while (!feof(fdIn) && (readAmnt = fread(buf, 1, readsize, fdIn)) > 0) {
    // checks if this is the last chunck of data being read and copys the tag to
    // the tag variable
    if (feof(fdIn)) {
      readAmnt -= 16;
      memcpy(tag, buf + readAmnt, 16);
      if (readAmnt == 0) {
        break;
      }
    }
    // preforms decryption operation and checks for errors
    err = gcry_cipher_decrypt(*hd, buf, readAmnt, NULL, 0);
    if (err) {
      printGcryErr("gcry_cipher_encrypt", err);
    }
    if (fwrite(buf, 1, readAmnt, fdOut) == 0) {
      fprintf(stderr, "could not write to output file\n");
      exit(EXIT_FAILURE);
    }
  }

  // checks to make sure the file has not been tampered with
  puts("authenticating");
  err = gcry_cipher_checktag(*hd, tag, readAmnt);
  puts((char *)tag);
  if (err) {
    printGcryErr("gcry_cipher_checktag", err);
  }
  puts("Done");
  fclose(fdIn);
  fclose(fdOut);
  if (inLine) {
    remove(infile);
    rename(outfile, infile);
  }
  return 0;
}

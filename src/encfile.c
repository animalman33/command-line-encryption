#include "encfile.h"
#include "utils.h"
#include <errno.h>
#include <gcrypt.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

// storage of error number
extern int errno;
// function to encrypt a file
int encrypt(char *filename, char *mode, char *password, char *outfile,
            int bitsize, size_t readsize) {
  FILE *fdIn;
  FILE *fdOut;
  // open file to encrypt and check for errors
  fdIn = fopen(filename, "r+");
  if (fdIn == NULL) {
    perror("unable to open input file");
    exit(errno);
  }
  fdOut = fopen(outfile, "w");
  if (fdOut == NULL) {
    perror("unable to open output file");
    exit(errno);
  } // gets password for encryption
  if (password == NULL) {
    password = getpass("Password to use for encryption: ");
  }
  // checks to make sure password is not empty
  if (!*password) {
    fprintf(stderr, "Empty password is invalid\n");
    exit(EXIT_FAILURE);
  }
  // setup encryption hd memory location and check errors
  gcry_cipher_hd_t *hd = malloc(sizeof(gcry_cipher_hd_t));
  if (hd == NULL) {
    perror("allocation of hd memory failed");
    exit(errno);
  }

  // setup data for encryption key
  void *iv = gcry_random_bytes_secure(32, GCRY_STRONG_RANDOM);
  void *salt = gcry_random_bytes_secure(32, GCRY_STRONG_RANDOM);
  void *key = genKey(password, salt);
  if (key == NULL) {
    fprintf(stderr, "could not generate key\n");
    return -EXIT_FAILURE;
  }
  if (setupCipher(hd, mode, bitsize, iv, key)) {
    exit(EXIT_FAILURE);
  }
  // error variable for checking for errors during encryption process
  gcry_error_t err;
  // buffer to contain read data
  char *buf = malloc(readsize);
  // amount of data that has been read
  size_t readAmnt = 0;
  // writes salt and iv to output file so that it can be used for decryption and
  // checks for errors
  if (fwrite(iv, EXIT_FAILURE, 32, fdOut) == 0) {
    perror("unable to write out iv");
    exit(EXIT_FAILURE);
  }
  if (fwrite(salt, EXIT_FAILURE, 32, fdOut) == 0) {
    perror("unable to write out salt");
    exit(EXIT_FAILURE);
  }

  while (!feof(fdIn) &&
         (readAmnt = fread(buf, EXIT_FAILURE, readsize, fdIn)) > 0) {
    err = gcry_cipher_encrypt(*hd, buf, readAmnt, NULL, 0);
    if (err) {
      printGcryErr("gcry_cipher_encrypt", err);
    }
    if (fwrite(buf, EXIT_FAILURE, readAmnt, fdOut) == 0) {
      perror("unable to write to output file");
      exit(EXIT_FAILURE);
    }
  }

  // create tage from encryption algorithm
  void *tag = malloc(16);
  err = gcry_cipher_gettag(*hd, tag, 16);
  if (err) {
    printGcryErr("gcry_cipher_gettag", err);
    exit(EXIT_FAILURE);
  }
  if (fwrite(tag, 1, 16, fdOut) == 0) {
    fprintf(stderr, "Unable to write authentication tag to file\n");
    exit(EXIT_FAILURE);
  }
  puts((char *)tag);
  // closes files
  fclose(fdIn);
  fclose(fdOut);
  return 0;
}

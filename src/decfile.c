#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <gcrypt.h>
#include "decfile.h"
#include "utils.h"

int decrypt(char *filename, char *mode, char *password, char *outfile, int bitsize, size_t readsize) {
  int inLine = 0;
  if(filename == NULL) {
    fprintf(stderr, "input file is NULL please provide a filename for decryption\n");
    return -1;
  }
  if(checkIfFile(filename)) {
    return -1;
  }
  if(outfile != NULL) {
    if(access(outfile, F_OK) == 0) {
      fprintf(stderr, "outfile exists cannot continue\n");
      return -1;
    }
  }
  if(password == NULL) {
    password = getpass("Password to use for decryption: ");
  }

  if(!*password) {
    fprintf(stderr, "Empty password is invalid\n");
    return -1;
  }
  FILE *fdIn;
  FILE *fdOut;

  if((fdIn = fopen(filename, "r+")) == NULL) {
    fprintf(stderr, "input file failed to open\n");
    return -1;
  }
  if(outfile != NULL) {
    if((fdOut = fopen(outfile, "w")) == NULL) {
      fprintf(stderr, "output file failed to open\n");
      return -1;
    }
  }
  else {
    int len = strlen(filename);
    outfile = malloc((len+5));
    strcpy(outfile, filename);
    strcpy(outfile+len, ".dec");
    inLine = 1;
    if((fdOut = fopen(outfile, "w")) == NULL) {
      fprintf(stderr, "unable to create temp file\n");
      return -1;
    }
  }
  void *iv = malloc(32);
  void *salt = malloc(32);
  if(fread(iv, 1, 32, fdIn) != 32) {
    fprintf(stderr, "invalid or corrupted file\n");
    return -1;
  }
  if(feof(fdIn)) {
    fprintf(stderr, "invalid or corrputed file, \n");
    return -1;
  }
  if(fread(salt, 1, 32, fdIn) != 32) {
    fprintf(stderr, "invalid or corrupted file, unable to read salt\n");
    return -1;
  }
  if(feof(fdIn)) {
    fprintf(stderr, "invalid or corrupted file, nothing to decrypt\n");
    return -1;
  }
  void *key = genKey(password, salt);
  gcry_cipher_hd_t *hd = malloc(sizeof(gcry_cipher_hd_t));
  setupCipher(hd, mode, bitsize, iv, key);
  char *loc = malloc(readsize);
  size_t readAmnt = 0;
  gcry_error_t err;
  fseek(fdIn, 0, SEEK_END);
  size_t filesize = ftell(fdIn)-80;
  rewind(fdIn);
  fseek(fdIn, 64, SEEK_CUR);
  while(!feof(fdIn) && filesize > readsize && (readAmnt = fread(loc, 1, readsize, fdIn)) > 0) {
    filesize -= readsize;
    err = gcry_cipher_decrypt(*hd, loc, readAmnt, NULL, 0);
    if(err) {
      printGcryErr("gcry_cipher_encrypt", err);
    }
    if(fwrite(loc, 1, readsize, fdOut) == 0) {
      fprintf(stderr, "could not write to output file\n");
      return -1;
    }
  }
  
  if(filesize > 0) {
    if(feof(fdIn)) {
      fprintf(stderr, "end of file reached while amount left to read file is > 0\n");
      return -1;
    }
    if((readsize = fread(loc, 1, filesize, fdIn)) > 0) {
      err = gcry_cipher_decrypt(*hd, loc, filesize, NULL, 0);
      if(err) {
	printGcryErr("gcry_cipher_encrypt", err);
      }
      if(fwrite(loc, 1, filesize, fdOut) == 0) {
	fprintf(stderr, "could not write to output file\n");
	return -1;
      }
    }
  }
  void *tag = malloc(16);
  if(!feof(fdIn) && (readAmnt = fread(loc,1,16,fdIn)) > 0) {
    puts("authenticating");
    err = gcry_cipher_checktag(*hd, tag, readAmnt);
    if(err) {
      printGcryErr("gcry_cipher_checktag", err);
    }
    puts("Done");
  }
  else {
    fprintf(stderr, "Unable to authenticate file may have been tampered with\n");
  }
  fclose(fdIn);
  fclose(fdOut);
  if(inLine) {
    remove(filename);
    rename(outfile, filename);
  }
  return 0;
}

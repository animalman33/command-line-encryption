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

int encrypt(char *filename, char *mode, char *password, char *outfile) {
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
  char *supMode = "AES-GCM-256";
  if(!strcasecmp(mode, supMode)) {
    fprintf(stderr, "unsupported mode");
    return -1;
  }
  FILE *fd;
  if((fd = fopen(filename, "r")) == NULL) {
    fprintf(stderr, "file failed to open");
    return -1;
  }
  return 0;
}

#include <stdio.h>
#include <argp.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <string.h>
#include <gcrypt.h>

//program documentation
static char doc[] = "basic command line encryption/decryption tool";

static char args_doc[] = "ARGS1 ARGS2";

//understood arguments
static struct argp_option options[] = {
				       {"encrypt", 'e', 0, OPTION_ARG_OPTIONAL, "tells the program to encrypt file input defaults to this if unspecified"},
				       {"decrypt", 'd', 0, OPTION_ARG_OPTIONAL, "tells the program to decrypt input file to output file"},
				       {"output", 'o', "FILE", 0, "tells program what file to output to will create file if necessary"},
				       {"infile", 'i', "FILE", 0, "tells the program what file to take input from and encrypt/decrypt"},
				       {"type", 't', 0, OPTION_ARG_OPTIONAL, "determines the type of encryption to use default=AES-GCM-256"},
				       {"password", 'p', 0, OPTION_ARG_OPTIONAL, "password for aes key do not use unless do large amount of files highly insecure the password will be asked for when necessary"},
				       { 0 }
};

//used by main to parse args
struct arguments {
  char *args[2]; /*ARGS1 ARGS2*/
  int encrypt;
  char *outfile;
  char *infile;
  char *password;
  char *type;
};


//function to be used by arg_parse to set indivisial arguments
static error_t parse_opt(int key, char *arg, struct argp_state *state) {

  struct arguments *arguments = state->input;

  switch (key) {
    case 'e':
      arguments->encrypt = 1;
      break;
    case 'd':
      arguments->encrypt = 0;
      break;
    case 'o':
      arguments->outfile = arg;
      break;
    case 'i':
      arguments->infile = arg;
      break;
    case 'p':
      arguments->password = arg;
      break;
    case 't':
      arguments->type = arg;
      break;
    case ARGP_KEY_ARG:
      if(state->arg_num > 2) {
	argp_usage(state);
      }
      arguments->args[state->arg_num] = arg;
      break;
    case ARGP_KEY_END:
      break;
    default:
      return ARGP_ERR_UNKNOWN;
  }
  return 0;

}
//structure necessary for operation of arg_parse based on documentation
static struct argp argp = { options, parse_opt, args_doc, doc };

int encrypt(char *filename, char *mode, char *password, char *outfile);

int main(int argc, char **argv) {
  struct arguments arguments;
  //sets default arguments for operation
  arguments.encrypt = 1;
  arguments.outfile = "-";
  arguments.infile = NULL;
  arguments.password = NULL;
  arguments.type = "AES-GCM-256";
  //parses args
  argp_parse(&argp, argc, argv, 0, 0, &arguments);
  //calls proper function for mode of program
  if(arguments.encrypt) {
    return encrypt(arguments.infile, arguments.type, arguments.password, arguments.outfile);
  }
  else {
    puts("decrypt");
  }
  return 0;
}


//checks that a file is a file and that it exists and provides a proper error message
int checkIfFile(char *filename) {
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

int checkIfExists(char *filename) {
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

#include <stdio.h>
#include <argp.h>
#include "encfile.h"
#include "decfile.h"

//program documentation
static char doc[] = "basic command line encryption/decryption tool";

static char args_doc[] = "input output";

//understood arguments
static struct argp_option options[] = {
				       {"encrypt", 'e', 0, OPTION_ARG_OPTIONAL, "tells the program to encrypt file input defaults to this if unspecified"},
				       {"decrypt", 'd', 0, OPTION_ARG_OPTIONAL, "tells the program to decrypt input file to output file"},
				       {"output", 'o', "FILE", 0, "tells program what file to output to will create file if necessary"},
				       {"infile", 'i', "FILE", 0, "tells the program what file to take input from and encrypt/decrypt"},
				       {"mode", 'm', 0, OPTION_ARG_OPTIONAL, "determines the mode of encryption to use default=GCM"},
				       {"password", 'p', 0, OPTION_ARG_OPTIONAL, "password for aes key do not use unless do large amount of files highly insecure the password will be asked for when necessary"},
				       {"bitsize", 'b', 0, OPTION_ARG_OPTIONAL, "determines bitsize to use for key default 256 bits"},
				       {"readsize", 'r', 0, OPTION_ARG_OPTIONAL, "determines the amount of data read from file per operation"},
				       { 0 }
};

//used by main to parse args
struct arguments {
  int encrypt;
  char *outfile;
  char *infile;
  char *password;
  char *mode;
  int bitsize;
  int readsize;
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
    case 'm':
      arguments->mode = arg;
      break;
    case 'b':
      arguments->bitsize = atoi(arg);
      break;
    case 'r':
      arguments->readsize = atoi(arg);
      break;
    case ARGP_KEY_ARG:
      if(state->arg_num > 2) {
	argp_usage(state);
      }
      if(state->arg_num == 0) {
	arguments->infile = arg;
      }
      else if(state->arg_num == 1) {
	arguments->outfile = arg;
      }
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



int main(int argc, char **argv) {
  struct arguments arguments;
  //sets default arguments for operation
  arguments.encrypt = 1;
  arguments.outfile = NULL;
  arguments.infile = NULL;
  arguments.password = NULL;
  arguments.mode = "GCM";
  arguments.bitsize = 256;
  arguments.readsize = 1024;
  //parses args
  argp_parse(&argp, argc, argv, 0, 0, &arguments);
  //calls proper function for mode of program
  if(arguments.outfile == NULL) {
    fprintf(stderr, "output file not specified\n");
  }
  if(arguments.bitsize != 256 && arguments.bitsize != 128 && arguments.bitsize != 192) {
    fprintf(stderr, "bitsize is incorrect value must be either 256, 192 or 128\n");
    return -1;
  }
  if(arguments.encrypt) {
    return encrypt(arguments.infile, arguments.mode, arguments.password, arguments.outfile, arguments.bitsize, arguments.readsize);
  }
  else {
    return decrypt(arguments.infile, arguments.mode, arguments.password, arguments.outfile, arguments.bitsize, arguments.readsize);
  }
  return 0;
}

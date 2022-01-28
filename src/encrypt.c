#include "decfile.h"
#include "encfile.h"
#include <argp.h>
#include <stdio.h>

// program documentation
static char doc[] = "basic command line encryption/decryption tool";

static char args_doc[] = "input";

// understood arguments
static struct argp_option options[] = {
    {"encrypt", 'e', 0, OPTION_ARG_OPTIONAL,
     "tells the program to encrypt file input defaults to this if unspecified"},
    {"decrypt", 'd', 0, OPTION_ARG_OPTIONAL,
     "tells the program to decrypt input file to output file"},
    {"output", 'o', "FILE", 0,
     "tells program what file to output to will create file if necessary"},
    {"mode", 'm', "MODE", 0,
     "determines the mode of encryption to use default=GCM"},
    {"password", 'p', "PASSWORD", 0,
     "password for aes key do not use unless do large amount of files highly "
     "insecure the password will be asked for when necessary"},
    {"bitsize", 'b', "BITSIZE", 0,
     "determines bitsize to use for key default 256 bits"},
    {"readsize", 'r', "READSIZE", 0,
     "determines the amount of data read from file per operation in kilobytes"},
    {0}};

// used by main to parse args
struct arguments {
  char *outfile;
  char *infile;
  char *password;
  char *mode;
  int bitsize;
  int readsize;
  int encrypt;
};

// function to be used by arg_parse to set indivisial arguments
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
    arguments->readsize = atoi(arg) * 1024;
    break;
  case ARGP_KEY_ARG:
    if (state->arg_num >= 1) {
      argp_usage(state);
    } else if (state->arg_num == 0) {
      arguments->infile = arg;
    }
    break;
  case ARGP_KEY_END:
    break;
  default:
    return ARGP_ERR_UNKNOWN;
  }
  return 0;
}
// structure necessary for operation of arg_parse based on documentation
static struct argp argp = {options, parse_opt, args_doc, doc};

int main(int argc, char **argv) {
  struct arguments arguments;
  // sets default arguments for operation
  arguments.encrypt = 1;
  arguments.outfile = NULL;
  arguments.infile = NULL;
  arguments.password = NULL;
  arguments.mode = "GCM";
  arguments.bitsize = 256;
  arguments.readsize = 1024;
  // parses args
  argp_parse(&argp, argc, argv, 0, 0, &arguments);
  // determines if bitsize is acceptable or not
  int bitsize = arguments.bitsize;
  if (bitsize != 256 && bitsize != 128 && bitsize != 192) {
    fprintf(stderr,
            "bitsize is incorrect value must be either 256, 192 or 128\n");
    return -1;
  }
  // calls proper function for correct name
  if (arguments.encrypt) {
    return encrypt(arguments.infile, arguments.mode, arguments.password,
                   arguments.outfile, bitsize, arguments.readsize);
  } else {
    return decrypt(arguments.infile, arguments.mode, arguments.password,
                   arguments.outfile, bitsize, arguments.readsize);
  }
  return 0;
}

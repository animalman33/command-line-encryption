#include <stdio.h>
#include <argp.h>
#include "encfile.c"
#include "decfile.c"

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

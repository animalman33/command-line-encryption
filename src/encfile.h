#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <gcrypt.h>


int encrypt(char *filename, char *mode, char *password, char *outfile);

#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <gcrypt.h>

//driver function definition for encrypting a file
int encrypt(char *filename, char *mode, char *password, char *outfile, int bitsize, size_t readsize);

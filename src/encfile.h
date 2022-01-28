#include <gcrypt.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

// driver function definition for encrypting a file
int encrypt(char *filename, char *mode, char *password, char *outfile,
            int bitsize, size_t readsize);

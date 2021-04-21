#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <gcrypt.h>

int decrypt(char *filename, char *mode, char *password, char *outfile, int bitsize, size_t readsize);

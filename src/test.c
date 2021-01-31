#include <stdlib.h>
#include <stdio.h>
//#include <gcrypt.h>

int main() {
  /*  char *text = malloc(32);
  strcpy(text, "testing testing");
  gcry_cipher_hd_t hd = malloc(sizeof(gcry_cipher_hd_t));
  gcry_error_t err = gcry_cipher_open(&hd, GCRY_CIPHER_AES256, GCRY_CIPHER_MODE_GCM, 0);
  if(err) {
    fprintf(stderr, "gcry_cipher_open err %s\n", gcry_strerror(err));
  }
  char *key = gcry_random_bytes(32, GCRY_STRONG_RANDOM);
  err = gcry_cipher_setkey(hd, key, 32);
   if(err) {
    fprintf(stderr, "gcry_cipher_setkey err %s\n", gcry_strerror(err));
  }
  void *iv = gcry_random_bytes(32, GCRY_STRONG_RANDOM);
  gcry_cipher_setiv(hd, iv, 32);
  err = gcry_cipher_encrypt(hd,text, 33, NULL, 0);
  if(err) {
    fprintf(stderr, "gcry_cipher_encrypt err %s", gcry_strerror(err));
  }
  puts(text);
  gcry_cipher_close(hd);

  hd = malloc(sizeof(gcry_cipher_hd_t));
  gcry_cipher_open(&hd, GCRY_CIPHER_AES256, GCRY_CIPHER_MODE_GCM, 0);
  gcry_cipher_setkey(hd, key, 32);
  gcry_cipher_setiv(hd, iv, 32);
  err = gcry_cipher_decrypt(hd, text, 33, NULL, 0);
  if(err) {
    fprintf(stderr, "gcry_cipher_decrypt err %s", gcry_strerror(err));
  }
  puts(text);
  */
  FILE *fd = fopen("test.txt", "r");
  char *loc = malloc(7);
  fread(loc, 7, 7, fd);
  printf("%s", loc);
  return 0;
}

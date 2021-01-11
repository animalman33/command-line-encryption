
CC := gcc

CFLAGS := -ggdb -Wall -Werror

GCRYPTFLAGS := $(shell libgcrypt-config --cflags)

GCRYPTLIBS := $(shell libgcrypt-config --libs)

encrypt: src/encrypt.o
	$(CC) -o encrypt $^ $(GCRYPTLIBS) $(GCRYPTFLAGS)

%.o: %.c
	$(CC) -o $@ -c $< $(CFLAGS)


clean:
	rm -rf src/*.o encrypt src/*~

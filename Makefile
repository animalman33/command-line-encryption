
CC := gcc

CFLAGS := -ggdb -Wall -Werror

GCRYPTFLAGS := $(shell libgcrypt-config --cflags)

GCRYPTLIBS := $(shell libgcrypt-config --libs)
#creates encrypt from source code
encrypt: src/encrypt.o src/encfile.o src/decfile.o src/utils.o
	$(CC) -o encrypt $^ $(GCRYPTLIBS) $(GCRYPTFLAGS)
#makes all .o files from .c files
%.o: %.c
	$(CC) -o $@ -c $< $(CFLAGS)

#cleans all unnecessary files mostly used to test compilation and clean all files up
clean:
	rm -rf src/*.o encrypt src/*~

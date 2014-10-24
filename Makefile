CC=gcc
CFLAGS= -std=c99 -lm -I.
DEPS = aes.h
OBJ = aes.o gentable.o

%.o: %.c $(DEPS)
	$(CC) -c -o $@ $< $(CFLAGS)

gentable: $(OBJ)
	gcc -o $@ $^ $(CFLAGS)

run24: gentable
	./gentable 24 20

run28: gentable
	./gentable 28 26

run24c: crack
	./crack 24 20 0xeb94f00c506705017ce61273667a0952

run28c: crack
	./crack 28 26 0xa2cf3f9d2e3000c5addea2d613acfda8

run20: gentable
	./gentable 20 19

run20c: crack
	./crack 20 19 0xae60abdcb19d5f962a891044129d56d4

clean:
	rm gentable

all:
	gcc -c aes.c
	gcc -g -O3 -Wall -c crack.c -std=c99 -lm -I.
	gcc -g -O3 -Wall -o crack crack.o aes.o -std=c99 -lm -I.
	gcc -g -O3 -Wall -c gentable.c -std=c99 -lm -I.
	gcc -g -O3 -Wall -o gentable gentable.o aes.o -std=c99 -lm -I.

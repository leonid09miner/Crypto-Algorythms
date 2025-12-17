
all: rsa2048

clean: 
	@rm -rf *.o rsa2048

rsa2048: oaep.o main2048.o sha256.o rsa2048.o
	g++ oaep.o main2048.o sha256.o rsa2048.o -lgmp -lgmpxx -o rsa2048
rsa2048.o: rsa2048.cpp
	g++ -g -c rsa2048.cpp
main2048.o: main2048.cpp
	g++ -g -c main2048.cpp
oaep.o: oaep.hpp oaep.cpp 
	g++ -g -c oaep.cpp
sha256.o: sha256.h sha256.c
	g++ -g -c sha256.c


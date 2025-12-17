#ifndef MURMUR2_H
#define MURMUR2_H

#define MURMURHASH2_BLOCK_SIZE 4

#include <stddef.h>

typedef unsigned char BYTE;             // 8-bit byte
typedef unsigned int  WORD;             // 32-bit word, change to "long" for 16-bit machines

void murmurHash2(const BYTE* data, size_t len, BYTE* hash);

#endif // MURMUR2_H

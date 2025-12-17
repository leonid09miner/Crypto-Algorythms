#include <memory.h>
#include "murmur2.h"

void murmurHash2(const BYTE* data, size_t len, BYTE* hash)
{
	// initialization
	const WORD m = 0x5bd1e995;
	const WORD seed = 0;
	const int r = 24;

	WORD h = (seed ^ len) & 0xffffffff;

	WORD k = 0;

	// transformation
	while (len >= 4)
	{
		k = data[0];
		k |= data[1] << 8;
		k |= data[2] << 16;
		k |= data[3] << 24;

		k *= m;
		k ^= k >> r;
		k *= m;

		h *= m;
		h ^= k;

		data += 4;
		len -= 4;
	}

	// final transformations
	switch (len)
	{
	case 3:
		h ^= data[2] << 16;
	case 2:
		h ^= data[1] << 8;
	case 1:
		h ^= data[0];
		h *= m;
	};

	h ^= h >> 13;
	h *= m;
	h ^= h >> 15;

	for (int i = 0; i < MURMURHASH2_BLOCK_SIZE; i++)
	{
		hash[i] = (h >> (24 - 8 * i)) & 0x000000ff;
	}
}
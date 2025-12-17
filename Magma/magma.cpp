#include "magma.hpp"

// f function for processing the A_i and the K_i f(A_i, K_i) 
unsigned int fFunc(unsigned int blockA, unsigned int k)
{
	//           0x0  0x1  0x2  0x3  0x4  0x5  0x6  0x7  0x8  0x9  0xA  0xB  0xC  0xD  0xE  0xF
	int s1[] = { 0x9, 0x6, 0x3, 0x2, 0x8, 0xB, 0x1, 0x7, 0xA, 0x4, 0xE, 0xF, 0xC, 0x0, 0xD, 0x5 };
	int s2[] = { 0x3, 0x7, 0xE, 0x9, 0x8, 0xA, 0xF, 0x0, 0x5, 0x2, 0x6, 0xC, 0xB, 0x4, 0xD, 0x1 };
	int s3[] = { 0xE, 0x4, 0x6, 0x2, 0xB, 0x3, 0xD, 0x8, 0xC, 0xF, 0x5, 0xA, 0x0, 0x7, 0x1, 0x9 };
	int s4[] = { 0xE, 0x7, 0xA, 0xC, 0xD, 0x1, 0x3, 0x9, 0x0, 0x2, 0xB, 0x4, 0xF, 0x8, 0x5, 0x6 };
	int s5[] = { 0xB, 0x5, 0x1, 0x9, 0x8, 0xD, 0xF, 0x0, 0xE, 0x4, 0x2, 0x3, 0xC, 0x7, 0xA, 0x6 };
	int s6[] = { 0x3, 0xA, 0xD, 0xC, 0x1, 0x2, 0x0, 0xB, 0x7, 0x5, 0x9, 0x4, 0x8, 0xF, 0xE, 0x6 };
	int s7[] = { 0x1, 0xD, 0x2, 0x9, 0x7, 0xA, 0x6, 0x0, 0x8, 0xC, 0x4, 0x5, 0xF, 0x3, 0xB, 0xE };
	int s8[] = { 0xB, 0xA, 0xF, 0x5, 0x0, 0xC, 0xE, 0x8, 0x6, 0x2, 0x3, 0x9, 0x1, 0x7, 0xD, 0x4 };

	int* blocks[] = { s1, s2, s3, s4, s5, s6, s7, s8 };
	unsigned int res;

	// res = (Ai + ki) % 0x100000000;
	if (blockA >= 0xffffffff - k + 1)
		res = blockA - 0xffffffff - k + 1;
	else
		res = blockA + k;

	// cout << hex << res << endl;
	
	for (int i = 0; i < 8; i++)
	{
		unsigned int fragment = (res & (0xf << (4 * (7 - i))));
		res -= fragment;
		fragment >>= 4 * (7 - i);
		// cout << hex << fragment;
		fragment = blocks[i][fragment] << (4 * (7 - i));
		res += fragment;
	}
	// cout << hex << res << endl;

	res = (res << 11) | (res >> (32 - 11));

	// cout << hex << res << endl;
	return res;
}

// encrypt one block
void blockEnc(unsigned int* ptrA, unsigned int* ptrB, unsigned int* key)
{
	unsigned int tmp;
	unsigned int blockA = *ptrA;
	unsigned int blockB = *ptrB;
	for (int i = 0; i < 24; i++)
	{
		tmp = blockA;
		blockA = fFunc(blockA, key[i % 8]);
		blockA = blockB ^ blockA;
		blockB = tmp;
	}

	for (int i = 7; i >= 1; i--)
	{
		tmp = blockA;
		blockA = fFunc(blockA, key[i]);
		blockA = blockB ^ blockA;
		blockB = tmp;
	}

	tmp = blockA;
	blockA = fFunc(blockA, key[0]);
	blockA = blockB ^ blockA;
	*ptrB = blockA;
	*ptrA = tmp;
}

// decrypt one block
void blockDec(unsigned int* ptrA, unsigned int* ptrB, unsigned int* key)
{
	unsigned int tmp;
	unsigned int blockA = *ptrA;
	unsigned int blockB = *ptrB;
	for (int i = 0; i < 8; i++)
	{
		tmp = blockA;
		blockA = fFunc(blockA, key[i]);
		blockA = blockB ^ blockA;
		blockB = tmp;
	}

	for (int i = 23; i >= 1; i--)
	{
		tmp = blockA;
		blockA = fFunc(blockA, key[i % 8]);
		blockA = blockB ^ blockA;
		blockB = tmp;
	}

	tmp = blockA;
	blockA = fFunc(blockA, key[0]);
	blockA = blockB ^ blockA;
	*ptrB = blockA;
	*ptrA = tmp;
}

// simple replacement encryption
unsigned char* simpEncrypt(unsigned char* data, int len, unsigned int* key)
{
	unsigned char* enc = new unsigned char[len + 1];

	for (int i = 0; i < len; i += 8)
	{
		unsigned int blockA = 0;
		for (int j = i; j < i + 4; j++)
			blockA += data[j] << ((j % 4) * 8);

		unsigned int blockB = 0;
		for (int j = i + 4; j < i + 8; j++)
			blockB += data[j] << ((j % 4) * 8);
		
		blockEnc(&blockA, &blockB, key);
	
		for (int j = i; j < i + 4; j++)
			enc[j] = (blockA & (0xff << ((j % 4) * 8))) >> ((j % 4) * 8);
	
		for (int j = i + 4; j < i + 8; j++)
			enc[j] = (blockB & (0xff << ((j % 4) * 8))) >> ((j % 4) * 8);
	}

	enc[len] = '\0';
	return enc;
}

// simple replacement decryption
unsigned char* simpDecrypt(unsigned char* data, int len, unsigned int* key)
{
	unsigned char* enc = new unsigned char[len + 1];
	
	for (int i = 0; i < len; i += 8)
	{
		unsigned int blockA = 0;
		for (int j = i; j < i + 4; j++)
			blockA += data[j] << ((j % 4) * 8);
	
		unsigned int blockB = 0;
		for (int j = i + 4; j < i + 8; j++)
			blockB += data[j] << ((j % 4) * 8);
		// cout << hex << blockA << " " << blockB << endl;	
		blockDec(&blockA, &blockB, key);
	
		for (int j = i; j < i + 4; j++)
			enc[j] = (blockA & (0xff << ((j % 4) * 8))) >> ((j % 4) * 8);
	
		for (int j = i + 4; j < i + 8; j++)
			enc[j] = (blockB & (0xff << ((j % 4) * 8))) >> ((j % 4) * 8);
	}

	enc[len] = '\0';
	return enc;
}

// gamma encryption with feedback encrypt
unsigned char* gammaEncFB(unsigned char* data, int len, unsigned char* pack, unsigned int* key)
{
	unsigned char* encr = new unsigned char[len + 1];

	unsigned char reg[8];
	for (int i = 0; i < 8; i++)
		reg[i] = pack[i];
	
	for (int i = 0; i < len; i += 8)
	{
		unsigned int blockA = 0;
		for (int j = 0; j < 4; j++)
			blockA += reg[j] << ((j % 4) * 8);

		unsigned int blockB = 0;
		for (int j = 4; j < 8; j++)
			blockB += reg[j] << ((j % 4) * 8);

		blockEnc(&blockA, &blockB, key);

		for (int j = 0; j < 4; j++)
		{
			unsigned char fragment = (blockA & (0xff << ((j % 4) * 8))) >> ((j % 4) * 8);
			if (i + j < len)
			{
				fragment = data[i + j] ^ fragment;
				encr[i + j] = fragment;
				reg[j] = fragment;
			}
		}

		for (int j = 4; j < 8; j++)
		{
			unsigned char fragment = (blockB & (0xff << ((j % 4) * 8))) >> ((j % 4) * 8);
			if (i + j < len)
			{
				fragment = data[i + j] ^ fragment;
				encr[i + j] = fragment;
				reg[j] = fragment;
			}
		}
	}

	encr[len] = '\0';
	return encr;
}

// gamma encryption with feedback decrypt
unsigned char* gammaDecFB(unsigned char* data, int len, unsigned char* pack, unsigned int* key)
{
	unsigned char* decr = new unsigned char[len + 1];

	unsigned char reg[8];
	for (int i = 0; i < 8; i++)
		reg[i] = pack[i];
	
	for (int i = 0; i < len; i += 8)
	{
		unsigned int blockA = 0;
		for (int j = 0; j < 4; j++)
			blockA += reg[j] << ((j % 4) * 8);

		unsigned int blockB = 0;
		for (int j = 4; j < 8; j++)
			blockB += reg[j] << ((j % 4) * 8);

		blockEnc(&blockA, &blockB, key);

		for (int j = 0; j < 4; j++)
		{
			unsigned char fragment = (blockA & (0xff << ((j % 4) * 8))) >> ((j % 4) * 8);
			if (i + j < len)
			{
				fragment = data[i + j] ^ fragment;
				decr[i + j] = fragment;
				reg[j] = data[i + j];
			}
		}

		for (int j = 4; j < 8; j++)
		{
			unsigned char fragment = (blockB & (0xff << ((j % 4) * 8))) >> ((j % 4) * 8);
			if (i + j < len)
			{
				fragment = data[i + j] ^ fragment;
				decr[i + j] = fragment;
				reg[j] = data[i + j];
			}
		}
	}

	decr[len] = '\0';
	return decr;
}
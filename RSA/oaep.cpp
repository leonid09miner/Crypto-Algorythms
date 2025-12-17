#include "oaep.hpp"
#include "sha256.h"
#include <sys/random.h>

// unsigned integer to octet string
unsigned char* I20SP (unsigned int x, int len)
{
	unsigned char* res = new unsigned char[len];

	for (int i = 0; i < len; i++)
	{
		res[3 - i] = x & 0xff;
		x >>= 8;
	}
	return res;
}

// mask generating function
unsigned char* mgf1(unsigned char* seed, int seedLen, int maskLen) // сделать функцию генерации маски
{
	unsigned char* mask = new unsigned char[maskLen];

	unsigned char* seed_ctr = new unsigned char[seedLen + 4];
	for (int i = 0; i < seedLen; i++)
		seed_ctr[i] = seed[i];
	
	int iter;
	if (maskLen % SHA256_BLOCK_SIZE == 0)
		iter = maskLen / SHA256_BLOCK_SIZE;
	else 
		iter = maskLen / SHA256_BLOCK_SIZE + 1;

	for (unsigned int i = 0; i < iter; i++)
	{
		unsigned char* ctrStr = I20SP(i, 4);
		
		BYTE hash[SHA256_BLOCK_SIZE];
		for (int j = 0; j < 4; j++)
			seed_ctr[seedLen + j] = ctrStr[j];
		sha256((const BYTE*)seed_ctr, seedLen + 4, hash);

		for (int j = 0; j < SHA256_BLOCK_SIZE; j++)
		{
			if (i * SHA256_BLOCK_SIZE + j < maskLen)
				mask[i * SHA256_BLOCK_SIZE + j] = hash[j];
			else 
				break;
		}
		delete[] ctrStr;
	}
	delete[] seed_ctr;

	return mask;
}

// padding encoding
unsigned char* paddingEncode(unsigned char* mes, int mesLen, unsigned char* label, int lbLen) 
{
	unsigned char* encMes = new unsigned char[129];

	BYTE hash[SHA256_BLOCK_SIZE];
	sha256((const BYTE*)label, lbLen, hash);

	for (int i = 0; i < 32; i++)
		encMes[33 + i] = hash[i];

	for (int i = 0; i < 30; i++)
		encMes[65 + i] = 0x00;

	encMes[95] = 0x01;

	for (int i = 0; i < 32; i++)
	{
		if (i < mesLen)
			encMes[96 + i] = mes[i];
		else if (i == mesLen)
			encMes[96 + i] = 0x01;
		else 
			encMes[96 + i] = 0x00;
	}

	unsigned char seed[32];
	size_t buflen = 32;
	ssize_t len = 0;

	len = getrandom(seed, buflen, 0);
	if (len < 32)
	{
		delete[] encMes;
		return 0;
	}
	
	unsigned char* mask = mgf1(seed, 32, 95);
	for (int i = 0; i < 95; i++)
		encMes[33 + i] = encMes[33 + i] ^ mask[i];
	delete[] mask;

	mask = mgf1(encMes + 33, 95, 32);
	for (int i = 0; i < 32; i++)
	{
		seed[i] = seed[i] ^ mask[i];
		encMes[1 + i] = seed[i];
	}
	delete[] mask;

	encMes[0] = 0x00;
	encMes[128] = '\0';
	
	return encMes;
}

// padding decoding
unsigned char* paddingDecode(unsigned char* block, unsigned char* label, int lbLen)
{
	if (block[0] != 0x00)
		return NULL;

	unsigned char seed[32];
	unsigned char* dataBlock = new unsigned char[95];
	unsigned char* mask;

	mask = mgf1(block + 33, 95, 32);
	for (int i = 0; i < 32; i++)
		seed[i] = block[1 + i] ^ mask[i];
	delete[] mask;

	mask = mgf1(seed, 32, 95);
	for (int i = 0; i < 95; i++)
		dataBlock[i] = block[33 + i] ^ mask[i];
	delete[] mask;

	BYTE hash[SHA256_BLOCK_SIZE];
	sha256((const BYTE*)label, lbLen, hash);

	for (int i = 0; i < SHA256_BLOCK_SIZE; i++)
	{
		if (dataBlock[i] != hash[i])
		{
			delete[] dataBlock;
			return NULL;
		}
	}

	for (int i = 0; i < 30; i++)
	{
		if (dataBlock[i + 32] != 0x00)
		{
			delete[] dataBlock;
			return NULL;
		}
	}

	if (dataBlock[62] != 0x01)
	{
		delete[] dataBlock;
		return NULL;
	}

	unsigned char* endPtr = &dataBlock[94];
	int dataLen = 32;
	while (*endPtr != 0x01)
	{
		endPtr--;
		dataLen--;
	}

	*endPtr = '\0';
	dataLen--;

	unsigned char* data = new unsigned char[dataLen + 1];
	for (int i = 0; i < dataLen; i++)
		data[i] = dataBlock[63 + i];
	data[dataLen] = '\0';
	
	delete[] dataBlock;
	return data;
}
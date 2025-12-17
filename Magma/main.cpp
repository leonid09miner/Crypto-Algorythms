#include <iostream>
#include <iomanip>
#include "sha256.h"
#include "magma.hpp"

using namespace std;

// unsigned char* simpEncrypt(unsigned char* data, int len, unsigned int* key);
// unsigned char* simpDecrypt(unsigned char* data, int len, unsigned int* key);
// unsigned char* gammaEncFB(unsigned char* data, int len, unsigned char* pack, unsigned int* key);
// unsigned char* gammaDecFB(unsigned char* data, int len, unsigned char* pack, unsigned int* key);

int main()
{
	unsigned char data[] = "Good day, sir. This text is just a demonstration, sir. T";
	unsigned char data1[] = "Good day, sir. This text is just a demonstration, sir. Thus, if you do not see it twice then something's wrong.";
	int len = 0;
	while (data[len])
		len++;

	const BYTE keyText[] = "This text will be processed via sha256 into a key";
	int textLen = 0;
	while(keyText[textLen])
		textLen++;

	BYTE hash[SHA256_BLOCK_SIZE];
	sha256(keyText, textLen, hash);

	// 0x70ec5368 0xb4db176b 0x59dde91f 0xafc6fe80 0xca70e93e 0x545f330 0x8ce3ad099 0xc2c7d098
	cout << "Key: ";
	unsigned int k[8];

	for (int i = 0; i < 8; i++)
	{
		k[i] = hash[i * 4] << 24 | hash[i * 4 + 1] << 16 | hash[i * 4 + 2] << 8 | hash[i * 4 + 3];
		cout << hex << setw(8) << setfill('0') << k[i] << " ";
	}
	cout << endl << endl;

	cout << "---- Simple encryption ----" << endl;

	cout << "Data: " << data << endl;
	cout << "Length: " << dec << len << endl;
	
	for (int i = 0; i < len; i++)
		cout << hex << setw(2) << setfill('0') << ((int)data[i] & 0xff);
	cout << endl;

	unsigned char* encr = simpEncrypt(data, len, k);

	for (int i = 0; i < len; i++)
		cout << hex << setw(2) << setfill('0') << ((int)encr[i] & 0xff);
	cout << endl;
	
	unsigned char* decr = simpDecrypt(encr, len, k);
	cout << decr << endl << endl;

	delete[] encr;
	delete[] decr;
	
	len = 0;
	while (data1[len])
		len++;
	
	cout << "---- Encryption with gamma and feedback ----" << endl;
	cout << "Data: " << data1 << endl;
	cout << "Length: " << dec << len << endl;

	for (int i = 0; i < len; i++)
		cout << hex << setw(2) << setfill('0') << ((int)data1[i] & 0xff);
	cout << endl;

	unsigned char syncPack[] = { 0xaf, 0x9d, 0x3a, 0x78, 0xe6, 0xa2, 0x10, 0xde };

	encr = gammaEncFB(data1, len, syncPack, k);

	for (int i = 0; i < len; i++)
		cout << hex << setw(2) << setfill('0') << ((int)encr[i] & 0xff);
	cout << endl;

	decr = gammaDecFB(encr, len, syncPack, k);
	cout << decr << endl;
	
	delete[] encr;
	delete[] decr;
	return 0;
}



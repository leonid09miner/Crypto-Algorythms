#include <iostream>
#include <iomanip>
#include "aes.hpp"

using namespace std;


unsigned char* encryptBlock(unsigned char* data, unsigned char* key);
unsigned char* decryptBlock(unsigned char* data, unsigned char* key);
unsigned char* testBlock(unsigned char* data);
unsigned char gfmul(unsigned char a, unsigned char b);

unsigned int gfmul2(unsigned int x, unsigned int m, unsigned int p)
{
	unsigned int res = x << 1;
	if (res >= m)
		res ^= p;

	return res;
}

int main() // test
{
	unsigned char data[] = "Here we go again";
	cout << data << endl;

	cout << "Data:      ";
	for (int i = 0; i < 16; i++)
		cout << hex << setw(2) << setfill('0') << (int)data[i];
	cout << endl;

	unsigned char key[32] = {0xa7, 0x2b, 0xf1, 0x4a, 0xf8, 0x70, 0x23, 0x1d, 0xdd, 0xc6, 0x27, 0xb8, 0x01, 0x34, 0x28, 0x69, 0xff, 0x7b, 0xdf, 0xda, 0x24, 0x97, 0x01, 0x4d, 0xfe, 0x23, 0x4e, 0xbc, 0x7c, 0x20, 0xcd, 0x3a};
	
	unsigned char* encr = encryptBlock(data, key);
	
	cout << "Encrypted: "; 
	for (int i = 0; i < 16; i++)
		cout << hex << setw(2) << setfill('0') << (int)encr[i];
	cout << endl;

	unsigned char* decr = decryptBlock(encr, key);
	
	cout << "Decrypted: " << decr << endl << endl;

	delete[] encr;
	delete[] decr;

	unsigned char data1[] = "Hier we go again";
	cout << data1 << endl;

	cout << "Data:      ";
	for (int i = 0; i < 16; i++)
		cout << hex << setw(2) << setfill('0') << (int)data1[i];
	cout << endl;

	encr = encryptBlock(data1, key);
	
	cout << "Encrypted: "; 
	for (int i = 0; i < 16; i++)
		cout << hex << setw(2) << setfill('0') << (int)encr[i];
	cout << endl;

	decr = decryptBlock(encr, key);
	
	cout << "Decrypted: " << decr << endl;

	delete[] encr;
	delete[] decr;

	/*
	unsigned int x = 0x08; // experiments with calculating S-box values

	unsigned char inv = 1;
	while (gfmul(x, inv) != 1)
		inv++;

	cout << hex << (int)inv << endl;
	cout << (int)gfmul(inv, x) << endl;

	unsigned char s = inv;
	s ^= (inv << 1) | (inv >> 7);
	s ^= (inv << 2) | (inv >> 6);
	s ^= (inv << 3) | (inv >> 5);
	s ^= (inv << 4) | (inv >> 4);
	s ^= 0x63;
	
	cout << (int)s << endl;	

	unsigned char sRev = 0;
	sRev ^= (s << 1) | (s >> 7);
	sRev ^= (s << 3) | (s >> 5);
	sRev ^= (s << 6) | (s >> 2);
	sRev ^= 0x05;

	inv = 1;
	while (gfmul(sRev, inv) != 1)
		inv++;

	cout << (int)inv << endl; // */

	return 0;
}
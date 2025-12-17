#include <cmath>
#include <iostream>
#include <string>
#include <random>
#include <iomanip>
#include <ctime>
#include <sys/random.h>
#include <gmpxx.h>
#include <chrono>
#include "oaep.hpp" // padding
#include "rsa2048.hpp" // rsa2048 functions

using namespace std;
typedef unsigned long long int longInt;

/* --- RSA with 56-bit module and 28-bit prime numbers --- */
longInt pows(longInt a, longInt b, longInt m);
longInt* generateKeys();

void benchmark(const string& name, int iterations, void (*func)());
void test_operation();

int main()
{
	//*
	unsigned char text[] = "This is a demonstration text";
	int textLen = 0;
	while(text[textLen])
		textLen++;
	
	unsigned char label[] = "This is a test label";
	int lbLen = 0;
	while(label[lbLen])
		lbLen++;
	
	unsigned char* encoded = paddingEncode(text, textLen, label, lbLen);
	mpz_class mes = 0;

	for (int i = 0; i < 128; i++)
	{
		mpz_class tmp = encoded[i];
		mes |= tmp << ((127 - i) * 8);
	}
	delete[] encoded;
	
	mpz_class* keys = generateLargeKeys();
	mpz_class module = keys[0];
	mpz_class publicKey = keys[1];
	mpz_class privateKey = keys[2];
	delete[] keys;

	cout << "--- Encryption testing ---" << endl;

	cout << "Module: " << module.get_str(16) << endl << endl;
	cout << "Public Key: " << publicKey.get_str(16) << endl << endl;
	cout << "Private Key: " << privateKey.get_str(16) << endl << endl;

	mes = powsl(mes, privateKey, module);
	cout << "Encrypted: " << mes.get_str(16) << endl << endl;

	mes = powsl(mes, publicKey, module);
	cout << "Decrypted: " << hex << setw(256) << setfill('0') << mes << endl << endl;
	
	unsigned char decr[128];

	for (int i = 0; i < 128; i++)
	{
		unsigned int shift = (127 - i) * 8;
		mpz_class tmp = (mes & (0xff_mpz << shift)) >> shift;
		decr[i] = (unsigned char)tmp.get_ui();
	}

	unsigned char* decoded = paddingDecode(decr, label, lbLen);
	cout << "Decoded: " << decoded << endl << endl;

	delete[] decoded; // */

	/*
	mpz_class* keys = generate256Keys();
	if (!keys)
		return 1;
	cout << keys[1].get_str(16) << endl;
	cout << keys[2].get_str(16) << endl; // */

	/*
	mpz_class* keys = generate256Keys();
	mpz_class module = keys[0];
	mpz_class publicKey = keys[1];
	mpz_class privateKey = keys[2];
	delete[] keys;

	unsigned char text[] = "This is a demonstration text";
	int textLen = 0;
	while(text[textLen])
		textLen++;
	
	unsigned char label[] = "This is a test label";
	int lbLen = 0;
	while(label[lbLen])
		lbLen++;
	
	unsigned char* encoded = paddingEncode(text, textLen, label, lbLen);
	mpz_class mes = 0;

	for (int i = 0; i < 128; i++)
	{
		mpz_class tmp = encoded[i];
		mes |= tmp << ((127 - i) * 8);
	}
	delete[] encoded;

	// mpz_class enc = powsl(mes, privateKey, module);
	// mpz_class dec;

	int iterations = 1;
	string name = "RSA15360 Prime generation";
	mpz_class pr;

	using namespace chrono;

    auto start = high_resolution_clock::now();

    for (int i = 0; i < iterations; ++i) {
        pr = generate256Prime();
    }

    auto end = high_resolution_clock::now();
    auto duration = duration_cast<microseconds>(end - start).count();

    std::cout << name << ": (" << iterations << " iterations)\n";
    std::cout << "  Total time: " << duration << " μs\n";
    std::cout << "  Avg per op: " << (double)duration / iterations << " μs\n\n"; // */

    // cout << pr.get_str(16) << endl;

	// benchmark("RSA Key generation", 100, test_operation);

	return 0;
}


void test_operation() 
{
	mpz_class* keys = generateLargeKeys();
}

void benchmark(const string& name, int iterations, void (*func)()) 
{
    using namespace chrono;

    auto start = high_resolution_clock::now();

    for (int i = 0; i < iterations; ++i) {
        func();
    }

    auto end = high_resolution_clock::now();
    auto duration = duration_cast<microseconds>(end - start).count();

    std::cout << name << ": (" << iterations << " iterations)\n";
    std::cout << "  Total time: " << duration << " μs\n";
    std::cout << "  Avg per op: " << (double)duration / iterations << " μs\n\n";
}


// modulo multiplication
longInt muls(longInt a, longInt b, longInt m)
{
	if (b == 1)
		return a;
	else if (b % 2 == 0)
	{
		longInt t = muls(a, b / 2, m);
		return (t * 2) % m;
	}
	else
		return (muls(a, b - 1, m) + a) % m;
}

// modulo degree
longInt pows(longInt a, longInt b, longInt m)
{
	if (b == 0)
		return 1;
	else if (b % 2 == 0){
		longInt t = pows(a, b / 2, m);
		return muls(t, t, m) % m;
	}
	else
		return (muls(pows(a, b - 1, m), a, m)) % m;
}

// greatest common divisor via extended euclid algorithm
longInt euclGCD(longInt a, longInt b)
{
	longInt r0;
	longInt r1;
	if (a > b)
	{
		r0 = a;
		r1 = b;
	}
	else 
	{
		r0 = b;
		r1 = a;
	}
	longInt q;
	longInt tmp;

	while(r1 != 0)
	{
		q = r0 / r1;

		tmp = r1;
		r1 = r0 - r1 * q;
		r0 = tmp;
	}

	return r0;
}

// find inverse number via extended euclid algorithm
longInt findInv(longInt a, longInt m)
{
	longInt t0 = 0;
	longInt t1 = 1;

	longInt r0 = m;
	longInt r1 = a;
	
	longInt q;
	longInt tmp;

	while(r1 != 0)
	{
		q = r0 / r1;

		tmp = r1;
		r1 = r0 - r1 * q;
		r0 = tmp;

		tmp = t1;
		// t1 = t0 - t1 * q;
		t1 = (t0 - muls(t1, q, m) + m) % m;
		t0 = tmp;
	}

	return t0;
}

// Fermat check
bool ferma(longInt x)
{
	if (x == 2)
		return 1;
	random_device dev;
	mt19937_64 gen(dev());
	uniform_int_distribution<longInt> dist(2, x - 2);

	for (int i = 0; i < 100; i++)
	{
		longInt a = dist(gen);
		if (euclGCD(a, x) != 1)
			return 0;
		if (pows(a, x - 1, x) != 1)
			return 0;
	}
	return 1;
}

// generate RSA keys
longInt* generateKeys()
{
	random_device dev;
	bool pr = false;

	longInt p; // 2559013
	longInt q; // 3270287
	
	while(!pr)
	{
		p = dev() % 0x10000000;
		if (ferma(p))
			pr = true;
	}

	pr = false;
	while(!pr)
	{
		q = dev() % 0x10000000;
		long long int dif = p - q;
		if (ferma(q) && abs(dif) >= 0x4000000)
			pr = true;
	}

	longInt phi = (p - 1) * (q - 1);

	longInt publicKey;
	pr = false;
	while (!pr)
	{
		publicKey = dev() % phi;
		if (euclGCD(publicKey, phi) == 1)
			pr = true;
	}

	longInt privateKey = findInv(publicKey, phi);

	longInt* keys = new longInt[3];
	keys[0] = p * q;
	keys[1] = publicKey;
	keys[2] = privateKey;

	return keys;
}

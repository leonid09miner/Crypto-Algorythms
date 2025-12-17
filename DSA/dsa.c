#include <stdlib.h>
#include <time.h>
#include <stdio.h>
#include <limits.h>
#include "DSA.h"
#include "murmur2.h"

llint gcd(llint a, llint b)
{
	if (b == 0)
		return a;
	return gcd(b, a % b);
}

llint mul(llint a, llint b, llint m)
{
	if (b == 1)
		return a;
	if (b % 2 == 0) {
		llint t = mul(a, b / 2, m);
		return (2 * t) % m;
	}
	return (mul(a, b - 1, m) + a) % m;
}

llint pows(llint a, llint b, llint m)
{
	if (b == 0)
		return 1;
	if (b % 2 == 0) {
		llint t = pows(a, b / 2, m);
		return mul(t, t, m) % m;
	}
	return (mul(pows(a, b - 1, m), a, m)) % m;
}

int ferma(llint x)
{
	if (x == 2)
		return 1;
	srand(time(NULL) % 0xffffffff);
	for (int i = 0; i < 100; i++) {
		llint a = (rand() % (x - 2)) + 2;
		if (gcd(a, x) != 1)
			return 0;
		if (pows(a, x - 1, x) != 1)
			return 0;
	}
	return 1;
}

llint find_p(llint q, int min_mul)
{
	int f = 0;
	llint p = 0;
	for (int i = min_mul; i < INT_MAX && !f; i++)
	{
		p = q * i + 1;
		if (ferma(p))
		{
			// printf("%lld\n", p);
			f++;
		}
	}
	return p;
}

DSA_PAR cypher_init()
{
	DSA_PAR par;
	par.q = 4294967291;
	par.p = 4611687499117361471;
	par.g = 1606373120950454435;
	srand(time(NULL) & 0xffffffff);
	// printf("g^q mod p = %lld\n", pows(par.g, par.q, par.p));
	return par;
}

/*
llint generate_keys(DSA_PAR *par)
{
	srand(time(NULL) & 0xffffffff);
	secret = rand() % (par->q - 1) + 1;
	llint open = pows(par->g, secret, par->p);
	return open;
}*/

WORD calc_int_hash(const char* data, unsigned int len)
{
	char hash[MURMURHASH2_BLOCK_SIZE] = { 0 };
	murmurHash2((const BYTE*)data, len, (BYTE*)hash);
	WORD h = 0;
	for (int i = 0; i < MURMURHASH2_BLOCK_SIZE; i++)
		h |= ((int)(hash[i])) << (24 - 8 * i) & (0xff << (24 - 8 * i));
	return h;
}

llint* get_cypher(const char* data, unsigned int len, DSA_PAR* par)
{
	llint x = rand() % (par->q - 1) + 1;
	// llint x = 23675; // uncomment for debug
	llint y = pows(par->g, x, par->p);

	WORD h = calc_int_hash(data, len);

	int b = 0;
	llint* cyp = (llint*)malloc(3 * sizeof(llint));
	if (!cyp)
	{
		printf("unable to allocate free memory\n");
		return NULL;
	}
	cyp[2] = y;
	
	while(!b)
	{
		llint r;
		llint s;
		llint k = rand() % par->q;
		// llint k = 65535; // uncomment for debug

		r = pows(par->g, k, par->p) % par->q;
		if (r == 0)
			continue;

		llint k_rev = pows(k, par->q - 2, par->q);
		s = (k_rev % par->q) * ((h + x * r) % par->q) % par->q;
		if (s == 0)
			continue;

		b = 1;
		cyp[0] = r;
		cyp[1] = s;
	}

	return cyp; // 0 - r, 1 - s, 2 - open key
}

int check_cypher(const char* data, unsigned int len, llint* cyp, DSA_PAR* par)
{
	llint w = pows(cyp[1], par->q - 2, par->q);
	
	WORD h = calc_int_hash(data, len);

	llint u1 = (h % par->q) * (w % par->q) % par->q;
	llint u2 = (cyp[0] % par->q) * (w % par->q) % par->q;

	llint v1 = pows(par->g, u1, par->p);
	llint v2 = pows(cyp[2], u2, par->p);

	llint v = mul(v1, v2, par->p);

	v %= par->q;
	
	return (v == cyp[0]);
}
#ifndef DSA_H
#define DSA_H

// #include <stddef.h>

typedef unsigned long long llint;
typedef struct {
	llint q;
	llint p;
	llint g;
} DSA_PAR;
// llint secret;

int ferma(llint x);
llint pows(llint a, llint b, llint m);
DSA_PAR cypher_init();
llint* get_cypher(const char* data, unsigned int len, DSA_PAR* par);
int check_cypher(const char* data, unsigned int len, llint* cyp, DSA_PAR* par);

#endif // DSA_H
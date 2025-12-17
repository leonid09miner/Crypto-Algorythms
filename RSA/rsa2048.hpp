#ifndef RSA2048_HPP
#define RSA2048_HPP

#include <gmpxx.h>

/* --- Operations with large numbers --- */
mpz_class powsl(mpz_class a, mpz_class b, mpz_class m);
/* --- RSA key genetation with 2048-bit module and 1024-bit prime numbers --- */
mpz_class generatePrime();
mpz_class* generateLargeKeys();
/* --- RSA key genetation with 15360-bit module and 15360-bit prime numbers --- */
mpz_class generate256Prime();
mpz_class* generate256Keys();

#endif // RSA2048_HPP
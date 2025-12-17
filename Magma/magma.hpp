#ifndef MAGMA_HPP
#define MAGMA_HPP

unsigned char* simpEncrypt(unsigned char* data, int len, unsigned int* key);
unsigned char* simpDecrypt(unsigned char* data, int len, unsigned int* key);
unsigned char* gammaEncFB(unsigned char* data, int len, unsigned char* pack, unsigned int* key);
unsigned char* gammaDecFB(unsigned char* data, int len, unsigned char* pack, unsigned int* key);

#endif // MAGMA_HPP
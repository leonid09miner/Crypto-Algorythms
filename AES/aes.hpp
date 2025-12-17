#ifndef AES_HPP
#define AES_HPP

unsigned char* encryptBlock(unsigned char* data, unsigned char* key);
unsigned char* decryptBlock(unsigned char* data, unsigned char* key);

#endif   // AES_HPP
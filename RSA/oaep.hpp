#ifndef OAEP_HPP
#define OAEP_HPP

/* --- Padding functions --- */
unsigned char* paddingEncode(unsigned char* mes, int mesLen, unsigned char* label, int lbLen);
unsigned char* paddingDecode(unsigned char* block, unsigned char* label, int lbLen);

#endif // OAEP_HPP
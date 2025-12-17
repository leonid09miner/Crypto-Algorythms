// Lab1_Crypt_Meth.cpp : Этот файл содержит функцию "main". Здесь начинается и заканчивается выполнение программы.
//

#include <iostream>
#include <random>
#include <string>

using namespace std;
using u32 = uint_least32_t;
using engine = std::mt19937;

char* caesar(char* data, int len, int shift);
char* substitutionEncr(char* data, int len);
char* substitutionDecr(char* data, int len);
char* vigenereEncr(char* data, int len, char* key, int keyLen);
char* vigenereDecr(char* data, int len, char* key, int keyLen);
char* transpositionEncr(char* data, int len, int* order, int cols);
char* transpositionDecr(char* data, int len, int* order, int cols);
char* enygmaEncrypt(char* data, int len, int* rotInitPos);

int main()
{
    char text[] = "Hello World!";
    int len = 0;
    while (text[len])
        len++;

    char text1[] = "Rock and stone you beautiful dwarf";
    int len1 = 0;
    while (text1[len1])
        len1++;

    char text2[] = "Third demonstration text without any significant content or meaning";
    int len2 = 0;
    while (text2[len2])
	    len2++;

    cout << "-- Caesar --" << endl;

    char* encr = caesar(text, len, 15);
    char* decr = caesar(encr, len, -15);
    
    cout << "Initial text:   " << text << endl;
    cout << "Encrypted text: " << encr << endl;
    cout << "Decrypted text: " << decr << endl << endl;

    delete[] encr;
    delete[] decr;

    encr = caesar(text1, len1, -9);
    decr = caesar(encr, len1, 9);
    
    cout << "Initial text:   " << text1 << endl;
    cout << "Encrypted text: " << encr << endl;
    cout << "Decrypted text: " << decr << endl << endl;

    delete[] encr;
    delete[] decr;

    encr = caesar(text2, len2, 2);
    decr = caesar(encr, len2, -2);
    
    cout << "Initial text:   " << text2 << endl;
    cout << "Encrypted text: " << encr << endl;
    cout << "Decrypted text: " << decr << endl << endl;

    delete[] encr;
    delete[] decr;

    cout << "-- Substitution --" << endl;

    encr = substitutionEncr(text, len);
    decr = substitutionDecr(encr, len);
    
    cout << "Initial text:   " << text << endl;
    cout << "Encrypted text: " << encr << endl;
    cout << "Decrypted text: " << decr << endl << endl;

    delete[] encr;
    delete[] decr;

    encr = substitutionEncr(text1, len1);
    decr = substitutionDecr(encr, len1);
    
    cout << "Initial text:   " << text1 << endl;
    cout << "Encrypted text: " << encr << endl;
    cout << "Decrypted text: " << decr << endl << endl;

    delete[] encr;
    delete[] decr;

    encr = substitutionEncr(text2, len2);
    decr = substitutionDecr(encr, len2);
    
    cout << "Initial text:   " << text2 << endl;
    cout << "Encrypted text: " << encr << endl;
    cout << "Decrypted text: " << decr << endl << endl;

    delete[] encr;
    delete[] decr;

    cout << "-- Transposition --" << endl;
    int lenEn;

    int order[] = { 5, 3, 1, 4, 2, 0 };
    encr = transpositionEncr(text, len, order, 6);
    
    lenEn = 0;
    while (encr[lenEn])
        lenEn++;
    decr = transpositionDecr(encr, lenEn, order, 6);
    
    cout << "Initial text:   " << text << endl;
    cout << "Encrypted text: " << encr << endl;
    cout << "Decrypted text: " << decr << endl << endl;

    delete[] encr;
    delete[] decr;
    
    int order1[] = { 3, 0, 4, 2, 5, 1 };
    encr = transpositionEncr(text1, len1, order1, 6);
    
    lenEn = 0;
    while (encr[lenEn])
        lenEn++;
    decr = transpositionDecr(encr, lenEn, order1, 6);
    
    cout << "Initial text:   " << text1 << endl;
    cout << "Encrypted text: " << encr << endl;
    cout << "Decrypted text: " << decr << endl << endl;

    delete[] encr;
    delete[] decr;

    int order2[] = { 1, 5, 2, 0, 4, 3 };
    encr = transpositionEncr(text2, len2, order2, 6);
    
    lenEn = 0;
    while (encr[lenEn])
        lenEn++;
    decr = transpositionDecr(encr, lenEn, order2, 6);
    
    cout << "Initial text:   " << text2 << endl;
    cout << "Encrypted text: " << encr << endl;
    cout << "Decrypted text: " << decr << endl << endl;

    delete[] encr;
    delete[] decr;

    cout << "-- Vigenere --" << endl;
    
    char key[] = "lemon";
    encr = vigenereEncr(text, len, key, 5);
    decr = vigenereDecr(encr, len, key, 5);
    
    cout << "Initial text:   " << text << endl;
    cout << "Encrypted text: " << encr << endl;
    cout << "Decrypted text: " << decr << endl << endl;

    delete[] encr;
    delete[] decr;

    char key1[] = "wererich";
    encr = vigenereEncr(text1, len1, key1, 8);
    decr = vigenereDecr(encr, len1, key1, 8);
    
    cout << "Initial text:   " << text1 << endl;
    cout << "Encrypted text: " << encr << endl;
    cout << "Decrypted text: " << decr << endl << endl;

    delete[] encr;
    delete[] decr;

    char key2[] = "testkey";
    encr = vigenereEncr(text2, len2, key2, 7);
    decr = vigenereDecr(encr, len2, key2, 7);
    
    cout << "Initial text:   " << text2 << endl;
    cout << "Encrypted text: " << encr << endl;
    cout << "Decrypted text: " << decr << endl << endl;

    delete[] encr;
    delete[] decr;

    cout << "-- Enygma --" << endl;

    int initPos[] = { 16, 23, 8 };
    encr = enygmaEncrypt(text, len, initPos);
    decr = enygmaEncrypt(encr, len, initPos);
    
    cout << "Initial text:   " << text << endl;
    cout << "Encrypted text: " << encr << endl;
    cout << "Decrypted text: " << decr << endl << endl;

    delete[] encr;
    delete[] decr;

    int initPos1[] = { 2, 9, 15 };
    encr = enygmaEncrypt(text1, len1, initPos1);
    decr = enygmaEncrypt(encr, len1, initPos1);
    
    cout << "Initial text:   " << text1 << endl;
    cout << "Encrypted text: " << encr << endl;
    cout << "Decrypted text: " << decr << endl << endl;

    delete[] encr;
    delete[] decr;
    
    int initPos2[] = { 24, 23, 13 };
    encr = enygmaEncrypt(text2, len2, initPos2);
    decr = enygmaEncrypt(encr, len2, initPos2);
    
    cout << "Initial text:   " << text2 << endl;
    cout << "Encrypted text: " << encr << endl;
    cout << "Decrypted text: " << decr << endl << endl;

    delete[] encr;
    delete[] decr;

    char textHello[] = "Hey, everybody! How are you doing?";
    int len3 = 0;
    while(textHello[len3])
	    len3++;

    int initPos3[] = {7, 13, 2};
    encr = enygmaEncrypt(textHello, len3, initPos3);
    cout << encr << endl;
    decr = enygmaEncrypt(encr, len3, initPos3);
    cout << decr << endl;

    delete[] encr;
    delete[] decr;
}

char* caesar(char* data, int len, int shift)
{
    if (shift == 0)
        return NULL;

    char* res = new char[len + 1];
    for (int i = 0; i < len; i++)
    {
        if (data[i] >= 'a' && data[i] <= 'z')
            res[i] = 'a' + (data[i] - 'a' + 26 + shift) % 26;
        else if (data[i] >= 'A' && data[i] <= 'Z')
            res[i] = 'A' + (data[i] - 'A' + 26 + shift) % 26;
        else
            res[i] = data[i];
    }

    res[len] = '\0';
    return res;
}

char* substitutionEncr(char* data, int len)
{
    char alph[] = "qwertyuiopasdfghjklzxcvbnm";
    char Alph[] = "QWERTYUIOPASDFGHJKLZXCVBNM";
    char alph_num[] = "5481096237";

    char* res = new char[len + 1];
    for (int i = 0; i < len; i++)
    {
        if (data[i] >= 'a' && data[i] <= 'z')
            res[i] = alph[data[i] - 'a'];
        else if (data[i] >= 'A' && data[i] <= 'Z')
            res[i] = Alph[data[i] - 'A'];
        else if (data[i] >= '0' && data[i] <= '9')
            res[i] = alph_num[data[i] - '0'];
        else
            res[i] = data[i];
    }

    res[len] = '\0';
    return res;
}

char reverseSubst(char c)
{
    char alph[] = "qwertyuiopasdfghjklzxcvbnm";
    char Alph[] = "QWERTYUIOPASDFGHJKLZXCVBNM";
    char alph_num[] = "5481096237";
    char res = c;
    if (c >= 'a' && c <= 'z')
    {
        for (int i = 0; i < 26; i++)
        {
            if (alph[i] == c)
            {
                res = 'a' + i;
                break;
            }
        }
    }
    else if (c >= 'A' && c <= 'Z')
    {
        for (int i = 0; i < 26; i++)
        {
            if (Alph[i] == c)
            {
                res = 'A' + i;
                break;
            }
        }
    }
    else if (c >= '0' && c <= '9')
    {
        for (int i = 0; i < 10; i++)
        {
            if (alph_num[i] == c)
            {
                res = '0' + i;
                break;
            }
        }
    }

    return res;
}

char* substitutionDecr(char* data, int len)
{
    char* res = new char[len + 1];
    for (int i = 0; i < len; i++)
    {
        res[i] = reverseSubst(data[i]);
    }

    res[len] = '\0';
    return res;
}

char* vigenereEncr(char* data, int len, char* key, int keyLen)
{
    char* res = new char[len + 1];
    int j = 0;

    for (int i = 0; i < len; i++)
    {
            if (data[i] >= 'a' && data[i] <= 'z')
            {
                res[i] = 'a' + (data[i] - 'a' + (key[j] - 'a')) % 26;
                j = (j + 1) % keyLen;
            }
            else if (data[i] >= 'A' && data[i] <= 'Z')
            {
                res[i] = 'A' + (data[i] - 'A' + (key[j] - 'a')) % 26;
                j = (j + 1) % keyLen;
            }
            else
                res[i] = data[i];
    }

    res[len] = '\0';
    return res;
}

char* vigenereDecr(char* data, int len, char* key, int keyLen)
{
    char* res = new char[len + 1];
    int j = 0;

    for (int i = 0; i < len; i++)
    {
        if (data[i] >= 'a' && data[i] <= 'z')
        {
            if (key[j] < data[i])
                res[i] = 'a' + (data[i] - key[j]) % 26;
            else 
                res[i] = 'a' + (26 + data[i] - key[j]) % 26;
            j = (j + 1) % keyLen;
        }
        else if (data[i] >= 'A' && data[i] <= 'Z')
        {
            char c = data[i] - 'A' + 'a';
            if (key[j] < c)
                res[i] = 'A' + (c - key[j]) % 26;
            else
                res[i] = 'A' + (26 + c - key[j]) % 26;
            j = (j + 1) % keyLen;
        }
        else
            res[i] = data[i];
    }

    res[len] = '\0';
    return res;
}

char* transpositionEncr(char* data, int len, int* order, int cols)
{
    int rows = len / cols;
    if (len % cols != 0)
        rows++;

    char* res = new char[rows * cols + 1];
    char** table = new char* [rows];

    for (int i = 0; i < rows; i++)
    {
        table[i] = new char[cols];
        for (int j = 0; j < cols; j++)
        {
            if (i * cols + j < len)
                table[i][j] = data[i * cols + j];
            else
                table[i][j] = ' ';
        }
    }

    for (int i = 0; i < cols; i++)
        for (int j = 0; j < rows; j++)
            res[i * rows + j] = table[j][order[i]];

    for (int i = 0; i < rows; i++)
        delete[] table[i];
    delete[] table;

    res[rows * cols] = '\0';
    return res;
}

char* transpositionDecr(char* data, int len, int* order, int cols)
{
    int rows = len / cols;

    char* res = new char[len + 1];
    char** table = new char* [rows];
    for (int i = 0; i < rows; i++)
        table[i] = new char[cols];

    for (int i = 0; i < cols; i++)
        for (int j = 0; j < rows; j++)
            table[j][order[i]] = data[i * rows + j];

    for (int i = 0; i < rows; i++)
    {
        for (int j = 0; j < cols; j++)
            res[i * cols + j] = table[i][j];

        delete[] table[i];
    }
    delete[] table;

    int ind = len - 1;
    while (res[ind] == ' ')
        ind--;

    res[ind + 1] = '\0';
    return res;
}

char* enygmaEncrypt(char* data, int len, int* rotInitPos)
{
    //               abcdefghijklmnopqrstuvwxyz
    char rotor1[] = "kjflabgvidpsxcyorhequtnwzm";
    char rotor1rev[] = "efnjscgribadzwpktqlvuhxmoy";
    char rotor2[] = "uyoxlsaithkncpvebrqgjfwzmd";
    char rotor2rev[] = "gqmzpvtjhukeylcnsrfiaowdbx";
    char rotor3[] = "mfseqwczoaukjtpixlbrghvynd";
    char rotor3rev[] = "jsgzdbuvpmlrayioetcnkwfqxh";
    char* rotors[] = { rotor1, rotor2, rotor3 };
    char* rotorsrev[] = { rotor1rev, rotor2rev, rotor3rev };
    char notches[] = { 'q', 'r' };
    //                  abcdefghijklmnopqrstuvwxyz
    char reflector[] = "yruhqsldpxngokmiebfzcwvjat";

    int rotPos[] = { rotInitPos[0], rotInitPos[1], rotInitPos[2] };

    char* res = new char[len + 1];
    for (int i = 0; i < len; i++)
    {
        char symb = data[i];
        if (symb >= 'a' && symb <= 'z')
        {
            rotPos[0] = (rotPos[0] + 1) % 26;
            if (rotor1[rotPos[0]] == notches[0])
                rotPos[1] = (rotPos[1] + 1) % 26;
            if (rotor2[rotPos[1]] == notches[1])
                rotPos[2] = (rotPos[2] + 1) % 26;

            symb = symb - 'a';
            for (int i = 0; i < 3; i++)
                symb = (rotors[i][(symb + rotPos[i]) % 26] - 'a' - rotPos[i] + 26) % 26;

            symb = reflector[symb] - 'a';

            for (int i = 2; i >= 0; i--)
                symb = (rotorsrev[i][(symb + rotPos[i]) % 26] - 'a' - rotPos[i] + 26) % 26;
            symb += 'a';
        }
        else if (symb >= 'A' && symb <= 'Z')
        {
            rotPos[0] = (rotPos[0] + 1) % 26;
            if (rotor1[rotPos[0]] == notches[0])
                rotPos[1] = (rotPos[1] + 1) % 26;
            if (rotor2[rotPos[1]] == notches[1])
                rotPos[2] = (rotPos[2] + 1) % 26;

            symb = symb - 'A';
            for (int i = 0; i < 3; i++)
                symb = (rotors[i][(symb + rotPos[i]) % 26] - 'a' - rotPos[i] + 26) % 26;

            symb = reflector[symb] - 'a';

            for (int i = 2; i >= 0; i--)
                symb = (rotorsrev[i][(symb + rotPos[i]) % 26] - 'a' - rotPos[i] + 26) % 26;
            symb = symb + 'A';
        }
        res[i] = symb;
    }

    res[len] = '\0';
    return res;
}

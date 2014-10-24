//need to read hash[0] and hash[x] from file.
// get hashed pass from inut and hash and reduce it to see if you get one of the hash[x] from the rainbow table

#include "aes.h"
#include <math.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>

#define KEYSIZE 16
#define BYTE 8
#define EXTRA 100


void PrintByteStr(char *bytes) {
    unsigned long val = 0;
    val |= bytes[0];
    val |= bytes[1] << 1;
    val |= bytes[2] << 2;
    val |= bytes[3] << 3;
    printf("0x%lx", val);
}

int equalCharStar(unsigned char* p1, unsigned char* p2, int bytes) {
    for (int i = 0; i < bytes; i++) {
        if (p1[i] != p2[i]) {
            return 0;
        }
    }
    return 1;
}

/** Code for rounding up from stack overflow */
unsigned int round_div(unsigned int dividend, unsigned int divisor)
{
    return (dividend + (divisor / 2)) / divisor;
}

void error(char *str)
{
    fprintf(stderr, "%s\n", str); 
    exit(-1);
}

unsigned char asciitohex(char c)
{
    if (('0'<=c) && (c<='9'))
        return (c-'0');
    else if (('a'<=c) && (c<='f'))
        return (c-'a'+10);
    else if (('A'<=c) && (c<='F'))
        return (c-'A'+10);
    else 
        error("Hash value can contain digits 0-9, a-f only");
}

void reduce(unsigned char* ciphertext, unsigned char* truncate, int n, int extra) {
    // Won't get the last byte, the incomplete byte, unless no incomplete byte exists.
    for (int i = 0; i < round_div(n,BYTE); i++) {
        truncate[round_div(n,BYTE) - 1 - i] = ciphertext[KEYSIZE - 1 - i];
    }
    //gets incomplete byte
    if (n % BYTE) {
        for (int i = BYTE - (n%BYTE); i > 0; i--) {
            unsigned int index = BYTE*sizeof(char) - i;
            truncate[0] &= ~(1 << index);
        }
    }
    truncate[round_div(n, BYTE) - 1] += extra;
}

/**Takes in a key value. That key value must be 128 bits. This method
        only returns an encrypted password. */
void HANDLE_THIS_PASSWORD(unsigned char *pass, unsigned char *ciphertext) {
    aes_context ctx;
    unsigned char* key = calloc(16, sizeof(char));
    for (unsigned int i = 0; i < 16; i++) {
        key[i] = pass[i];
    }
    unsigned char* plaintext = calloc(16, sizeof(char));
    aes_setkey_enc(&ctx, key, 128);
    aes_crypt_ecb(&ctx, AES_ENCRYPT, plaintext, ciphertext);            //Need Error Handling code
    free(key);
    free(plaintext);
}

int haveCorrectChain(unsigned char* hash, unsigned int n, unsigned int s, unsigned char* pass, int* aes) {

    unsigned long long totalChains = (3 * 16 * pow(2, s)) / (round_div(n, BYTE) + 16);
    unsigned long long power = pow(2, n);
    unsigned long long chain_len = 3 * (((power + (totalChains/2)) / totalChains) + 1);

    //unsigned long long totalChains = (.93) * (3 * 16 * pow(2, s)) / (round_div(n, BYTE) + 16);
    //unsigned int chain_len = 40 * pow(2, n) / totalChains;
    unsigned char* copyPass = calloc(round_div(n, BYTE), sizeof(char));
    unsigned char* exPass = calloc(16, sizeof(char));
    unsigned char* currentHash = calloc(KEYSIZE, sizeof(char));
    // printf("%s\n\n", "Taking found chain and doing AES over it and extra");
    // for (int i = 0; i < round_div(n, BYTE); i++) {
    //     printf("%02x", pass[i]);
    // }
    // printf("             This is the value of pass\n");

    for (unsigned int i = 0; i < EXTRA; i++) {                  // goes through every extra value
        for (int index = 0; index < round_div(n, BYTE); index++) {          
            copyPass[index] = pass[index];                              //set copypass back to pass, didn't get it starting at extra = i;
        }

        int extra = i;
        for (unsigned int j = 0; j < chain_len + 300; j++, extra++) {              // do a hash with this incrementing extra chain_len times
            extra = extra % EXTRA;
            for (int i1 = 0; i1< round_div(n, BYTE); i1++) {
                exPass[(KEYSIZE -1) - i1] = copyPass[(round_div(n, BYTE) - 1) - i1];
            }

            HANDLE_THIS_PASSWORD(exPass, currentHash);
            *aes += 1;
            if (equalCharStar(hash, currentHash, KEYSIZE) == 1) {           //found the *correct* password
                printf("Password is 0x");
                for (int i = 0; i < KEYSIZE; i++) {
                    exPass[i] = 0;
                }
                for (int i1 = 0; i1< round_div(n, BYTE); i1++) {
                    exPass[(KEYSIZE -1) - i1] = copyPass[(round_div(n, BYTE) - 1) - i1];
                }
                for (int i = 0; i < 16; i++) {
                    printf("%02x", exPass[i]);
                }
                printf(". AES was evaluated %d times\n", *aes);
                free(exPass);
                free(copyPass);
                free(currentHash);
                return 1;
            } else {
                reduce(currentHash, copyPass, n, extra);
            }
        }
    }

    //printf("%s\n", "Did not find a password");
    return 0;
}

void doCompareAndHash(unsigned char* hash, unsigned int n, unsigned int s, unsigned char* pass, int* aes) {
    FILE *file;
    int errnum;
    file = fopen("gentable.bin","rb");
    if (!file) {
        error("Could not open file");
    }

    unsigned long long totalChains = (3 * 16 * pow(2, s)) / (round_div(n, BYTE) + 16);
    unsigned long long power = pow(2, n);
    unsigned long long chainElems = 3 * (((power + (totalChains/2)) / totalChains) + 1);
    if (n == s) {
        chainElems = 1;
    }
    unsigned char* exPass = calloc(KEYSIZE, sizeof(char));    
    unsigned char* currentHash = calloc(KEYSIZE, sizeof(char));
    for (int i = 0; i < KEYSIZE; i++) {
        currentHash[i] = hash[i];
    }
    unsigned char* fileHash = calloc(KEYSIZE, sizeof(char));

    //for every H(p) until hash len times
        // for every hash in the file
    for (int e = 0; e < EXTRA; e++) {
        for (int index = 0; index < KEYSIZE; index++) {          
            currentHash[index] = hash[index];                              //set copypass back to pass, didn't get it starting at extra = i;
        }
        int extra = e;
        for (int hashCount = 0; hashCount < chainElems; hashCount++, extra++) {
            extra = extra % EXTRA;
            int endOfFile = 0;
            fseek(file, SEEK_SET, 0);
            reduce(currentHash, pass, n,extra);       // pass = P1
            HANDLE_THIS_PASSWORD(pass, currentHash);        //currentHash = H1
            *aes += 1;
            while (endOfFile == 0) {
                if (fread(pass, sizeof(char), round_div(n, BYTE), file) < round_div(n, BYTE)) {        //pass = chain's password
                    //printf("%s\n", "End of File Reading Password");
                    endOfFile = 1;
                    break;
                }

                if (fread(fileHash, sizeof(char), KEYSIZE, file) < KEYSIZE) {           //hash = currentHash
                    printf("%s\n", "End of File Reading Hash");
                    endOfFile = 1;
                }

                if (equalCharStar(currentHash, fileHash, KEYSIZE) == 1) {
                    //printf("%d\n", *aes);
                    if (haveCorrectChain(hash, n, s, pass, aes) == 1) {
                        free(exPass);
                        free(currentHash);
                        free(fileHash);
                        free(exPass);
                        fclose(file);
                        return;
                    }
                }
            }
        }
    }
    fclose(file);
    free(currentHash);
    free(fileHash);
    printf("%s\n", "Didnt find a matching hash");
    return;
}

void at(int* p) {
    *p += 1;
}

int main (int argc, char *argv[])
{

    int n = atoi(argv[1]);
    int s = atoi(argv[2]);
    unsigned char buffer[16];
    int i, j;

    if (argc != 4)
         error("Usage:  crack n s hash");

    if ((strlen(argv[3]) != 34) | (argv[3][0] != '0') || (argv[3][1] != 'x'))
        error("Hash value should be of the form 0x... and exactly 16 bytes long");
    for (i=2, j=0; j<16; i += 2, j++)
        buffer[j] = (asciitohex(argv[3][i])<<4) | (asciitohex(argv[3][i+1]));
    int* aesP = (int *)malloc(sizeof(int));

    *aesP = 0;
    unsigned char* passHead = calloc(round_div(n, BYTE), sizeof(char));
    // int zero = malloc(sizeof(int));
    // zero = 0;
    //aesP = zero;
    doCompareAndHash(buffer, n, s, passHead, aesP);
    //haveCorrectChain(buffer, n, s, passHead);
    free(passHead);
    free(aesP);
    return 0;
}

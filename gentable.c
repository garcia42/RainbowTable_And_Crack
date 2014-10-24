#include "aes.h"
#include <stdio.h>
#include <stdlib.h>     /* atoi */
#include <math.h>

#define KEYSIZE 16
#define BYTE 8
#define EXTRA 100

/** Code for rounding up from stack overflow */
unsigned int round_div(unsigned int dividend, unsigned int divisor)
{
    return (dividend + (divisor / 2)) / divisor;
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

void reduce(unsigned char* ciphertext, unsigned char* truncate, int n, int extra) {
    // Won't get the last byte, the incomplete byte, unless no incomplete byte exists.
    for (int i = 0; i < round_div(n,BYTE); i++) {
        truncate[round_div(n,BYTE) - 1 - i] = ciphertext[KEYSIZE - 1 - i];
    }
    //gets incomplete byte
    if (n % BYTE) {
        for (int i = BYTE - (n%BYTE); i > 0; i--) {
            // 0 1 2 3
            unsigned int index = BYTE*sizeof(char) - i;
            truncate[0] &= ~(1 << index);
        }
    }
    truncate[round_div(n, BYTE) - 1] += extra;
}

/** Got this code from mathcs.emory.edu */
void  setBit(unsigned int A[ ], unsigned long long k )
{
    int i = k/32;
    int pos = k%32;
    unsigned int flag = 1;  // flag = 0000.....00001
    flag = flag << pos;     // flag = 0000...010...000   (shifted k positions)
    A[i] = A[i] | flag;     // Set the bit at the k-th position in A[i]
}

/** Got this code from mathcs.emory.edu */
void  clearBit(unsigned int A[ ],  unsigned long long k )
{
   int i = k/32;
   int pos = k%32;
   unsigned int flag = 1;  // flag = 0000.....00001
   flag = flag << pos;     // flag = 0000...010...000   (shifted k positions)
   flag = ~flag;           // flag = 1111...101..111
   A[i] = A[i] & flag;     // RESET the bit at the k-th position in A[i]
}

/** Got this code from mathcs.emory.edu */
int checkBit(unsigned int A[], unsigned long long k) {
    int i = k/32;
    int pos = k%32;

    unsigned int flag = 1;  // flag = 0000.....00001

    flag = flag << pos;     // flag = 0000...010...000   (shifted k positions)

    if ( A[i] & flag )      // Test the bit at the k-th position in A[i]
        return 1;
    else
        return 0;
}

// /*
//  *  assign -- transform long long (64 bit unsigned integer) val to 16 byte array pass
//  */

void assign(unsigned char *pass, unsigned long long val)
{
        int i;

        for (i = 15; i >= 8; i--)
        {
                pass[i] = (unsigned char) val & 0xFF;
                val >>= 8;
        }
    for (i =7; i >= 0; i--)
        pass[i] = 0;
}

unsigned int getIntValue(unsigned char *ciphertext, unsigned int n) {

    unsigned long long check = 0;
    for (int byte = round_div(n, BYTE) - 1; byte > -1; byte--) {
        // printf("%02x            Byte Value\n", ciphertext[byte]);
        for (int i=0; i < BYTE; i++) {
            int pow2 = (((round_div(n, BYTE) -1) - byte) * BYTE) + i;
            //printf("%d\n", (ciphertext[byte]));
            if (((ciphertext[byte] >> i)  & 1) == 1) {
                check += pow(2, pow2);
            }
        }
    }
    return check;
}

void testIntValue() {
    unsigned char* truncate = calloc(3, sizeof(char));
    //02 22 9f
    truncate[0] = 0x02;
    truncate[1] = 0x22;
    truncate[2] = 0x9f;
    for (int i = 0; i < 3; i++) {
        printf("%02x", truncate[i]);
    }
    printf("\n");
    printf("%d\n", getIntValue(truncate, 20));
    //139935
}

void testAES() {
    unsigned char* test = calloc(16, sizeof(char));
    unsigned char* ciphertext = calloc(16, sizeof(char));
    test[14] = 0xA;
    test[15] = 0xBC;
    HANDLE_THIS_PASSWORD(test, ciphertext);                 //cypertext will be returned as H(p)
    for (int i = 0; i < 16; i++) {
        printf("%02x", ciphertext[i]);
    }
    printf("\n");
    free(test);
    free(ciphertext);
}

void testReduce() {
    unsigned char* test = calloc(16, sizeof(char));
    unsigned char* truncate = calloc(3, sizeof(char));
    test[13] = 0xAB;
    test[14] = 0xCD;
    test[15] = 0xEF;
    for (int i = 0; i < 16; i++) {
        printf("%02x", test[i]);
    }
    printf("\n");
    for (int i=0; i < 3; i++) {
        printf("%02x", truncate[i]);
    }
    printf("\n");
    reduce(test, truncate, 22, 0);
    for (int i=0; i < 3; i++) {
        printf("%02x", truncate[i]);
    }
    printf("\n");
    free(test);
    free(truncate);
}


int equalCharStar(unsigned char* p1, unsigned char* p2, int bytes) {
    for (int i = 0; i < bytes; i++) {
        if (p1[i] != p2[i]) {
            return 0;
        }
    }
    return 1;
}

/** Takes in 2 arguments
    1) Password length: n in bits
    2) s bound of size of rainbow
    Rainbow no larger than 3 x 128 x 2^s bits
    n - s <= 10
 */
int main(int argc, char *argv[])
{
    int n = atoi(argv[1]);
    int s = atoi(argv[2]);

    //unsigned long long totalChains = (.93) * (3 * 16 * pow(2, s)) / (round_div(n, BYTE) + 16);
    unsigned long long totalChains = (.93) * (3 * 16 * pow(2, s)) / (round_div(n, BYTE) + 16);
    unsigned long long power = pow(2, n);
    unsigned long long chainElems = 3 * (((power + (totalChains/2)) / totalChains) + 1);
    if (n == s) {
        chainElems = 1;
    }
    printf("%llu\n", power);
    printf("%llu            Upper bound on number of chains allowed\n", totalChains);
    printf("%llu            Number of elements in a chain\n", chainElems);
    int nVal = n;

    /*  1<<28 = 2^28 = number of bytes for a bitmap with 2^31 entries */
    unsigned int *A = calloc( 1u << 28, sizeof( unsigned int ));

    FILE *file;
    file = fopen("gentable.bin","wb");
    if (!file) {
        printf("\n fopen() Error!!!\n");
        return 1;
    }

//The thing that needs to be hashed is only going to be at most 32 bits, but we wil extend it to 128 bits.
//Only need an array of 32 bit numbers, so unsigned ints.
    unsigned char* truncate;
    truncate = calloc(round_div(n, BYTE), sizeof(char));
    unsigned char* pass = calloc(KEYSIZE, sizeof(char));                                                         // Character to be hashed
    unsigned char* ciphertext = calloc(KEYSIZE, sizeof(char));               // Placeholder to keep cyphertext through function calls

    unsigned long long numChains = 0;
    unsigned long long up = pow(2,nVal);
    unsigned long long extra = 0;
    unsigned long long totalPasses = 0;

    for (unsigned long long i = 0; i < up; i++) {
        if (!checkBit(A, i)) {
            totalPasses++;
            numChains++;
            assign(pass, i);

            setBit(A, i);
            unsigned int length = 1;
            ////-------------------
            for (int k = 0; k < 16 + 1; k++) {
                ciphertext[k] = 0;                                   // Clear the bit array
            }
            HANDLE_THIS_PASSWORD(pass, ciphertext);                 //cypertext will be returned as H(p)

            int j;

            for (j = round_div(n, BYTE) - 1; j >= 0; j--) {
                truncate[j] = pass[(KEYSIZE -1) - ((round_div(n, BYTE) -1) - j)];                                   // Clear the bit array
            }

            //--------------------

            while (length < chainElems) {
                length++;

                extra++;
                extra = extra % EXTRA;
                reduce(ciphertext, truncate, n, extra);        //
                if (!checkBit(A, getIntValue(truncate, n))) {
                    totalPasses++;
                }
                setBit(A, getIntValue(truncate, n));                                  // mark that we have now seen this password
                int j;
                for (j = 0; j < round_div(n ,4); j++) {
                    pass[j] = truncate[j];                                   // Clear the bit array
                }
                for (int rest = j; rest < 16; rest++) {
                    pass[rest] = 0;
                }

                HANDLE_THIS_PASSWORD(pass, ciphertext);                 //cypertext will be returned as H(p)
            }

            if (round_div(n, BYTE) != fwrite(truncate, 1, round_div(n, BYTE), file)) {
                printf("\n Error: password KEYSIZE != fwrite\n");
                printf("%d\n", round_div(n, BYTE));
                for (int i = 0; i < 16; i++) {
                    printf("%02x", truncate[i]);
                }
                printf("\n");
                return 1;
            }
            if (KEYSIZE != fwrite(ciphertext, 1, KEYSIZE, file)) {
                printf("\n Error: hash KEYSIZE != fwrite\n");
            }
            if (totalChains - numChains == 1) {
                printf("\n%s\n\n", "Number of created chains larger than allowed chains");
                fclose(file); /*done!*/
                free(A);
                free(pass);
                free(ciphertext);
                free(truncate);

                printf("%llu        current password index in for loop\n", i);
                printf("%llu        2^n\n", up);
                printf("%llu        Total unique passwords\n", totalPasses);
                return 0;
            }
        }
    }
    printf("%llu            Number of chains created\n", numChains);
    printf("%llu        Total unique passwords\n", totalPasses);
    free(A);
    free(pass);
    free(ciphertext);
    free(truncate);
    fclose(file); /*done!*/
    return 0;
}

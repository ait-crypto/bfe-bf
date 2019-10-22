#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>
#include "util.h"
#include "relic/relic.h"
#include "logger.h"

void byteArraysXOR(uint8_t *out, uint8_t *array1, uint8_t *array2, int len1, int len2) {
    int lengthDiff = len1 - len2;
    for (int i = 0; i < len1 + abs(lengthDiff); ++i) {
        if (i < len1) {
            out[i] = array1[i] ^ array2[i];
        } else {
            if (lengthDiff < 0) {
                out[i] = (uint8_t) 0 ^ array2[i];
            } else {
                out[i] = array1[i] ^ (uint8_t) 0;
            }

        }
    }
}

/**

 * Ansi C "itoa" based on Kernighan & Ritchie's "Ansi C":

 */

void strreverse(char* begin, char* end) {

    char aux;

    while(end>begin)

        aux=*end, *end--=*begin, *begin++=aux;

}

void itoa(int value, char* str, int base) {

    static char num[] = "0123456789abcdefghijklmnopqrstuvwxyz";

    char* wstr=str;

    int sign;

    // Validate base
    if (base<2 || base>35){ *wstr='\0'; return; }

    // Take care of sign
    if ((sign=value) < 0) value = -value;

    // Conversion. Number is reversed.
    do *wstr++ = num[value%base]; while(value/=base);
    if(sign<0) *wstr++='-';
    *wstr='\0';


    // Reverse string
    strreverse(str,wstr-1);

}

int compareBinaryStrings(char *string1, char *string2) {
    size_t len1 = strlen(string1);
    size_t len2 = strlen(string2);
    size_t longerLength = len1 < len2 ? len2 : len1;
    size_t lengthDiff = len1 < len2 ? len2 - len1 : len1 - len2;

    int i = 0;
    for (; i < lengthDiff; i++) {
        if (len1 < len2) {
            if (string2[i] == '1') {
                return -1;
            }
        } else {
            if (string1[i] == '1') {
                return 1;
            }
        }
    }

    for (; i < longerLength; i++) {
        if (len1 < len2) {
            if (string1[i - lengthDiff] != string2[i]) {
                return string1[i - lengthDiff] - string2[i];
            }
        } else {
            if (string1[i] != string2[i - lengthDiff]) {
                return string1[i] - string2[i - lengthDiff];
            }
        }
    }

    return 0;
}

#if defined __GLIBC__ && defined __linux__

#if __GLIBC__ > 2 || __GLIBC_MINOR__ > 24
#  include <sys/random.h>

void generateRandomBytes(uint8_t* dst, int binSize) {
    getrandom(dst, binSize, GRND_NONBLOCK);
}

#else /* older glibc */
#include <unistd.h>
#include <sys/syscall.h>

void generateRandomBytes(uint8_t* dst, int binSize) {
    syscall(SYS_getrandom, dst, binSize, 0);
}

#endif

#endif
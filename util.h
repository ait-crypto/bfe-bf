#ifndef MASTER_PROJECT_UTIL_H
#define MASTER_PROJECT_UTIL_H

#include <stdint.h>

void byteArraysXOR(uint8_t *out, const uint8_t *array1, const uint8_t *array2, int len1, int len2);

void itoa(int value, char* str, int base);

int compareBinaryStrings(char *string1, char *string2);

void generateRandomBytes(uint8_t *bin, unsigned int binSize);

#endif //MASTER_PROJECT_UTIL_H

#ifndef MASTER_PROJECT_UTIL_H
#define MASTER_PROJECT_UTIL_H

void byteArraysXOR(uint8_t *out, uint8_t *array1, uint8_t *array2, int len1, int len2);

void itoa(int value, char* str, int base);

int compareBinaryStrings(char *string1, char *string2);

void generateRandomBytes(uint8_t *bin, int binSize);

#endif //MASTER_PROJECT_UTIL_H

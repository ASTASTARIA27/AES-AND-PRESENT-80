#include <stdio.h>
#include "PRESENT_80.h"

/*
Present_80 encryption process has 31 rounds plus one final round, each round it uses 64bit round key 
IT has total of 32 rounds so total size will be 32*8=256
*/
unsigned char keyExpansion[256];
void Key_Expansion(unsigned char EncryptionKey[10]) {   
    //For circular shift instead of doing left shift of 61 bits .
    //I am doing the right shift of 19 bits.
    uint8_t key[10];
    memcpy(key,EncryptionKey,10);
    uint8_t temp[10];
    /*
    (key[(i + 8) % 10] >> 3) takes bytes from two positions back and move its bits to 3 positions right.this fills bottom 5 bits on the byte.
    (key[(i + 7) % 10] << 5) takes three bits that are falling off the right side of the byte three positions back and puts them all the 
    way to the left side of the current byte.
    */
    for(int i=0; i<10; i++) {
        temp[i] = (key[(i + 8) % 10] >> 3) |
                  (key[(i + 7) % 10] << 5);
    }
    memcpy(key,temp,10);

    //SBOX with the top bits and XOR with a round counter
    
}
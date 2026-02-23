#include <stdio.h>
#include "AES.h"

unsigned char KeyExpansion[176];
//As for in Key_Expansion function we have 176 bit array we can think of it as 44 words
//First four words as W0,W1,W2,W3 for the encryption key
void Key_Expansion(unsigned char*Encryption_Key,unsigned char*RoundConst) {
    //AES-128 requires 11 sets of 16-byte round keys (11×16=176).
    
    //Temporary array of 44 words where each 4byte is a word
    //First 4 words just copying from the Encryption Key
    uint32_t word[44];
    for (int i =0; i<4;i++) {
        word[i] = ((uint32_t)Encryption_Key[4*i]<<24) |
                  ((uint32_t)Encryption_Key[4*i + 1]<<16) | 
                  ((uint32_t)Encryption_Key[4*i + 2]<<8) |
                  ((uint32_t)Encryption_Key[4*i + 3]);
    }

    //Generating remaining 40 words using loop
    //AES Key Schedule logic 
    //Each new word is created by XORing previos words to the word from 4 positions ago
    //word[i] = word[i-1] ^ word[i-4]
    for (int i = 4; i<44; i++) {
        uint32_t wordN = word[i-1];
        //Every 4th word(i%4==0) goes a special transformation
        if(i%4==0) {
            //Rot word - Performs a circular shift on the 4 bytes(which is a word)
            wordN = (wordN << 8) | (wordN >> 24);
            //Sub word looking for each byte in the sbox
            //substitute each byte using sbox look up table to provide non linearity
            wordN = (sbox[(wordN >> 24) & 0xff] << 24) |
                    (sbox[(wordN >> 16) & 0xff] << 16) |
                    (sbox[(wordN >> 8) & 0xff] << 8) |
                    (sbox[(wordN & 0xff)]);
            //Round constant XOR
            //XORs the leftmost byte with a specific value from RoundConst to ensure each round key is unique.
            //i/4-1 because i starts at 4 for the 1st constant
            wordN ^= (uint32_t)RoundConst[i/4 - 1] << 24;
        }
        word[i] = word[i-4]^wordN;
    }
    //copying in to KeyExpansion using memcpy from the temporary array word
    //memcpy(KeyExpansion, word, 176);
    for (int i = 0; i < 44; i++) {           // 44 words
        KeyExpansion[4*i]     = (word[i] >> 24) & 0xFF;
        KeyExpansion[4*i + 1] = (word[i] >> 16) & 0xFF;
        KeyExpansion[4*i + 2] = (word[i] >> 8)  & 0xFF;
        KeyExpansion[4*i + 3] =  word[i] & 0xFF;
    }
}


//Added a new function for subsytes as it can make too cluttter in the main function
void SubBytes(unsigned char State[4][4]) {
    for(int i=0; i<4; i++) {
        for(int j=0; j<4; j++) {
            State[i][j] = sbox[State[i][j]];
        }
    } 
}
//Shifting rows
void ShiftRow(unsigned char State[4][4]) {
    for(int i=0;i<4;i++) {
        unsigned char temp[4];
        for(int j=0; j<4; j++) {
            temp[j] = State[i][j];
        }
        for (int j=0; j<4; j++) {      // shift row left by i
            State[i][j] = temp[(j + i) % 4];
        }
    }
}
//xtime function
//The xtime function performs a left shift and, if the result overflows, it performs an XOR with the value 0x1b.
unsigned char xtime(unsigned char b) {
//single byte consists of 8 bits which is 0x80 inn hexa decimal
//checking is the high bit 0x80 is set or not(0x80 in binary is 10000000)
//shifting it left causes that 1 to overflow(MSB)
    if(b & 0x80) {
        return ((b<<1) ^0x1b);
    }else {
        return (b<<1);
    }
}


//MixColumns
/*MixColumns is a matrix multiplication where each "new" byte in a column is a 
weighted sum of the four "old" bytes in that same column.*/
/*
AES uses Galois Field GF(28) arithmetic. In this field:
Addition is just the XOR (^) operation.
Multiplication is specialized. Multiplying by 1 does nothing, 
but multiplying by 2 (binary 10) requires a special function often called xtime(created above to handle multiplication by 2)
*/
void MixColoumn(unsigned char State[4][4]) {
    for(int j=0;j<4;j++) {
        unsigned char temp[4];
        for(int i=0;i<4;i++) {
            temp[i] = State[i][j];
        }
        State[0][j] = xtime(temp[0]) ^ (xtime(temp[1]) ^ temp[1]) ^ temp[2] ^ temp[3];
        State[1][j] = temp[0] ^ xtime(temp[1]) ^ (xtime(temp[2]) ^ temp[2]) ^ temp[3];
        State[2][j] = temp[0] ^ temp[1] ^ xtime(temp[2]) ^ (xtime(temp[3]) ^ temp[3]);
        State[3][j] = (xtime(temp[0]) ^ temp[0]) ^ temp[1] ^ temp[2] ^ xtime(temp[3]);
    }
}


//Function for the Addroundkey
void AddRoundKey(unsigned char State[4][4], int round) {
    int temp = round * 16;
    for (int j = 0; j < 4; j++) {
        for (int i = 0; i < 4; i++) {
            State[i][j] ^= KeyExpansion[temp + (j * 4 + i)]; 
        }
    }
}
//Created a new function encrypt to test both plaintexts at once
void Encrypt(unsigned char State[4][4]) {
        //Initial Round(0)
    AddRoundKey(State, 0);

    //Round (1 to 9)
    for(int round =1 ; round < 10; round++) {
        SubBytes(State);
        ShiftRow(State);
        MixColoumn(State);
        AddRoundKey(State, round);
    }

    //Final Round(10)
    SubBytes(State);
    ShiftRow(State);
    AddRoundKey(State, 10);
}

//For printing both ciphertexts
void print(unsigned char State[4][4]) {
    for (int j = 0; j < 4; j++) {      // Iterate through columns
        for (int i = 0; i < 4; i++) {  // Iterate through rows
            printf("%02X ", State[i][j]);
        }
    }
    printf("\n");
}

int main() {
    Key_Expansion(Encryption_Key, RoundConst);
    //STATE MATRIX
    //The 16 bytes are filled into the matrix column by column.
    //Byte 0 goes to row 0, col 0 ;Byte 1 goes to row 1, col 0.
    //the formula to find the 1D index from 2D coordinates (i,j) is Index = (Coloum *4) + row
    unsigned char State[4][4];
//-----------------TEST Plaintext 1-------------
    for(int i=0;i<4;i++) {
        for(int j = 0;j<4;j++) {
            State[i][j] = Plaintext_1[j*4 +i];
        }
    }
    Encrypt(State);
    print(State);
//-----------------TEST Plaintext 2--------------
    for(int i=0;i<4;i++) {
        for(int j = 0;j<4;j++) {
            State[i][j] = Plaintext_2[j*4 +i];
        }
    }
    Encrypt(State);
    print(State);

    return 0;

}
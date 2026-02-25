#include <stdio.h>
#include "PRESENT_80.h"

/*
Present_80 encryption process has 31 rounds plus one final round, each round it uses 64bit round key 
IT has total of 32 rounds so total size will be 32*8=256
*/
unsigned char keyExpansion[256];
void Key_Expansion(unsigned char *EncryptionKey) {   
    //For circular shift instead of doing left shift of 61 bits .
    //I am doing the right shift of 19 bits.
    uint8_t key[10];
    memcpy(key,EncryptionKey,10);
    uint8_t temp[10];

    memcpy(keyExpansion,key,8); //first key is the leftmost 64 bits of the orginal key
    //SBOX with the top bits and XOR with a round counter
    //since each roundkey is 8 bytes long below offset is taken.
    for(int round=1; round<32; round++) {

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
        uint8_t top_bits = key[0] >>4;
        //apply sbox
        top_bits = sbox[top_bits];
        //clear top bits in key and putting the new top bits 
        //using 0x0f because in binary it is 00001111 so it keeps bottom bits and clear top bits
        key[0] = (key[0] & 0x0F) | (top_bits << 4);
        //we need to xor(as algorithm spficies) the bits in key[0] - 19 to 15 to give a unique stamp each round
        //It is used to break symmetry between rounds
        //key[7] - 23–16, key[8] - 15–8
        /*round >>1 - what is does is 
        round = abcde after the logic operation it becomes 0abcd now we have the upper four bits
        round = abcde after logic operation round & 1 → e and then after e<<7 e0000000 
        */
        key[7] ^= (round >>1);
        key[8] ^= (round & 0x01) << 7;
        //copying the key back to the keyExpansion
        memcpy(keyExpansion + (round*8),key,8);
    }

}
//Add round key
// XOR with Round Key
void addRoundkey(uint8_t State[8],int round) {
    for(int i=0; i<8; i++) {
        //We use the round multiplier to jump to the right 8-byte block,
        //then add 'i' to get the specific byte.
        State[i] ^= keyExpansion [(round*8)+i];
    }
}

//Sbox Layer
// 4-bit S-Box substitution
void sboxLayer(uint8_t State[8]) {
    for(int i=0; i<8; i++) {
        //get top four bits and get bottom four bits and combine them
        uint8_t top = State[i] >> 4;//shifts 7-4 to 3-0
        uint8_t bottom = State[i] & 0x0F; //mask out 7-4 bits
        top = sbox[top];
        bottom = sbox[bottom];
        top = top << 4;
        State[i] = top | bottom;
    }
}

//pLayer 
// Bit permutation
void pLayer(uint8_t State[8]) {
    uint8_t temp[8] = {0, 0, 0, 0, 0, 0, 0, 0}; //temporary state
    for (int i=0; i<64; i++) {
        //Finding bit position
        //The permutation formula: P(i) = (16 * i) % 63 (except for bit 63)
        int bit_pos = (16*i)%63;
        if(i==63) {
            bit_pos = 63;
        }
        //Finding the bit value
        //Bits are numbered 0-63 (0 is least significant bit of State[7])
        //To get bit i: byte index = 7 - (i / 8), bit position = i % 8
        uint8_t bit_val = (State[7 - (i / 8)] >> (i % 8)) & 0x01;
        //2. If the bit is 1, set the bit in the temp state at 'bit_pos'
        if (bit_val) {
            temp[7 - (bit_pos / 8)] |= (1 << (bit_pos % 8));
        }
    }
    // Copying the permuted state back to the original State array
    memcpy(State, temp, 8);
}

//For Encryption
void Encrypt(uint8_t State[8]) {
    for(int round = 0; round < 31; round++) {
        addRoundkey(State, round);  
        sboxLayer(State);           
        pLayer(State);              
    }
    //Final Round key
    addRoundkey(State, 31);
}
//For printing cypher text
void print(unsigned char State[8]) {
    printf("Ciphertext: ");
    for (int i = 0; i < 8; i++) { 
        printf("%02X", State[i]);
    }
    printf("\n");
}

int main() {

    //-------Plaintext 1--------
    Key_Expansion(EncryptionKey_1);
    Encrypt(Plaintext_1);
    print(Plaintext_1);
    //-------Plaintext 2--------
       
    Key_Expansion(EncryptionKey_2); // Must re-expand whenever the key changes
    Encrypt(Plaintext_2);
    print(Plaintext_2);
    //-------Plaintext 3--------
    
    Key_Expansion(EncryptionKey_3);
    Encrypt(Plaintext_3);
    print(Plaintext_3);
    //-------Plaintext 4--------

    Key_Expansion(EncryptionKey_4);
    Encrypt(Plaintext_4);
    print(Plaintext_4);
}
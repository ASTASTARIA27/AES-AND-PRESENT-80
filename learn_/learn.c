#include <stdio.h>
#include <stdint.h>

int main() {
    printf("Hello World\n");
    return 0;
}

/*
--------------Step 1:
The first operation in AES is the AddRoundKey. 
This is the only step that uses the security key directly in the round. 
It uses a bitwise XOR (⊕) operation between the current state and the subkey for that round.

Example:
If your state[0][0] byte is 0xAB and the corresponding roundKey byte is 0x55,
 what would be the resulting byte after the AddRoundKey transformation?

(Hint: Convert them to binary or use a calculator to find 0xAB ^ 0x55 in C).
result is XOR between them

0xAB = 10101011
0x55 = 01010101
result = 11111110

----------Step 2:(IMP)
Representing the State and subbyte transformation
1. The State: The 4×4 Grid

In AES, your 128-bit (16-byte) input is not treated as a long string. 
Instead, it is mapped into a 4×4 matrix of bytes called the State.
A critical detail for your code: the mapping is column-major. 
This means the first four bytes of your input fill the first column, 
the next four fill the second column, and so on.

Example:
If your Plaintext1 is 0123456789abcdeffedcba9876543210, it is mapped like this:
    | | Col 0 | Col 1 | Col 2 | Col 3 |
      | :--- | :--- | :--- | :--- | :--- |
| Row 0 | 01 | 89 | fe | 76 |
| Row 1 | 23 | ab | dc | 54 |
| Row 2 | 45 | cd | ba | 32 |
| Row 3 | 67 | ef | 98 | 10 |


 Gemini said

To implement AES-128 for your assignment, you must first master how data is organized and substituted. Since your assignment requires you personally code these algorithms without library calls, let's break down the logic step-by-step.
1. The State: The 4×4 Grid

In AES, your 128-bit (16-byte) input is not treated as a long string. Instead, it is mapped into a 4×4 matrix of bytes called the State.

A critical detail for your code: the mapping is column-major. This means the first four bytes of your input fill the first column, the next four fill the second column, and so on.

Example:
If your Plaintext1 is 0123456789abcdeffedcba9876543210, it is mapped like this:
| | Col 0 | Col 1 | Col 2 | Col 3 |
| :--- | :--- | :--- | :--- | :--- |
| Row 0 | 01 | 89 | fe | 76 |
| Row 1 | 23 | ab | dc | 54 |
| Row 2 | 45 | cd | ba | 32 |
| Row 3 | 67 | ef | 98 | 10 |


2. SubBytes: The Substitution Layer

The SubBytes transformation is a non-linear byte substitution. 
Every byte in the State is replaced by another byte using a fixed lookup table called the S-Box

How the S-Box Works

Think of the S-Box as a 256-element array where each index holds a specific replacement value.
    Input: A byte from your State (e.g., 0x12).
    Logic: Use that byte value as the index for the S-Box array.
    Output: The value stored at that index.

    Implementation Logic
In C, you would define the S-Box as a constant array:
const unsigned char sbox[256] = {
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    // ... (remaining 240 values)
};
To transform the entire State, you loop through every row and column:
state[row][col] = sbox[state[row][col]];


Practice Exercise
Let's use the actual data from your assignment requirements.
Scenario:

    Your Plaintext1 starts with the byte 0x01.

    Following the column-major rule, this byte sits at state[0][0].

    You look at the S-Box array: sbox[0] is 0x63, and sbox[1] is 0x7c.

Question: After the SubBytes step, what will be the new value of state[0][0]?
(Hint: Remember we are using the byte value as an index, not doing math!)
Would you like me to provide the full S-Box table so you can practice more lookups, 
or shall we move on to the Key Expansion logic?


------------------------STEP 3 :
 Shift rows"
A Quick Logic Check

If Row 1 of your state currently looks like this (in hex):
[0x23, 0x67, 0xab, 0xef]

What would that row look like after a left shift of 1 position? 
(Remember, the byte that "falls off" the left side wraps around to the right).
Answer : [0x67, 0xab,0xef,0x23] 

------------------------STEP 4:
The Third Gear: MixColumns 🧪

Now that the rows are scrambled, we need to mix the columns. This is the most mathematically complex part of AES.

In MixColumns, each column is treated as a four-term polynomial
We multiply each column by a specific fixed matrix. While the math involves "Galois Field" multiplication, for coding purposes, it boils down to two main rules for each byte:
    Multiplication by 01: The byte stays the same.
    Multiplication by 02: You shift the bits of the byte left by 1.
    If the bit that shifted out was a 1, you XOR the result with the hex value 0x1B.
    Multiplication by 03: This is just (02 XOR 01).

This step ensures that every byte in a column eventually influences every other byte in that column.4


Putting it together -     

Before we can run these 10 rounds, we need to prepare the keys. 
The original 128-bit key you are given isn't enough; we need a unique "Round Key" for each of the 10 rounds, plus one for the very beginning. This process is called Key Expansion.

If your starting key is 0f1571c947d9e8590cb7add6af7f6798, we need to expand it into a much longer list of words.

*/


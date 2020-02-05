#include <iostream>
#include <stdio.h>
#include <string.h>

// sbox found on Rijindael Sbox page on Wikepedia
unsigned char sbox[256] = {
    0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,
    0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0,
    0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,
    0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75,
    0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84,
    0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,
    0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8,
    0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2,
    0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,
    0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB,
    0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79,
    0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,
    0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A,
    0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E,
    0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
    0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16
};

// remote console
unsigned char rcon[256] = {0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36};

// every byte is replaced by the index of the sbox
void subBytes(unsigned char *block) {
    for (int i = 0; i < 16; i++) {
        std::cout << std::hex << (int)block[i];
    }
    std::cout << std::endl;
}

// state and round key are added using XOR (^=) and are added as Galois fields. All bits in the plaintext are added to the round key's respective bits
// memcpy copies the values of num bytes from the location pointed to by the expandedKey directly to the memory block pointed to by the roundKey
void addRoundKey(unsigned char *input, unsigned char *expandedKey, unsigned char *roundKey, int b) {
    memcpy(roundKey, expandedKey + b*16, 16);
    for (int i = 0; i < 4; i++){
        input[i*4] ^= roundKey[i*4];
        input[i*4+1] ^= roundKey[i*4+1];
        input[i*4+2] ^= roundKey[i*4+2];
        input[i*4+3] ^= roundKey[i*4+3];
    }
}

// the 4 bytes are treated as 1 block and are shifted by one to the left. When shifting from the first bit to the left, it ends up at the last bit. Then each of the bytes passed to the expandedkey are replaced by its respective value in the sbox
void circularShift(unsigned char *spot0, unsigned char *spot1, unsigned char *spot2, unsigned char *spot3) {
    unsigned char temp = *spot0;
    *spot0 = *spot1;
    *spot1 = *spot2;
    *spot2 = *spot3;
    *spot3 = temp;
}

// Byte Shift: Row 1 - unchanged, Row 2 -  shifts by 1, Row 3 - shift by 3
void shiftRows(unsigned char *word) {
    circularShift(&word[1], &word[5], &word[9], &word[13]);
    
    circularShift(&word[2], &word[6], &word[10], &word[14]);
    circularShift(&word[2], &word[6], &word[10], &word[14]);
    
    circularShift(&word[3], &word[7], &word[11], &word[15]);
    circularShift(&word[3], &word[7], &word[11], &word[15]);
    circularShift(&word[3], &word[7], &word[11], &word[15]);
}

// subs values in matrix when shifted
void subInMatrix(unsigned char *spot0, unsigned char *spot1, unsigned char *spot2, unsigned char *spot3) {
    *spot0 = sbox[*spot0];
    *spot1 = sbox[*spot1];
    *spot2 = sbox[*spot2];
    *spot3 = sbox[*spot3];
}

// matrix multiplication in Galois Field (2^8)
unsigned char galoisMult(unsigned char a, unsigned char b) {
    unsigned char result = 0;
    unsigned char high_bit = 0;
    
    for (int i = 0; i < 8; i++) {
        if (b & 1)
            result ^= a;
        
        high_bit = (a & 0x80);
        //bitwise left shift assignment
        a <<= 1;
        
        // prevents overflow and keeps value within range
        if (high_bit == 0x80)
            a ^= 0x1b;
        
        //bitwise right shift assignment
        b >>= 1;
    }
    
    return result;
}

// each column is processed separately and each byte is replaced by a value dependent on all 4 bytes in the column
// each column is treated as a four-term polynomial
void mixColumns(unsigned char *state0, unsigned char *state1, unsigned char *state2, unsigned char *state3) {
    
    unsigned char temp[4] = {*state0, *state1, *state2, *state3};
    
    *state0 = galoisMult(temp[0], 2) ^ galoisMult(temp[3], 1) ^ galoisMult(temp[2], 1) ^ galoisMult(temp[1], 3);
    *state1 = galoisMult(temp[1], 2) ^ galoisMult(temp[0], 1) ^ galoisMult(temp[3], 1) ^ galoisMult(temp[2], 3);
    *state2 = galoisMult(temp[2], 2) ^ galoisMult(temp[1], 1) ^ galoisMult(temp[0], 1) ^ galoisMult(temp[3], 3);
    *state3 = galoisMult(temp[3], 2) ^ galoisMult(temp[2], 1) ^ galoisMult(temp[1], 1) ^ galoisMult(temp[0], 3);
}

// takes 4 bytes from the keys generated from matrix multiplication and XOR the state of those 4 bytes
void expand(unsigned char *key, unsigned char *result) {
    
    for (int i = 0; i < 16; i++) {
        result[i] = key[i];
    }
    
    for (int i = 1; i < 11; i++) {
        result[i*16 + 0] = result[i*16 - 4 + 0];
        result[i*16 + 1] = result[i*16 - 4 + 1];
        result[i*16 + 2] = result[i*16 - 4 + 2];
        result[i*16 + 3] = result[i*16 - 4 + 3];
        
        circularShift(&result[i*16 + 0], &result[i*16 + 1], &result[i*16 + 2], &result[i*16 + 3]);
        subInMatrix(&result[i*16 + 0], &result[i*16 + 1], &result[i*16 + 2], &result[i*16 + 3]);
        
        result[i*16 + 0] ^= result[i*16 - 16 + 0] ^ rcon[i];
        result[i*16 + 1] ^= result[i*16 - 16 + 1];
        result[i*16 + 2] ^= result[i*16 - 16 + 2];
        result[i*16 + 3] ^= result[i*16 - 16 + 3];
        
        for (int j = 0; j < 12; j++) {
            result[i*16 + 4 + j] = result[i*16 + j] ^ result[i*16 - 12 + j];
        }
        
    }
    
}

// returns plaintext as ciphertext
void encryption(unsigned char *input, unsigned char *key){
    
    unsigned char expandedKey[176] = {0};
    unsigned char roundKey[16] = {0};
    
    expand(key, expandedKey);
    
    // round key is added before starting
    addRoundKey(input, expandedKey, roundKey, 0);
    
    // start (9 rounds))
    for (int i = 1; i < 10; i++) {
        // byte substitution
        for (int j = 0; j < 16; j+=4){
            subInMatrix(&input[j], &input[j+1], &input[j+2], &input[j+3]);
        }
        
        // shift rows
        shiftRows(input);
        
        // mix Coloumns
        for (int j = 0; j < 16; j+=4){
            mixColumns(&input[j], &input[j+1], &input[j+2], &input[j+3]);
        }
        
        // add round keys
        addRoundKey(input, expandedKey, roundKey, i);
    }
    
    // last cycle
    for (int j = 0; j < 16; j+=4){
        subInMatrix(&input[j], &input[j+1], &input[j+2], &input[j+3]);
    }
    
    shiftRows(input);
    
    addRoundKey(input, expandedKey, roundKey, 10);
    
}

int main(){
    
    // test case 1
    unsigned char text[16] =  {'L','o','s','A','n','g','e','l','e','s','L','a','k','e','r','s'};
    unsigned char key[16] = {'1','2','3','4','5','6','7','8','9','a','b','c','d','e','f','g'};
    
    std::cout << "Plaintext:\t"; subBytes(text);
    encryption(text, key);
    std::cout << "Key:\t\t"; subBytes(key);
    std::cout << "Ciphertext:\t"; subBytes(text);
    
    std::cout << "\n\n";
    
    
    // test case 2
    unsigned char text1[16] =  {'L','o','s','A','n','g','e','l','e','s','L','a','k','e','r','s'};
    unsigned char key1[16] = {'a','b','c','d','e','f','g','1','2','3','4','5','6','7','8','9'};
    
    std::cout << "Plaintext:\t"; subBytes(text1);
    encryption(text1, key1);
    std::cout << "Key:\t\t"; subBytes(key1);
    std::cout << "Ciphertext:\t"; subBytes(text1);
    
    return 0;
    
}

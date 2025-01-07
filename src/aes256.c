#include <stdint.h>
#include "aes256.h"

// Minimal AES256 implementation from Ref A : https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.197.pdf 
// and for Mix Columns : Ref B Gamal, Eslam & Shaaban, Eman & Hashem, Mohamed.
// (2009). Lightweight mix columns implementation for AES.  

/*
    Copyright (C) 2025 S Combes

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <https://www.gnu.org/licenses/>.
*/

// Aimed at 8 bit microcontroller (32 bit instructions would make it simpler)
// Should be safe for any endianism as is fully byte orientated.

// In order to minimise codesize/complexity only implements encryption (hence should create a stream 
// cipher via counter mode (https://en.wikipedia.org/w/index.php?title=Block_cipher_mode_of_operation&oldid=1263913846#Counter_(CTR)),
// which then encrypts/decrypts via xor)

// Uses minimal memory (e.g. key expansion overwrites the existing key - *** NOTE DESTROYS PROVIDED KEY *** )
// Uses xor whenever possible.

// TESTING.  Matches the test vectors in Ref A.

// Also compared with 1,000,000 ECB encryptions from python using random
// 256 bit key and random 128 bit 'plaintext'.  100% matches with 
// generated ciphertext.

// Sets of 1,000,000 ECB encryptions corrupted by forcing single bit high in key.
// As expected, typically 50% still match (as 50% chance bit was already high)
// And c25% when bit coerced high in both key and plaintext.

// Finally all single bits (256) in key were flipped (via XOR).  As expected, 
// now 0% match with expected ciphertext.
 
const uint8_t xorSBox[256]={0x63,0x7d,0x75,0x78,0xf6,0x6e,0x69,0xc2,0x38,0x08,0x6d,0x20,0xf2,0xda,0xa5,0x79,0xda,0x93,0xdb,0x6e,0xee,0x4c,0x51,0xe7,0xb5,0xcd,0xb8,0xb4,0x80,0xb9,0x6c,0xdf,0x97,0xdc,0xb1,0x05,0x12,0x1a,0xd1,0xeb,0x1c,0x8c,0xcf,0xda,0x5d,0xf5,0x1f,0x3a,0x34,0xf6,0x11,0xf0,0x2c,0xa3,0x33,0xad,0x3f,0x2b,0xba,0xd9,0xd7,0x1a,0x8c,0x4a,0x49,0xc2,0x6e,0x59,0x5f,0x2b,0x1c,0xe7,0x1a,0x72,0x9c,0xf8,0x65,0xae,0x61,0xcb,0x03,0x80,0x52,0xbe,0x74,0xa9,0xe7,0x0c,0x32,0x92,0xe4,0x62,0x16,0x11,0x06,0x90,0xb0,0x8e,0xc8,0x98,0x27,0x28,0x55,0xe2,0x2d,0x90,0x68,0x14,0x3c,0x51,0xf1,0xc7,0x21,0xd2,0x32,0xfc,0xe6,0xe8,0x4e,0x82,0xc4,0xcf,0xa0,0x5a,0x6c,0x82,0x8d,0xad,0x4d,0x8d,0x91,0x6f,0xdb,0x12,0xc2,0x90,0x4c,0x2e,0xf4,0xb6,0xe8,0xd0,0x97,0xfc,0xf0,0x10,0xdd,0x4f,0xb6,0xbf,0x06,0x1f,0xde,0x77,0x22,0x8f,0x42,0xc3,0x95,0x44,0x40,0x93,0x98,0xa9,0xed,0xa3,0x82,0xfb,0x6a,0x7a,0x06,0xc9,0x3d,0x38,0x4a,0xd6,0x57,0x79,0x85,0xde,0x39,0x60,0xf8,0x1e,0xd4,0xef,0x4e,0x51,0xd9,0xc7,0x10,0xb7,0x7a,0xb9,0xe7,0xed,0xd8,0x63,0x72,0x01,0x20,0x14,0xbe,0xd4,0x87,0x70,0x45,0x45,0xa0,0xef,0x67,0xb5,0x9c,0xd6,0x20,0xd9,0xb9,0xec,0x8d,0x62,0x5a,0x1c,0xc3,0x41,0x01,0x19,0x7a,0xf2,0x8d,0x3c,0x68,0x73,0x73,0xf7,0x6d,0x02,0x22,0xb8,0xc6,0x30,0x7c,0x50,0x7b,0xfe,0x4b,0x13,0xb4,0x9f,0xb9,0x60,0xd7,0xf4,0x4c,0xa9,0x45,0xe9};
// The xor to apply to convert i to sbox[i]
// -------------------------------------------------------------------------------
void RotWord(uint8_t * start) { 
// Byte rotation of word in place.  RotWord() in sect 5.3 of Ref A
  uint8_t temp=start[0];
  start[0]=start[1];  
  start[1]=start[2];  
  start[2]=start[3];  
  start[3]=temp;
}
// -------------------------------------------------------------------------------
void SubWord(uint8_t * start) { 
// Byte substitution of word in place.  SubWord() in sect 5.3 of Ref A
  start[0]^=xorSBox[start[0]];  
  start[1]^=xorSBox[start[1]];  
  start[2]^=xorSBox[start[2]];  
  start[3]^=xorSBox[start[3]];  
}
// -------------------------------------------------------------------------------
void XorRCon(uint8_t Nk,uint8_t * start) {
  *start^=(1<<((Nk>>3)-1)); 
  // For AES 256, RCon never exceeds 0x80, so no need for xor 0x1B. (Ref A A3)
}
// -------------------------------------------------------------------------------
void ExpandKey(uint8_t Nk,uint8_t * key) { // Ref A Fig 11 & A3
  // Must be called with consecutive Nk
  // Expands key in place, so key must be used by a round before next call
  
  // General principle - consider key to be 8 words of 32 bits, numbered 0,1...7
  // and in a cyclical arrangement (i.e. word 0 is after word 7)
  
  // Note that consecutive rounds of encryption used 128 bits of the key, flipping
  // from first half to second half and vice versa, at next round.  There are four
  // Nk steps between each round.
  
  // At every Nk, the relevant word of the key is xor'd with something based on the
  // previous word.  For most cases this is simply the previous word.
  // When word 0 of the key is updated, the xor is based on the preceding word 
  // after rotation; byte substitution; and xor with a round constant.
  // When word 3 is updated, the xor is based on the preceding word after byte
  // substitution.
  
  // Note that the 'round constant' is in fact only used on alternate rounds.
    
  if (Nk<8) return; // Leave key alone

  uint8_t temp[4]; // Last word of previous key, which is then mutated

  // Pointer to the start of the word from which we derive temp
  uint8_t * keySource=key+(((32-4)+(Nk<<2))&0x1F); // "-4 mod 32" = previous word
  // Pointer to the start of the word that we are about to change 
  uint8_t * keySink  =key+((Nk<<2)&0x1F); 

  temp[0]=keySource[0];
  temp[1]=keySource[1];
  temp[2]=keySource[2];
  temp[3]=keySource[3];

  if (Nk&0x07) { 
    if (!(Nk&0x03)) SubWord(temp); // Special step when Nk=4, 12, ...  (i.e. keySink is word 3 of key)  
    
  } else { // Special steps when Nk=8,16,...56 (i.e. keySink is word 0 of key)  
    RotWord(temp);
    SubWord(temp);
    XorRCon(Nk,temp);
  }
  keySink[0]^=temp[0];
  keySink[1]^=temp[1];
  keySink[2]^=temp[2];
  keySink[3]^=temp[3];
}
// -------------------------------------------------------------------------------
void SubBytes(uint8_t * state) {                  // Ref A 5.1.1
  for (uint8_t i=0;i<16;i++) state[i]^=xorSBox[state[i]];  
}
// -------------------------------------------------------------------------------
#define XORSWAP(A,B)(state[A]^=state[B],state[B]^=state[A],state[A]^=state[B]) 
// Unsafe if A=B, but we know A!=B

void ShiftRows(uint8_t * state) { 
// Must use same name as macro;   Ref A 5.1.2
// Not generic - hardcoded indices for AES256
  
                         // Ignore row 0
  
  uint8_t temp=state[1]; // Shift row 1
  state[1]=state[5];
  state[5]=state[9];
  state[9]=state[13];
  state[13]=temp;
  
  XORSWAP(2,10);         // Shift row 2
  XORSWAP(6,14); 
  
  temp=state[3];         // Shift row 3
  state[3]=state[15];
  state[15]=state[11];
  state[11]=state[7];
  state[7]=temp;
}
// -------------------------------------------------------------------------------
uint8_t xtime(uint8_t input) { // Ref A sect 4.2.1
  return (input&0x80)?(input<<1)^0x1B:(input<<1); 
}
// -------------------------------------------------------------------------------
void MixColumns(uint8_t * state) { // From Ref B Equation (4)
  for (uint8_t colBase=0;colBase<16;colBase+=4) {
    uint8_t * column=state+colBase;
    uint8_t temp=column[0];
    uint8_t xorOfCol=column[0]^column[1]^column[2]^column[3];
    
    column[0]^=(xtime(column[0]^column[1])^xorOfCol);
    column[1]^=(xtime(column[1]^column[2])^xorOfCol);
    column[2]^=(xtime(column[2]^column[3])^xorOfCol);
    column[3]^=(xtime(column[3]^temp)^xorOfCol); 
  }
}
// -------------------------------------------------------------------------------
void AddRoundKey(uint8_t * key,uint8_t * state) { // Ref A 5.1.4
  for (uint8_t i=0;i<16;i++) state[i]^=key[i];
}
// -------------------------------------------------------------------------------
void AES256_Encrypt(uint8_t * key,uint8_t * state) {
  // AES256 encryption of 16-byte state array via 32-byte key.
  // Returns result in state - *** hence overwrites input ***
  // Also *** overwrites key *** (to avoid large memory requirement for key expansion)
  
  // If key/input state need to be kept, caller must make a copy.
  
  AddRoundKey(key,state);

  for (uint8_t i=1;i<60;i++) {
    ExpandKey(i+4,key);

    if (!(i%8)) {
      SubBytes(state);    
      ShiftRows(state);    
      if (i!=56) { // Skip on last round
        MixColumns(state);
      }
      AddRoundKey(key,state);
    }
    if (!((i+4)%8)) {
      SubBytes(state);
      ShiftRows(state);
      MixColumns(state);
      AddRoundKey(key+16,state);    
    }
  }  
}
// ** No AES256_Decrypt provided **.  Would bloat code. Intent is that encrypt is used 
// with CTR mode to create a stream cipher that can encrypt/decrypt 

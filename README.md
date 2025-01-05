# Microcontroller-AES256
## AES256 minimal implementation designed for low memory and code size and 8-bit microcontroller use

Implementation from Ref A : https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.197.pdf and, for Mix Columns, Ref B Gamal, Eslam & Shaaban, Eman & Hashem, Mohamed. (2009). Lightweight mix columns implementation for AES.  

Aimed at 8 bit microcontroller (32 bit instructions would have made it simpler)

Should be safe for any endianism as is fully byte orientated.

In order to minimise codesize/complexity only implements encryption (hence should create a stream cipher via counter mode (https://en.wikipedia.org/w/index.php?title=Block_cipher_mode_of_operation&oldid=1263913846#Counter_(CTR)), which then encrypts/decrypts via xor)

Uses minimal memory (e.g. key expansion *** overwrites the existing key ***)

Uses xor whenever possible.

## TESTING.  

Matches the test vectors in Ref A.

Also compared with 1,000,000 ECB encryptions from python using random 256 bit key and random 128 bit 'plaintext'.  100% matches with generated ciphertext.

Sets of 1,000,000 ECB encryptions corrupted by forcing single bit high in key.
As expected, typically 50% still match (as 50% chance bit was already high) and c25% when bit coerced high in both key and plaintext.

Finally all single bits (256) in key were flipped (via XOR).  As expected, now 0% match with expected ciphertext.

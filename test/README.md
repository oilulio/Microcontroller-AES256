# Testing instructions


Compile and run as follows:
```
gcc -o aes256-Test ../src/aes256.c ../src/aes256-MainTest.c
./aes256-Test
Key expansion test from FIPS197 : PASS
Standard Encryption test from FIPS197 : PASS
405 Standard Encryption test vectors from FIPS : PASS

gcc -o aes256-ComparisonTest ../src/aes256.c ../src/aes256-ComparisonTest.c
./aes256-ComparisonTest
Encryption test 0 : PASS
Encryption test 1 : PASS
Successes = 2 out of 2
```
The 405 tests are relevant ones from https://web.archive.org/web/20091023001419/http://csrc.nist.gov/groups/STM/cavp/documents/aes/KAT_AES.zip
Specifically those in "ECBGFSbox256e.txt","ECBKeySbox256e.txt","ECBVarKey256e.txt","ECBVarTxt256e.txt" (copied here)

To generate tests of one's own, use ```python testGenerator.py``` 

Note that aes256-ComparisonTest must be compiled to expect the right number of tests



# After pip install pycrypto
# Generates test vectors of ECB encryptions in AES256 with 256 bit key, 16 byte PT and 16 byte CT

from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import codecs

for i in range(1000000):

    key = get_random_bytes(32)
    plaintext = get_random_bytes(16)
    cipher = AES.new(key, AES.MODE_ECB)
    ciphertext = cipher.encrypt(plaintext)
      
    # Prints hex key, followed by hex 'plaintext' and hex ciphertext as matching triple  
    print (codecs.encode(key, 'hex').decode(),codecs.encode(plaintext, 'hex').decode(),codecs.encode(ciphertext, 'hex').decode())

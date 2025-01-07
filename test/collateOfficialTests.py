# Formats  test vectors of ECB encryptions in AES256 as C-code, then added to MainTest.c
# Tests from https://web.archive.org/web/20091023001419/http://csrc.nist.gov/groups/STM/cavp/documents/aes/KAT_AES.zip
      
idx=1
for file in ["ECBGFSbox256e.txt","ECBKeySbox256e.txt","ECBVarKey256e.txt","ECBVarTxt256e.txt"]: # The ECB-encryption tests
    
    if (file[0:3]!="ECB"):
      continue # Must be an ECB test    
    
    with open(file) as f:
       data=f.readlines()
       
    if (data[0]!="[ENCRYPT]\n"):
      continue # Must be an encryption test
    
    i=0
    while (i < len(data)-3):
      while (i < len(data)-3 and data[i][0:8]!="COUNT = "):
        i=i+1
      key=data[i+1].rstrip().split(" ")[2]
      pt=data[i+2].rstrip().split(" ")[2]
      ct=data[i+3].rstrip().split(" ")[2]
      i=i+4
      
      # print (key,pt,ct) # This would create inputs to tests.txt if required
      
      print ("  uint8_t key"+str(idx)+"[32]={",end="")
      for j in range(32):
         print ("0x"+key[j*2:j*2+2],end=",")
      print ("};")

      print ("  uint8_t state"+str(idx)+"[16]={",end="")
      for j in range(16):
         print ("0x"+pt[j*2:j*2+2],end=",")
      print ("};")  
  
      print ("  AES256_Encrypt(key"+str(idx)+",state"+str(idx)+");")

      print ("  uint8_t target"+str(idx)+"[16]={",end="")
      for j in range(16):
         print ("0x"+ct[j*2:j*2+2],end=",")
      print ("};")
      
      print ("  pass=1;")
      print ("  for (int j=0;j<16;j++) pass&=(state"+str(idx)+"[j]==target"+str(idx)+"[j]);")
      print ('  printf(pass?"":"x");')
      print ("  allPass&=pass;")
        
      idx=idx+1

import os
import sys
from Crypto.Cipher import AES

#padding for AES_ECB encryption
pad = lambda s: s + (16 - len(s) % 16)*chr(16 - len(s)% 16)    

def encrypt_se(keyword, skprf, iv):
    """This function converts keyword to token"""
    #converting skprf to bytes from hex
    skprf = bytes.fromhex(skprf)

    #padding the keyword for AES block size
    keyword_kw = pad(keyword)
    obj = AES.new(skprf, AES.MODE_ECB, iv)

    #AES_ECB to generate token
    token_tk = obj.encrypt(keyword_kw)#token_tk will be in 'bytes'

    #converting ciphertxt into hexadecimal
    token_tk = token_tk.hex()
    print("Token is: ",token_tk)
    return token_tk
    
#argv[0] is program name
#argv[1] is keyword
#argv[2] is path of skprf file

keyword = sys.argv[1]
skprf_path = sys.argv[2]

#opening plaintext.txt
skprf_file = open(skprf_path,'r')
skprf = skprf_file.read()
#print ("PRF secret key is: ",skprf)

#--------------------
#opening file for writing token
token_file = open("../data/token.txt", "w")

#function call and writing token to a file
token = encrypt_se(keyword, skprf, "")#iv is null for AES ECB
token_file.write(token)

#closing token file
token_file.close()

import os

def key_gen(parameter):
    """This function generates random bytes of length given by parameter"""
    rndkey = os.urandom(parameter)
    return rndkey

#opening files for writing keys and iv
skprf_file = open("../data/skprf.txt", "w")
skaes_file = open("../data/skaes.txt", "w")
iv_file = open("../data/iv.txt","w")

#function call and convert to hex
#skprf and skaes are 32 bytes in length
skprf = key_gen(32).hex()
skaes = key_gen(32).hex()

#iv requires 16 bit key
iv = key_gen(16).hex()

print("Generated PRF key is:\n",skprf)
print("Generated AES key is:\n",skaes)
print("Generated IV for AES is:\n",iv)

#writing hexadecimal keys and iv to files
skprf_file.write(skprf)
skaes_file.write(skaes)
iv_file.write(iv)

#closing all files
skprf_file.close()
skaes_file.close()
iv_file.close()

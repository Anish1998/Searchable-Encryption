import os
import sys
from Crypto.Cipher import AES
import timeit

def unpad(s):
    """this function removes padding"""
    return "".join([i for i in s if ord(i)>31])

def decrypt_files(res_list, path, key, iv):
    """This function decrypts files and displays in plain text for each file given in the res_list"""
    str1 = "" #for data in res_list
    str2 = "" #for data in each file
    
    #generate str1 which has elements in res_list
    for j in res_list:
        str1 = str1 + j + " "
    str1 = str1 + "\n"

    #converting key,iv to bytes from hex
    key = bytes.fromhex(key)
    iv = bytes.fromhex(iv)
    
    #decryption for every file
    for f in res_list:
        #path of each file
        cipher_file_path = os.path.join(path, f)
        #opening each file
        with open(cipher_file_path, 'r') as fo:
            cipher_dec = fo.read()
            
        #convert ciphertext to bytes
        cipher = bytes.fromhex(cipher_dec)
        #decrypt the text
        obj = AES.new(key, AES.MODE_CBC, iv)
        plaintext = obj.decrypt(cipher)
        #function call to decode and remove padding
        plaintext = plaintext.decode('utf-8')
        plaintext = unpad(plaintext)
        #concate str1 and str2 to get final result
        str2 = str2 + f + " " + plaintext + "\n"
    #return result
    return(str1 + "\n" + str2)

def search_se(dict, token):
    """This function finds if a given token is in the inverted index"""
    if token in dict:
        return dict[token]
    else:
        print("Token Not Found")

#main
#argv[0] is program name
#argv[1] is path of enc inv index
#argv[2] is path of skaes file
#argv[3] is path of iv file
#argv[4] is path of token file
#argv[5] is path of cipher files = ..\data\ciphertextfiles
inv_ind_path = sys.argv[1]
skaes_path= sys.argv[2]
iv_path = sys.argv[3]
token_path = sys.argv[4]
files_path = sys.argv[5]

#opening token file, aes secret key file, iv file and result file
token_file = open(token_path, "r")
skaes_file = open(skaes_path, "r")
iv_file = open(iv_path, "r")
result_file = open("../data/result.txt","w")

#reading secret key, toke, iv and encrypted inverted index  from files
inv_ind = eval(open(inv_ind_path).read())
token = token_file.read()
skaes = skaes_file.read()
iv = iv_file.read()

#printing data
#print("Token is: ", token)
#print ("AES secret key is: ",skaes)
#print ("AES IV is: ",iv)

#starting timer
start = timeit.default_timer()

#function call to search in inverted index
search_res = search_se(inv_ind, token)

print("\n")
#function call to decrypt corresponding files
result = decrypt_files(search_res, files_path, skaes, iv)

#display result
print(result)

#write result to result.txt
result_file.write(result)

#end of timer
stop = timeit.default_timer()

#closing all opened files
token_file.close()
skaes_file.close()
iv_file.close()
result_file.close()

#print running time
print("\n Running Time: ", stop-start)
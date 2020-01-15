import os
import sys
from Crypto.Cipher import AES
import timeit

#padding for AES encryption
pad = lambda s: s + (16 - len(s) % 16)*chr(16 - len(s)% 16)

def f_to_c(f):
    """this function converts fi.txt to ci.txt; Ex: f1.txt to c1.txt"""
    str_num = ""
    for i in f:
        if i.isdigit():
            str_num = str_num + i
    cfile = "c" + str_num + ".txt"
    return cfile        

def encrypt_prf(keyword, skprf, iv):
    """This function encrypts a word with AES ECB"""
    #converting skprf to bytes from hex
    skprf = bytes.fromhex(skprf)

    #padding the keyword for AES block size
    keyword_kw = pad(keyword)
    obj = AES.new(skprf, AES.MODE_ECB, iv)

    #AES_ECB generate encrypted word
    token_tk = obj.encrypt(keyword_kw)#token_tk will be in 'bytes'

    #converting it into hexadecimal
    token_tk = token_tk.hex()
    #print("Token in hexadecimal is: ",token_tk)
    return token_tk

def ind_gen(dir):
    """This function generates plain inverted index for given files in a directory"""
    curr_dir = dir
    for root, _, files in os.walk(curr_dir):
        for f in files:
            abs_file_path = os.path.join(root, f)
            #opening each files
            with open(abs_file_path, 'r') as fo:
                message = fo.read()
            
            #splitting sentences to generate keywords
            list1 = message.split()
            #adding these values to plain index
            for i in list1:
                if i not in index_plain.keys():
                    index_plain[i]=list()
                    index_plain[i].append(f)
                else:
                    index_plain[i].append(f)
                    
def ind_to_inv_ind(dict):
    """This function generates encrypted inverted index for a given plain inverted index"""
    for i in dict:
        #print(i)
        #encrypts key with AES ECB
        inv_key=encrypt_prf(i, skprf, "") #iv is null for AES_ECB
        list2=[]
        for j in dict[i]:
            #function call to convert fi to ci
            list2.append(f_to_c(j))
        inv_ind[inv_key]=list2
            
def encrypt_files(dir, cdir, key, iv):
    """This function encrypts all files in a given directory
    and stores their corresponding cipher files in another given directory"""
    curr_dir = dir #directory of plain files
    root2 = cdir #directory for cipher files
    
    #converting key to bytes from hex
    key = bytes.fromhex(key)
    iv = bytes.fromhex(iv)
    
    #encryption for every file
    for root, _, files in os.walk(curr_dir):
        for f in files:
            abs_file_path = os.path.join(root, f)

            #function call to convert fi to ci
            cipher_file = f_to_c(f)
            cipher_file_path = os.path.join(root2, cipher_file)

            #opening files
            with open(abs_file_path, 'r') as fo:
                message = fo.read()
            
            #encrypt files and convert to hex
            message = pad(message)
            cipher = AES.new(key, AES.MODE_CBC, iv)
            enc_bytes = cipher.encrypt(message)
            ciphertxt = enc_bytes.hex()
            
            #write cipher to respective files
            with open(cipher_file_path, 'w') as fo:
                fo.write(ciphertxt)

def print_dict(dict):
    """this function prints the key and value pairs in a dictionary as strings"""
    for i in dict:
        str1 = i
        for j in dict[i]:
            str1 = str1 + " " + j
        print(str1)

#main
#argv[0] is program name
#argv[1] is path of skprf file
#argv[2] is path of skaes file
#argv[3] is path of iv file
#argv[4] is path of plaintext files = ..\data\files
#argv[5] is path of cipher files = ..\data\ciphertextfiles

skprf_path= sys.argv[1]
skaes_path= sys.argv[2]
iv_path = sys.argv[3]
files_path = sys.argv[4]
cipher_path = sys.argv[5]

#opening sk, iv files
skprf_file = open(skprf_path, "r")
skaes_file = open(skaes_path, "r")
iv_file = open(iv_path, "r")

#reading secret keys and iv from files
skprf = skprf_file.read()
skaes = skaes_file.read()
iv = iv_file.read()

#printing keys
#print ("PRF secret key is: ",skprf)
#print ("AES secret key is: ",skaes)
#print ("AES IV is: ",iv)

#starting timer
start = timeit.default_timer()

#function call to encrypt files
encrypt_files(files_path, cipher_path, skaes, iv)

#create two blank dictionaries
#one for plain inverted index and other for encrypted inverted index
inv_ind = {}
index_plain={}

#function call to generate plainindex
ind_gen(files_path)

#function call to convert plain index to encrypted index
ind_to_inv_ind(index_plain)

#end of timer
stop = timeit.default_timer()

#printing the inverted index
print("\nInverted Index is:\n")
print_dict(inv_ind)

#write inverted index to file as string format
inv_ind_file = open("../data/index.txt", "w")
inv_ind_file.write(str(inv_ind))
inv_ind_file.close()

#prnt running time
print("\nRunning Time: ", stop-start)
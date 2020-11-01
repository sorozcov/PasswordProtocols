# Universidad del Valle de Guatemala
# Cifrado de información 2020 2
# Grupo 7
# Implementation Scrypt Password.py

import scrypt
from passlib.utils import consteq
import Crypto.Random
random = Crypto.Random.new().read

#The algorithm includes the following parameters:

# Password      - The string of characters to be hashed.
# Salt          - A string of characters that modifies the hash to protect against Rainbow table attacks
# N             - CPU/memory cost parameter.
# p             - Parallelization parameter; a positive integer.
# r             - The blocksize parameter, which fine-tunes sequential memory read size and performance. 8 is commonly used.
# hLen          - The length in octets of the hash function (32 for SHA256).

Password = 'password'
Salt = random(32)
N = 14
p = 1
r = 8
hLen = 32
Hash = scrypt.hash(Password,Salt,1<<N,r,p,hLen)

print('\n','-'*40)
print('Password: ', Password)
print('Salt: ', Salt)
print('N: ', N)
print('p: ', p)
print('r: ', r)
print('Length of Hash: ', hLen)
print('Hash: ', Hash)
print('-'*40,'\n')

def verifyPassword( password ):
    newhash = scrypt.hash(password,Salt,1<<N,r,p,hLen)
    # We use a contstant-time comparison function from passlib.utils.consteq to mitigate timing attacks.
    if consteq(newhash,Hash):
        print("La contraseña '" + password + "' es correcta")
    else:
        print("La contraseña '" + password + "' es incorrecta")

verifyPassword('wrong password')
verifyPassword('password')
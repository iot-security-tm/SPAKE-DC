import socket
import hashlib
import os
import time
from fuzzy_extractor import FuzzyExtractor
import base64

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


# connection establishment
HOST = "192.168.100.101"
PORT = 8910
sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.connect((HOST, PORT))


# registration phase
IDu, PWDu, BIOu = "user123", "pass456", "bio789"
q = generate_random()
bio_bytes = hashlib.sha256(BIOu.encode()).digest()[:16]  # 16 bytes = 128 bits
extractor = FuzzyExtractor(16, 8)
delta_u, eta_u = extractor.generate(bio_bytes)

M1_reg_user = f"{IDu}"
sock.send(M1_reg_user.encode())


JIDu, Nu, IDd, Wm, PIDu = sock.recv(10240).decode("utf-8").split(",") # m2

RPWu = h(PWDu + q)
JIDu_prime = xor_bytes([JIDu.encode(), h(delta_u.hex() + IDu ).encode()])
Nu_prime = xor_bytes([Nu.encode(), h(PWDu + delta_u.hex()).encode()])
Id = xor_bytes([(IDd + Wm).encode(), h(IDu + PWDu + q).encode()])
Qu = (IDu + RPWu + delta_u.hex())


print("[#] Registration: Successful")
time.sleep(2)

############## main protocol 
# M1
bio_bytes = hashlib.sha256(BIOu.encode()).digest()[:16]
extractor = FuzzyExtractor(16, 8)
delta_u_prime = extractor.reproduce(bio_bytes, eta_u)

RPWu = h(PWDu + q)
Qu_check = (IDu + RPWu + delta_u_prime.hex())
if Qu_check != Qu:
    print("[-] Authentication failed.")
    exit()

JIDu = xor_bytes([JIDu_prime, h(delta_u_prime.hex() + IDu).encode() ]) # changed

Id_decoded = xor_bytes( [ Id , h(IDu + PWDu + q).encode() ]).decode("utf-8")
IDd, Wm = Id_decoded[:8], Id_decoded[8:]

Nu = xor_bytes([ Nu_prime, h(PWDu + delta_u_prime.hex()).encode()])

n1 = generate_random()
T1 = str(int(time.time()))
PIDu_new = generate_random()

Z1 = to_b64(xor_bytes([h(to_b64(JIDu) + T1).encode(), n1.encode()]))
Z2 = to_b64(xor_bytes([IDd.encode(), h(to_b64(Nu) + to_b64(JIDu) + T1).encode()]))
Z3 = to_b64(xor_bytes([h(n1 + to_b64(JIDu) + to_b64(Nu) + T1).encode(), PIDu_new.encode()]))
R1 = h(to_b64(JIDu) + IDd + n1 + T1)

M1 = f"{Z1},{Z2},{Z3},{R1},{PIDu},{T1}"

print("[+] M1 has been sent.")
time.sleep(1)
sock.send(M1.encode())

# M3
Z8, Z9, Z10, R3, T3 = sock.recv(10240).decode("utf-8").split(",")
Z8 = from_b64(Z8)
Z9 = from_b64(Z9)
Z10 = from_b64(Z10)
print("[+] M3 has been received.")


if int(time.time()) - int(T3) > 100:
    print("[-] Authentication faild")
    exit()

n3 = xor_bytes([ Z8 , h( to_b64(JIDu) + T3).encode() ]).decode("utf-8")
n2 = xor_bytes([ Z9 , h( IDd + T3).encode()  ]).decode("utf-8")
SK = h(to_b64(JIDu) + Wm + IDd + n1 + n2 + n3)
R3_prime = h(SK + IDd + to_b64(JIDu) + Wm + n1 + n3)

if R3 != R3_prime:
    print("[-] Authentication faild")
    exit()

PIDu_new = xor_bytes( [ h(to_b64(JIDu) + IDd + T3).encode() , Z10])

print("PID_new: ", to_b64(PIDu_new))
print("SK: ", SK)
print("[+] Protocol Completed Succesfully.")
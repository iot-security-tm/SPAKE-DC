import socket
import os
import hashlib
import time
import base64

def generate_random() -> str:
    return os.urandom(32).hex()

def h(data: str) -> str:
    return hashlib.sha256(data.encode()).hexdigest()

def xor_bytes(list_of_bytes):
    max_len = max(len(b) for b in list_of_bytes)

    result = bytearray(max_len)
    for i in range(len(result)):
        result[i] = list_of_bytes[0][i] if i < len(list_of_bytes[0]) else 0

    for b in list_of_bytes[1:]:
        for i in range(len(b)):
            result[i] ^= b[i]

    return bytes(result)

def from_b64(b64_str):
        return base64.b64decode(b64_str.encode('utf-8'))

def to_b64(bytes):
	return base64.b64encode(bytes).decode("ascii")

# connection establishment
HOST = "192.168.100.101"
PORT = 8910
sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.connect((HOST, PORT))



IDd = "droneABC"

# registration phase
Cm = generate_random()
Wm = h(Cm)

M1_reg = f"{Cm},{Wm},{IDd}"
sock.send(M1_reg.encode())

Nd = sock.recv(10240).decode("utf-8")


print("[#] Registration: Successful")

############## main protocol 
# M2
Z1, Z4, Z5, Z6, Z7, R2, T1, T2 = sock.recv(10240).decode("utf-8").split(",")
Z1 = from_b64(Z1)
Z4 = from_b64(Z4)
Z5 = from_b64(Z5)
Z6 = from_b64(Z6)
Z7 = from_b64(Z7)
print("[*] M2 has been received.")


# M3
if int(time.time()) - int(T2) > 100:
    print("[-] Authentication faild 666")
    exit()

JIDu = xor_bytes( [h(IDd+Nd+T2).encode(), Z6] )
n2 = xor_bytes( [h(IDd+Nd).encode(), Z4 ] )
Cm = xor_bytes( [Z7,  h(Nd + IDd + T2).encode()] )

R2_prime = h(IDd + Cm.decode("utf-8") + Nd + n2.decode("utf-8") + T2)

if R2 != R2_prime:
    print("[-] Authentication faild 888")
    exit()

n1 = xor_bytes( [h(to_b64(JIDu) + T1).encode() , Z1] )

n3 = generate_random()
T3 = str(int(time.time()))

Wm_prime = h(Cm.decode("utf-8"))

SK = h(to_b64(JIDu) + Wm_prime + IDd + n1.decode("utf-8") + n2.decode("utf-8") + n3)
Z8 = to_b64(xor_bytes([ h(to_b64(JIDu) + T3).encode(), n3.encode() ]))
Z9 = to_b64(xor_bytes([ h(IDd + T3).encode(), n2 ]))
PIDu_new = to_b64(xor_bytes( [h(Nd+IDd).encode() , Z5 ] ))
Z10 = to_b64(xor_bytes([ h(to_b64(JIDu) + IDd + T3).encode() , from_b64(PIDu_new) ]))
R3 = h(SK + IDd + to_b64(JIDu) + Wm_prime + n1.decode("utf-8") + n3)

M3 = f"{Z8},{Z9},{Z10},{R3},{T3}"

sock.send(M3.encode())
print("[*] M3 has been sent.")

print("PID_new: ", PIDu_new)
print("SK: ", to_b64(SK.encode()))
print("[+] Protocol Completed Succesfully.")
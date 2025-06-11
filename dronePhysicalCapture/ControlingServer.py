import time
import socket
import hashlib
import os
import base64

# helper functions
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

def generate_random() -> str:
    return os.urandom(32).hex()

# 
Kp = generate_random()

# connection settings
sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
host = '192.168.100.101'
port = 8910

try:
    sock.bind((host, port))
except socket.error as e:
    print(str(e))
    exit(0)

sock.listen(2)

# drone connection
print("[#] Connection Setting:")
print("\tDrone: ",end="",flush=True)
drone, drone_address = sock.accept()
print(f"Connected")

# drone registeration phase
M1_reg_drone = drone.recv(10240).decode('utf-8')
Cm, Wm, IDd = M1_reg_drone.split(",")
kd = generate_random()

Nd = h(IDd + kd + Kp)
M2_reg_drone = f"{Nd}"
drone.send(M2_reg_drone.encode())
print("\tDrone regestration: Successful")

# sending Nd to attacker
HOST_A = "192.168.100.105"
PORT_A = 8911
sock_a = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock_a.connect((HOST_A, PORT_A))
sock_a.send(M2_reg_drone.encode())

# user connection
print("\tUser: ", end="",flush=True)
user, user_address = sock.accept()
print(f"Connected")

# user registration phase
IDu = user.recv(10240).decode("utf-8")

ku = generate_random()
PIDu = h(IDu + ku)

JIDu = h(IDu + ku)

Nu = h(JIDu + ku + Kp)

JIDu_star = xor_bytes([JIDu.encode(), h(ku + Kp).encode()])

M2_reg_user = f"{JIDu},{Nu},{IDd},{Wm},{PIDu}"

user.send(M2_reg_user.encode())
print("\tUser regestration: Successful")

############## main protocol 
# M1
Z1, Z2, Z3, R1, PIDu, T1 = user.recv(10240).decode("utf-8").split(",")
Z1 = from_b64(Z1)
Z2 = from_b64(Z2)
Z3 = from_b64(Z3)

print("[*] M1 has been received.")

# M2
if int(time.time()) - int(T1) > 100:
    print("[-] Authentication faild")
    exit()

JIDu = xor_bytes([JIDu_star, h(ku + Kp).encode()])
n1 = xor_bytes([ h( to_b64(JIDu) + T1).encode(), Z1 ]).rstrip(b'\x00').decode('utf-8')

IDd = xor_bytes([ Z2 , h(to_b64(Nu.encode()) + to_b64(JIDu) + T1).encode() ]).rstrip(b'\x00').decode('utf-8')
R1_prime = h(to_b64(JIDu) + IDd + n1 + T1)

if R1 != R1_prime:
    print("[-] Authentication faild.")
    exit()

n2 = generate_random()
T2 = str(int(time.time()))

PIDu_new = xor_bytes( [h(n1 + to_b64(JIDu) + to_b64(Nu.encode()) + T1).encode(), Z3 ] )

Nd = h(IDd+kd+Kp)

Z4 = xor_bytes([n2.encode(), h(IDd + Nd).encode() ])
Z5 = xor_bytes([h(Nd + IDd).encode() , PIDu_new ])
Z6 = xor_bytes([JIDu , h(IDd + Nd + T2).encode() ])
Z7 = xor_bytes([Cm.encode() , h(Nd + IDd + T2).encode() ])

R2 = h(IDd + Cm + Nd + n2 + T2)
M2 = f"{to_b64(Z1)},{to_b64(Z4)},{to_b64(Z5)},{to_b64(Z6)},{to_b64(Z7)},{R2},{T1},{T2}"

drone.send(M2.encode())
print("[*] M2 has been sent.")

# sending m2 to attacker
sock_a.send(M2.encode())


# sending m3 from D to U
M3 = drone.recv(10240)
user.send(M3)


print("PID_new: ", to_b64(PIDu_new))
print("[+] Protocol Completed Succesfully.")

# sending m3 to attacker
sock_a.send(M3)


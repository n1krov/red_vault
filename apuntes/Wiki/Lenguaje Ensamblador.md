---
Tema: "[[wiki]]"
---

## ⚙️ Lenguaje Ensamblador y Llamadas al Sistema (Syscalls)

Estos conceptos de bajo nivel van fuertemente ligados a la **[[Arquitectura x86_64]]**.  
La base de la interacción con el kernel de Linux en ensamblador de 32 bits (x86) ocurre enviando la interrupción **`0x80`**.

---

### 📚 Registros Principales (Lectura/Escritura)

En la arquitectura x86, utilizamos varios registros Multipropósito de 32-bits que actúan como "variables" o contenedores a las que acede el procesador:

- `EAX` (Acumulador)
- `EBX` (Base)
- `ECX` (Contador)
- `EDX` (Datos)
- `ESP` (Stack Pointer - Puntero de Pila)

> [!tip] ¿Cómo funcionan las llamadas al sistema?
> Cuando ejecutas la interrupción `int 0x80`, el kernel lee qué hay exactamente dentro del registro `EAX` para saber **qué tipo de función** (syscall) quieres ejecutar.  
> Por ejemplo, si queremos ejecutar la syscall `sys_write` (escribir en pantalla), su identificador es el `4`.

Por lo tanto, la carga clásica se hace así:
```nasm
mov eax, 4  ; Le decimos al kernel que prepare una operación Write()
```

---

### 💻 Ejemplo Práctico: Hola Mundo en Ensamblador (x86)

El siguiente script define explícitamente y bloque por bloque cómo imprimir la cadena "Hola mundo\n" y luego salir limpiamente del programa.

```nasm
section .text
    global _start

_start:
    ; --- 1. PREPARACIÓN DE LA LLAMADA AL SISTEMA WRITE ---
    mov eax, 4      ; Syscall #4: sys_write
    mov ebx, 1      ; Descriptor de archivo (1 = STDOUT - Consola)
    
    ; --- 2. CARGA DEL MENSAJE EN LA PILA (Little-Endian) ---
    ; Los strings se empujan (push) al stack de atrás hacia adelante
    push 0x0a6f64    ; Push: "do\n"  (\n = 0x0a)
    push 0x6e756d20  ; Push: " mun" (con espacio)
    push 0x616c6f48  ; Push: "Hola"
    
    ; --- 3. PARAMETRIZACIÓN DEL PUNTERO Y LONGITUD ---
    mov ecx, esp    ; El inicio del mensaje ahora está en ESP, lo pasamos a ECX
    mov edx, 11     ; Longitud total del mensaje ("Hola mundo\n" = 11 bytes)
    
    ; --- 4. EJECUCIÓN ---
    int 0x80        ; Llamar a la interrupción del kernel
    
    ; --- 5. SALIDA LIMPIA (Graceful Exit) ---
    mov eax, 1      ; Syscall #1: sys_exit
    mov ebx, 0      ; Código de retorno (0 = Éxito)
    int 0x80        ; Llamar interrupción del kernel
```

---

### 🛠️ Compilación y Enlazado (Building process)

Para que el microprocesador pueda ejecutar este código necesitamos compilarlo con **[[nasm]]** a un formato de Objeto y enlazarlo con **[[ld]]**.

> [!info] ¿Qué es el formato ELF?
> **ELF** (Executable and Linkable Format) es el formato de archivo estándar para código ejecutable, bibliotecas compartidas (SO) y volcados de núcleo (core dumps) en sistemas tipo UNIX como Linux.

1. **Ensamblado (Assembling):** Compila el código a archivo objeto tipo ELF 32 bits.
   ```bash
   nasm -f elf code.asm
   ```
2. **Enlazado (Linking):** Vincula para crear el binario final ejecutable (`final`).
   ```bash
   ld -m elf_i386 -o final code.o
   ```

---

### 🔍 Desensamblado y Extracción de Shellcode

Una vez tenemos el binario final, podemos utilizar **[[objdump]]** para desensamblar y ver cómo quedó escrito el código a bajo nivel.

```bash
objdump -d final
```

Te devolverá una estructura visual similar a esto:
![[Pasted image 20260108100202.png]]

> [!example] ¿Cómo leer el formato de objdump?
> Las columnas representan lo siguiente:
> `[Dirección de Memoria]` : `[Bytes Hexadecimales (Opcodes)]` -> `[Instrucción ASM (nemónico)]`

Para el hacking (ej: creación de payloads/shellcodes), lo que realmente necesitamos son esos **bytes hexadecimales puros** que están en el medio.

#### 🧲 Extracción Mágica (One-Liner)

Esta línea de comando conjuga **[[grep]]**, **[[cut]]**, **[[tr]]** y **[[sed]]** para parsear la salida de `objdump` y aislar únicamente los Opcodes extra funcionales.

1. **Filtrar solo los Hex:**
   ```bash
   objdump -d final | grep "^ " | cut -f2 | tr -d ' ' | tr -d '\n'; echo 
   ```

2. **Formateo para Shellcode (`\x`):**
   ```bash
   printf '\\x' && objdump -d final | grep "^ " | cut -f2 | tr -d ' ' | tr -d '\n' | sed 's/.{2\}/&\\x/g' | head -c-3 | tr -d ' '; echo
   ```
   *Nota: Recuerda siempre revisar este output en busca de **nullbytes** (`\x00`) o badchars conocidos si este shellcode se usará en exploits.*

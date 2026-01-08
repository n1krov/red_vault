---
Tema: "[[wiki]]"
---

Embellecé y organizá mis apuntes de hacking en Obsidian usando Markdown (encabezados, listas, callouts, tablas, mermaid, bloques de código).  
Simplificá lo confuso, agregá ejemplos de comandos/técnicas. 
lo que este encerrado entre {indicaciones para LLM} son indicaciones para ti sobre lo que tienes que hacer en ese punto.
Respetá  OBLIGATORIAMENTE enlaces e imágenes.  
Objetivo: notas claras, técnicas y atractivas.  

Aqui va el texto:

---

esto va de la mano con [[Arquitectura x86_64]]
lo importante es que hay una instruccion que es la qeu se encarga de hacer las interrupciones el cual es -> `0x80`


### Registros de lectura

eax
ebx
ecx
edx
...

como se aplica:
- Cuando se aplique una interrupcion 80h, lo que va a hacer es leer a nivel de argumento(que tiene adentro) el registro eax, por lo que tienes que cargar ahi el tipo de lllamada que quieres hacer, en nuestro caso si queremos hacer un tipo write() es el 4
y eso se hace de la siguiente manera

```asm
mov eax, 4
```


a continuacion un hola mundo en asm

```asm
section .text
    global _start
_start:
    mov eax, 4  ; llamada al sistema de escritura
    mov ebx, 1  ; stdout
    ; esto va a estar en el tope de la pila, cabe aclarar que se escribe al revés dado que estamos trabajando con little-endian
    ; little-endian porque es de arquitectura x86
    push 0x0a6f64      ; "do\n"
    push 0x6e756d20  ; " mun"
    push 0x616c6f48  ; "Hola"
    mov ecx, esp  ; puntero al mensaje, la direccion del esp la pasamos a ecx
    mov edx, 11   ; longitud del mensaje
    int 0x80    ; llamada al sistema
    ; -- salir del programa
    
    mov eax, 1  ; llamada al sistema de salidaa
    mov ebx, 0 ; código de salida 0
    int 0x80    ; llamada al sistema
```

ahora utilizamos [[nasm]] para crear un archivo `.o` y de formato `elf` {que es elf??}
```sh
nasm -f elf code.asm
```

ahora para representar el binario final utillzamos [[ld]]

```sh
ld -m elf_i386 -o final code.o
```


adicionalmente se utiliza [[objdump]] para desensamblarlo

```sh
objdump -d final
```


mostrandote esto

![[Pasted image 20260108100202.png]]

muestra algo como esto {explicar}
numeros:    bytes bytes bytes bytes    instruccion   instruccion


lo importante son los bytes que estan en el medio que es lo qeu vamos a necesitar

se lo puede obtener de la siguiente manera
```sh
objdump -d final | grep "^ " | cut -f2 | tr -d ' ' | tr -d '\n'; echo 
```

ahora por cadenas de 2 meter un `\x`  (esto contiene posibles nullbytes o badchars)

```sh
objdump -d final | grep "^ " | cut -f2 | tr -d ' ' | tr -d '\n' | sed 's/.{2\}//'
```
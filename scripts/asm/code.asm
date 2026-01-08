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

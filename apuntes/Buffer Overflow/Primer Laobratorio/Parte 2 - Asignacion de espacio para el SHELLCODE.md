---
Tema: "[[Buffer Overflow]]"
---

Embellecé y organizá mis apuntes de hacking en Obsidian usando Markdown (encabezados, listas, callouts, tablas, mermaid, bloques de código).  
Simplificá lo confuso, agregá ejemplos de comandos/técnicas.  
Respetá enlaces e imágenes.  
Objetivo: notas claras, técnicas y atractivas.  

Aqui va el texto:

---

en la [[Parte 1 - Tomando control del registro EIP]] vimos que necesitabamos llenar el offset para llegar al registro EIP pero que pasa si pasamos el EIP y escribimos mas de la cuenta

estos datos se escriben en el stack y si logramos escribir instrucciones validaodos los caracs ahi podemos llegar a ejecutar nuestro shellcode 

el ESP apunta a la direccion actual de la "pila" donde estan los datos que hemos escrito y si logramos redirigir el EIP al ESP podremos ejecutar nuestro shellcode

la pila como tal es una estructura de datos LIFO (Last In First Out) que se utiliza para almacenar datos temporales, direcciones de retorno y variables locales durante la ejecución de un programa.

la idea con esto es hacer que el EIP apunte a una direccion que contenga un JMP (instruccion de salto) al ESP

problema: no todos los caracteres son interpretados correctamente por el programa vulnerable, algunos pueden ser filtrados o modificados, lo que puede impedir que el shellcode se ejecute correctamente. estos se conocen como "bad chars" y para cada programa pueden variar, por lo que se debe realizar un analisis para identificarlos como fuzzing.


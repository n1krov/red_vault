
### **¿Qué es CBC?**

CBC es un modo de operación para cifrar datos en bloques (como con AES). Es uno de los métodos más comunes para cifrar información de manera segura.

---

### **¿Cómo funciona?**

1. **Divide los datos en bloques**:  
   Los datos se dividen en bloques de tamaño fijo (por ejemplo, 128 bits).

2. **XOR con el bloque anterior**:  
   Cada bloque de texto plano se combina (usando XOR) con el bloque cifrado anterior antes de ser cifrado.  
   - Para el primer bloque, se usa un **vector de inicialización (IV)** en lugar del bloque anterior.

3. **Cifra el bloque**:  
   El resultado del XOR se cifra usando una clave secreta.

---

### **Ejemplo Visual**

```plaintext
Texto Plano: [Bloque1] [Bloque2] [Bloque3]
               ⊕         ⊕         ⊕
              IV       Cifrado1  Cifrado2
               |         |         |
            Cifrado -> Cifrado -> Cifrado
```

- **⊕**: Operación XOR.
- **IV**: Vector de Inicialización (aleatorio y único para cada cifrado).

---

### **¿Por qué es seguro?**

- **Aleatoriedad**: El IV asegura que dos mensajes iguales se cifren de manera distinta.
- **Propagación de errores**: Si un bloque se corrompe, solo afecta a ese bloque y al siguiente.

---

### **Problemas comunes**

4. **Ataque de Oráculo de Relleno**: Si el servidor revela errores de relleno, un atacante puede descifrar el mensaje.
5. **Velocidad**: No se puede paralelizar, ya que cada bloque depende del anterior.

---

### **Resumen**

- **CBC**: Cifra datos en bloques, combinando cada bloque con el anterior usando XOR.
- **Seguridad**: Usa un IV para asegurar aleatoriedad y evitar patrones.
- **Uso común**: En protocolos como TLS (HTTPS) para cifrar comunicaciones.

---

[[glosario]]
[[]]
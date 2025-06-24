

La vulnerabilidad **Local File Inclusion (LFI)** permite a un atacante acceder a archivos locales en el servidor web mediante la **manipulación de entradas de usuario** no validadas adecuadamente.  


## ¿Qué es Local File Inclusion (LFI)?

LFI es una vulnerabilidad en aplicaciones web que ocurre cuando el servidor incluye archivos locales sin validar correctamente la entrada del usuario. Esto permite a atacantes acceder a archivos sensibles del sistema, como configuraciones, contraseñas o incluso ejecutar código malicioso.

---

## ¿Cómo funciona un ataque LFI?

Generalmente ocurre cuando una aplicación web usa parámetros para incluir archivos, pero no valida estas entradas correctamente. Un atacante puede modificar el parámetro para apuntar a archivos no autorizados.

### Ejemplo básico

URL vulnerable:

```

[http://example.com/index.php?page=about](http://example.com/index.php?page=about)

```

Manipulación maliciosa:

```

[http://example.com/index.php?page=../../../../etc/passwd](http://example.com/index.php?page=../../../../etc/passwd)

```

### Técnica de Path Traversal

El atacante utiliza la secuencia `../` para subir niveles en la estructura de directorios y acceder a archivos del sistema, por ejemplo `/etc/passwd`.

### Inyección de código PHP o malicioso

En servidores que ejecutan PHP, se puede subir un archivo malicioso y luego incluirlo vía LFI para ejecutar comandos remotamente.

---

## Uso avanzado: Filter Chains en PHP

PHP permite el uso de "wrappers" y filtros para manipular archivos y datos. Esto puede facilitar la explotación de LFI para obtener información o ejecutar código.

### Ejemplo con cadena de filtros:

```

[http://example.com/index.php?page=php://filter/read=convert.base64-encode/resource=config.php](http://example.com/index.php?page=php://filter/read=convert.base64-encode/resource=config.php)

```

- `php://filter`: Wrapper que permite manipular flujos.
- `convert.base64-encode`: Codifica el contenido en Base64 para evitar problemas de visualización.

### Herramienta útil:

- **[PHP Filter Chain Generator](https://github.com/synacktiv/php_filter_chain_generator)**  
  Automatiza el uso de cadenas de filtros para explotar LFI y ejecutar comandos remotos.

---

## Impactos de un ataque LFI

- **Acceso a información sensible**: Archivos de sistema, registros, claves privadas.
- **Escalamiento de privilegios**: Uso de credenciales para acceso interno.
- **Ejecución remota de código (RCE)**: Mediante inclusión de archivos maliciosos.
- **Interrupción del servicio**: Corrupción o manipulación de archivos críticos.

---

## Mitigación de ataques LFI

1. **Validar entradas de usuario**  
   Utilizar listas blancas para restringir archivos permitidos.  
   Ejemplo en PHP:
```php
   $allowed_pages = ['about', 'contact', 'home'];
   if (in_array($_GET['page'], $allowed_pages)) {
       include($_GET['page'] . '.php');
   } else {
       die('Archivo no permitido');
   }
````

2. **Deshabilitar funciones peligrosas**  
    Configurar `php.ini` para desactivar `allow_url_include` y `allow_url_fopen`.
    
3. **Limitar permisos de archivos**  
    Ajustar permisos para proteger archivos sensibles.
    
4. **Registrar y monitorear actividad sospechosa**  
    Analizar logs para detectar intentos de Path Traversal o accesos anómalos.
    
5. **Cifrar datos sensibles**  
    Proteger archivos críticos mediante cifrado.
    

---

[[OWASP]]
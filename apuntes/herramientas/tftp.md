# 📡 TFTP: Trivial File Transfer Protocol

---

## 📝 Introducción

### ¿Qué es TFTP?

**TFTP (Trivial File Transfer Protocol)** es un protocolo de transferencia de archivos extremadamente simple, basado en UDP, que permite enviar y recibir archivos entre dispositivos en una red. No requiere autenticación ni cifrado, lo que lo hace rápido pero inseguro.

### ¿Para qué sirve?

- Transferir archivos de configuración o firmware a dispositivos de red (routers, switches, IoT)
- Arranque de sistemas sin disco (PXE Boot)
- Copia de archivos en entornos controlados o de laboratorio

### Contextos de uso en ciberseguridad

- **Post-explotación**: Exfiltración o carga de archivos en sistemas comprometidos
- **Red Team**: Transferencia rápida de payloads en redes internas
- **Auditoría de red**: Detección de servidores TFTP inseguros
- **Análisis forense**: Recuperación de archivos de dispositivos embebidos

---

## 🛠️ Guía Práctica Paso a Paso

### Sintaxis básica

```bash
tftp [opciones] <ip_servidor>
```

### Comandos interactivos

Una vez dentro del prompt de TFTP:

```bash
tftp> get <archivo_remoto> [archivo_local]   # Descargar archivo
tftp> put <archivo_local> [archivo_remoto]   # Subir archivo
tftp> quit                                   # Salir
```

### Comandos directos (no interactivo)

```bash
# Descargar archivo
tftp <ip_servidor> -c get <archivo_remoto> [archivo_local]

# Subir archivo
tftp <ip_servidor> -c put <archivo_local> [archivo_remoto]
```

> [!tip] Alternativa moderna:  
> En sistemas modernos, también podés usar `atftp` o `utftp` con sintaxis similar.

---

## ⚙️ Parámetros y Opciones Comunes

| Opción | Descripción | Ejemplo |
|--------|-------------|---------|
| `-c`   | Ejecuta un comando (get/put) | `-c get archivo` |
| `-m`   | Especifica el modo (octet, netascii) | `-m octet` |
| `-v`   | Modo verbose (detallado) | `-v` |
| `-l`   | Especifica archivo local | `-l archivo_local` |
| `-r`   | Especifica archivo remoto | `-r archivo_remoto` |

### Modos de transferencia

- **octet**: Binario (recomendado para archivos no texto)
- **netascii**: ASCII (para archivos de texto plano)

---

## 🎯 Casos de Uso Típicos

- **Descargar archivos de configuración** de routers/switches
- **Subir payloads** o scripts a sistemas comprometidos
- **Exfiltrar archivos** en post-explotación
- **Recuperar archivos** de sistemas embebidos o IoT

---

## 💻 Ejemplos Prácticos

### Ejemplo 1: Descargar un archivo de configuración

```bash
# Descargar config.txt desde el servidor TFTP
tftp 192.168.1.10 -c get config.txt
```

### Ejemplo 2: Subir un archivo malicioso (post-explotación)

```bash
# Subir shell.sh al servidor TFTP
tftp 192.168.1.10 -c put shell.sh
```

### Ejemplo 3: Usar TFTP en modo interactivo

```bash
tftp 192.168.1.10
tftp> get backup.cfg
tftp> put exploit.bin
tftp> quit
```

### Ejemplo 4: Automatizar transferencia de varios archivos

```bash
for file in passwd shadow hosts; do
    tftp 192.168.1.10 -c get $file
done
```

---

## ⚠️ Riesgos y Consideraciones de Seguridad

> [!warning] TFTP es INSEGURO por diseño
> - **Sin autenticación**: Cualquiera puede leer o escribir archivos
> - **Sin cifrado**: Todo el tráfico es en texto claro
> - **Sin control de acceso**: Puede ser explotado para exfiltración o carga de malware
> - **Uso limitado recomendado**: Solo en redes internas y controladas

### Ejemplo de ataque

```mermaid
flowchart TD
    A[Atacante] -- put shell.sh --> B[Servidor TFTP vulnerable]
    B -- shell.sh ejecutado --> C[Compromiso del sistema]
```

---

## 💡 Tips y Buenas Prácticas

> [!tip] Consejos para pentesters y administradores
> - **Buscar servidores TFTP expuestos** en auditorías de red (`nmap -sU -p 69 --script tftp-enum`)
> - **Limitar el acceso** a TFTP solo a hosts autorizados
> - **Deshabilitar TFTP** si no es estrictamente necesario
> - **Monitorear logs** de acceso a TFTP para detectar actividad sospechosa
> - **Usar TFTP solo para archivos no sensibles** y en entornos controlados

### Errores comunes y soluciones

| Error | Causa | Solución |
|-------|-------|----------|
| `Permission denied` | El servidor no permite escritura | Revisar permisos en el servidor |
| `Timeout` | Firewall bloquea UDP 69 | Abrir puerto o probar conectividad |
| `File not found` | Archivo no existe en el servidor | Verificar nombre y ruta |
| `Access violation` | Restricción de acceso en el servidor | Revisar configuración del servidor |

---

## 📊 Comparativa TFTP vs FTP vs SFTP

| Protocolo | Puerto | Transporte | Autenticación | Cifrado | Uso típico |
|-----------|--------|------------|---------------|---------|-----------|
| **TFTP**  | 69/UDP | UDP        | ❌            | ❌      | Boot, config, IoT |
| **FTP**   | 21/TCP | TCP        | ✅            | ❌      | Transferencia general |
| **SFTP**  | 22/TCP | TCP (SSH)  | ✅            | ✅      | Transferencia segura |

---

## 🔍 Detección y Enumeración

### Escaneo con Nmap

```bash
# Detectar servidores TFTP en la red
nmap -sU -p 69 --script tftp-enum 192.168.1.0/24
```

### Enumeración manual

```bash
# Listar archivos conocidos (si el servidor lo permite)
tftp 192.168.1.10 -c get /etc/passwd
tftp 192.168.1.10 -c get /etc/shadow
```

---

## 🧠 Resumen

- **TFTP** es un protocolo de transferencia de archivos simple y rápido, pero **muy inseguro**.
- Es útil en redes internas, arranque PXE y dispositivos embebidos, pero **no debe usarse en redes públicas**.
- Es un vector común de exfiltración y persistencia en post-explotación.

---

> [!success] Recuerda
> Si encontrás TFTP abierto en una auditoría, ¡es un objetivo prioritario para análisis y explotación!

[[protocolos]] [[post-explotacion]] [[enumeracion]]
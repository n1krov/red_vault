
# 📜 MD5sum: Verificación de Integridad de Archivos

## 📋 ¿Qué es MD5sum?

**MD5sum** es una utilidad de línea de comandos que calcula y verifica sumas de comprobación MD5 (Message Digest 5). Este algoritmo genera una "huella digital" o "hash" de 128 bits (16 bytes) de un archivo, que se representa típicamente como un número hexadecimal de 32 dígitos.

> [!info] Función principal
> La principal función de MD5sum es verificar la integridad de los archivos, asegurando que no hayan sido modificados o corrompidos durante su transferencia o almacenamiento.

## 🔍 Características principales

- Genera una secuencia de 32 caracteres hexadecimales única para cada archivo
- Detecta cambios incluso mínimos en los archivos
- Disponible en sistemas Unix/Linux y Windows (como parte de GNU Coreutils)
- Rápido y eficiente para verificación de integridad

## ⚠️ Consideraciones de seguridad

> [!warning] Limitaciones de seguridad
> MD5 **NO** se considera seguro para propósitos criptográficos o de seguridad. Ha sido comprometido y es vulnerable a ataques de colisión. Para verificaciones de seguridad, se recomienda usar algoritmos como SHA-256 o SHA-3.

## 🖥️ Uso básico de MD5sum

### Calcular el hash MD5 de un archivo

```bash
md5sum archivo.txt
```

### Calcular hash MD5 para múltiples archivos

```bash
md5sum archivo1.txt archivo2.txt archivo3.jpg
```

### Guardar hashes en un archivo

```bash
md5sum archivo1.txt archivo2.txt > checksums.md5
```

### Verificar la integridad de archivos

```bash
md5sum -c checksums.md5
```

## 🛠️ Opciones comunes

| Opción | Descripción |
|--------|-------------|
| `-b`, `--binary` | Lee archivos en modo binario (predeterminado en sistemas no Unix) |
| `-c`, `--check` | Verifica los MD5 sums contra la lista en un archivo |
| `-t`, `--text` | Lee archivos en modo texto (predeterminado en Unix) |
| `--status` | No muestra salida, útil para scripts |
| `-w`, `--warn` | Advierte sobre líneas de formato incorrecto |

## 📝 Ejemplos prácticos

### Ejemplo 1: Verificar una descarga

```bash
# Descargar un archivo
wget https://ejemplo.com/archivo.iso

# Verificar contra el hash proporcionado
echo "a52c3945b0bed61d9a710a363b8d0893 archivo.iso" > archivo.md5
md5sum -c archivo.md5
```

### Ejemplo 2: Verificar múltiples archivos en un directorio

```bash
# Generar hashes para todos los archivos .txt
md5sum *.txt > checksums.md5

# Verificar posteriormente
md5sum -c checksums.md5
```

## 🔄 Alternativas más seguras

Si necesitas mayor seguridad, considera usar:

- **SHA-256**: `sha256sum archivo.txt`
- **SHA-512**: `sha512sum archivo.txt`
- **SHA-1**: `sha1sum archivo.txt` (más seguro que MD5 pero también vulnerable)

---

## 🔗 Enlaces y recursos

- [Documentación oficial de GNU CoreUtils](https://www.gnu.org/software/coreutils/manual/html_node/md5sum-invocation.html)
- [RFC 1321 - Algoritmo MD5](https://tools.ietf.org/html/rfc1321)
- [[Verificación de integridad de datos]]
- [[Algoritmos de hash criptográficos]]

#herramientas #seguridad #línea_de_comandos #verificación_integridad



---

[[unix]]
[[apuntes/herramientas/herramientas]]
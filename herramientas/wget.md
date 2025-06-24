# 🛰️ `wget`

`wget` es una herramienta de línea de comandos para descargar archivos desde la web, soportando HTTP, HTTPS y FTP.

Ideal para:
- Automatizar descargas
- Bajar sitios enteros
- Recuperar archivos en pentests (ej: payloads, wordlists, reportes, etc.)

---

## 📌 Sintaxis básica

```bash
wget [opciones] <URL>
````

---

## 🔹 Ejemplos rápidos

### ▪ Descargar un archivo

```bash
wget http://ejemplo.com/archivo.txt
```

---

### ▪ Descargar y guardar con otro nombre

```bash
wget -O salida.txt http://ejemplo.com/archivo.txt
```

---

### ▪ Descargar múltiples archivos desde una lista

```bash
wget -i lista.txt
```

**Ejemplo de `lista.txt`:**

```
http://example.com/file1.txt
http://example.com/file2.txt
```

### 🧪 Verificá primero con `--spider`

Antes de hacer la descarga completa, podés probar con:
```sh
wget --spider -r -np --reject-regex 'venv/' http://192.168.0.5:8000/
```

### ✅ Opción: Excluir un directorio con `--reject-regex`

```sh
wget -r -np -nH --cut-dirs=0 --reject-regex 'venv/' http://192.168.0.5:8000/
```


---

## 🔸 Descarga recursiva

### ▪ Descargar un sitio o directorio entero

```bash
wget -r http://192.168.0.10:8000/
```

### ▪ Opciones recomendadas para scrapeo limpio:

```bash
wget -r -np -nH --cut-dirs=0 http://192.168.0.10:8000/
```

- `-r`: recursivo
- `-np`: no seguir a directorios padres
- `-nH`: no crear carpeta con nombre del host
- `--cut-dirs=N`: ignora **N** niveles del path

---

## 🛠️ Otras opciones útiles

|Opción|Descripción|
|---|---|
|`-c`|Reanudar descarga interrumpida|
|`--limit-rate=200k`|Limita la velocidad de descarga|
|`--user` y `--password`|Autenticación básica HTTP|
|`--no-check-certificate`|Ignora errores SSL (útil con HTTPS inseguros)|
|`--mirror`|Modo espejo: recursivo + timestamping|
|`--convert-links`|Convierte enlaces para navegación offline|
|`--user-agent="..."`|Cambia el agente de usuario HTTP|
|`--background`|Ejecuta en segundo plano|

---

## 📥 Ejemplo completo para pentesting

Supongamos que levantás un servidor en Kali con:

```bash
python3 -m http.server 8000
```

Y desde otra máquina descargás **todo** con:

```bash
wget -r -np -nH --cut-dirs=0 http://<IP>:8000/
```

---

## 🧠 Tips útiles

- Siempre usar `-c` para evitar repetir descargas grandes.
    
- Para evitar problemas con certificados en CTFs: `--no-check-certificate`
    
- Para navegar sitios offline: `--mirror --convert-links`
    

---

## 📚 Recursos

- `man wget`
    
- [https://www.gnu.org/software/wget/manual/](https://www.gnu.org/software/wget/manual/)
    

---

> 📌 _wget es una herramienta clave en cualquier pentest o entorno forense. Ligero, potente y automatizable._

---
[[herramientas]]
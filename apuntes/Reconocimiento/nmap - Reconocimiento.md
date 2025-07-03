
## 🛰️ Reconocimiento de Puertos con Nmap

### 🔍 Escaneo de todos los puertos TCP

```bash
nmap -p- --open -sS --min-rate 5000 -vvv -n -Pn <IP> -oG allPorts
```

#### 🔧 Explicación de los parámetros:

|Parámetro|Función|
|---|---|
|`-p-`|Escanea **todos los puertos TCP (1-65535)**.|
|`--open`|Reporta **solo los puertos que estén abiertos**.|
|`-sS`|Realiza un **escaneo SYN stealth**, más rápido y menos detectable. No completa el **three-way handshake** (envía `SYN`, recibe `SYN/ACK`, pero no responde con `ACK`).|
|`--min-rate 5000`|Fuerza a `nmap` a enviar **al menos 5000 paquetes por segundo**, útil para agilizar escaneos en redes lentas o sin IDS.|
|`-vvv`|**Triple verbose**: muestra información detallada en tiempo real.|
|`-n`|Evita la resolución DNS, **más rápido y silencioso**.|
|`-Pn`|**Desactiva la detección de host**, asumiendo que el objetivo está activo.|
|`-oG allPorts`|Exporta el resultado en formato **grepeable**, ideal para usar con herramientas como `extractPorts`.|

> 💡 Luego de este escaneo, utilizamos nuestra función personalizada `extractPorts` del `.zshrc` para extraer los puertos abiertos y copiarlos automáticamente al portapapeles.

---

### 🎯 Escaneo específico a puertos abiertos detectados

```bash
nmap -sC -sV -p <puertos> <IP> -oN targeted
```

#### 🔧 Explicación de los parámetros:

|Parámetro|Función|
|---|---|
|`-sC`|Ejecuta los **scripts por defecto de Nmap** (`default scripts`) para reconocimiento inicial.|
|`-sV`|**Detecta versiones de los servicios** que corren en los puertos abiertos.|
|`-p <puertos>`|Especifica los **puertos abiertos detectados previamente**.|
|`-oN targeted`|Guarda el resultado en **formato clásico de Nmap**, ideal para lectura manual.|

> 📝 También podés combinar los flags `-sC -sV` como `-sCV` para simplificar el comando.

#### Escaneo de puerto http 80

```sh
nmap -p80 --script=http-enum,http-title,http-headers,http-methods,http-robots.txt,http-server-header _ip_
```

### Escaneo de versiones de puertos

```sh
nmap -sV --version-all -p _puertos_ _IP_
```

##### De modo agresivo

```sh
nmap -A -p _puertos_ _IP_ 
```

---

[[reconocimiento]]
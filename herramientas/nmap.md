
# Total de puertos -> 65535


- **-p** : Especifica el puerto o rango de puertos a escanear (Ejemplo: -p 80, -p 80-443, -p 80,443,8080, -p- para todos los puertos)

- **--top-ports 500** : Escanea los 500 puertos mas comunes

- **-v** : Modo verbose

- **--open** : Muestra solo los puertos abiertos

- **-n** : No resuelve DNS

- **-T** : Modo de escaneo (0-5) 0: Paranoid, 1: Sneaky, 2: Polite, 3: Normal, 4: Aggressive, 5: Insane

- **-sT** : Escaneo de puertos TCP

- **-Pn** : No realiza el descubrimiento de hosts, es decir, no verifica si el host esta activo


---

## **Manual de Nmap: Parámetros y Explicación**

### **1. Escaneo de Puertos**
#### **`-p`**: Especificar puertos o rangos de puertos.
- **Ejemplo**: `nmap -p 80,443 192.168.1.1`
- **Descripción**: Escanea solo los puertos 80 (HTTP) y 443 (HTTPS) en el objetivo.

#### **`-p-`**: Escanear todos los puertos (1-65535).
- **Ejemplo**: `nmap -p- 192.168.1.1`
- **Descripción**: Escanea todos los puertos del objetivo.

#### **`--top-ports <n>`**: Escanear los `n` puertos más comunes.
- **Ejemplo**: `nmap --top-ports 100 192.168.1.1`
- **Descripción**: Escanea los 100 puertos más comunes.

---

### **2. Tipos de Escaneo**
#### **`-sS`**: Escaneo TCP SYN (medio abierto).
- **Ejemplo**: `nmap -sS 192.168.1.1`
- **Descripción**: Escaneo sigiloso que no completa la conexión TCP.

#### **`-sT`**: Escaneo de conexión TCP completa.
- **Ejemplo**: `nmap -sT 192.168.1.1`
- **Descripción**: Completa la conexión TCP (menos sigiloso que `-sS`).

#### **`-sU`**: Escaneo UDP.
- **Ejemplo**: `nmap -sU 192.168.1.1`
- **Descripción**: Escanea puertos UDP (útil para servicios como DNS, DHCP).

#### **`-sP`**: Escaneo de ping (solo verifica si el host está activo).
- **Ejemplo**: `nmap -sP 192.168.1.1`
- **Descripción**: Verifica si el host está activo sin escanear puertos.

#### **`-sV`**: Detección de versiones de servicios.
- **Ejemplo**: `nmap -sV 192.168.1.1`
- **Descripción**: Intenta determinar la versión del servicio que corre en cada puerto.

#### **`-O`**: Detección del sistema operativo.
- **Ejemplo**: `nmap -O 192.168.1.1`
- **Descripción**: Intenta identificar el sistema operativo del objetivo.

---

### **3. Opciones de Temporización**
#### **`-T<0-5>`**: Controlar la velocidad del escaneo.
- **Ejemplo**: `nmap -T4 192.168.1.1`
- **Descripción**: 
  - `-T0` (Paranoico): Muy lento, evita detección.
  - `-T1` (Sigiloso): Lento.
  - `-T2` (Educado): Moderado.
  - `-T3` (Normal): Predeterminado.
  - `-T4` (Agresivo): Rápido.
  - `-T5` (Insano): Muy rápido, puede ser detectado.

---

### **4. Evasión de Firewalls y Detección**
#### **`-f`**: Fragmentar paquetes.
- **Ejemplo**: `nmap -f 192.168.1.1`
- **Descripción**: Divide los paquetes en fragmentos más pequeños para evadir firewalls.

#### **`--data-length <n>`**: Agregar datos aleatorios a los paquetes.
- **Ejemplo**: `nmap --data-length 100 192.168.1.1`
- **Descripción**: Agrega 100 bytes de datos aleatorios a los paquetes.

#### **`-D <decoy1,decoy2,...>`**: Usar hosts señuelo.
- **Ejemplo**: `nmap -D 192.168.1.2,192.168.1.3 192.168.1.1`
- **Descripción**: Oculta tu dirección IP usando hosts señuelo.

#### **`--spoof-mac <MAC>`**: Falsificar dirección MAC.
- **Ejemplo**: `nmap --spoof-mac 00:11:22:33:44:55 192.168.1.1`
- **Descripción**: Falsifica la dirección MAC del escáner.

---

### **5. Escaneo de Redes**
#### **`-sn`**: Escaneo de ping sin escanear puertos.
- **Ejemplo**: `nmap -sn 192.168.1.0/24`
- **Descripción**: Escanea una red para encontrar hosts activos.

#### **`-PR`**: Escaneo ARP (útil en redes locales).
- **Ejemplo**: `nmap -PR 192.168.1.0/24`
- **Descripción**: Usa ARP para descubrir hosts en una red local.

---

### **6. Salida de Resultados**
#### **`-oN <archivo>`**: Guardar resultados en formato normal.
- **Ejemplo**: `nmap -oN resultado.txt 192.168.1.1`
- **Descripción**: Guarda los resultados en un archivo de texto.

#### **`-oX <archivo>`**: Guardar resultados en formato XML.
- **Ejemplo**: `nmap -oX resultado.xml 192.168.1.1`
- **Descripción**: Guarda los resultados en un archivo XML.

#### **`-oG <archivo>`**: Guardar resultados en formato "grepeable".
- **Ejemplo**: `nmap -oG resultado.grep 192.168.1.1`
- **Descripción**: Guarda los resultados en un formato fácil de procesar con `grep`.

#### **`-v`**: Aumentar verbosidad.
- **Ejemplo**: `nmap -v 192.168.1.1`
- **Descripción**: Muestra más detalles durante el escaneo.

#### **`-vv`**: Aumentar aún más la verbosidad.
- **Ejemplo**: `nmap -vv 192.168.1.1`
- **Descripción**: Muestra aún más detalles.

---

### **7. Scripts de NSE (Nmap Scripting Engine)**
#### **`-sC`**: Ejecutar scripts predeterminados.
- **Ejemplo**: `nmap -sC 192.168.1.1`
- **Descripción**: Ejecuta los scripts predeterminados de NSE.

#### **`--script <script>`**: Ejecutar un script específico.
- **Ejemplo**: `nmap --script http-title 192.168.1.1`
- **Descripción**: Ejecuta el script `http-title` para obtener el título de las páginas web.

#### **`--script-args <args>`**: Pasar argumentos a los scripts.
- **Ejemplo**: `nmap --script http-title --script-args http-title.url=/index.html 192.168.1.1`
- **Descripción**: Pasa argumentos al script `http-title`.

---

### **8. Escaneo Avanzado**
#### **`-A`**: Escaneo agresivo (detecta SO, versiones, scripts).
- **Ejemplo**: `nmap -A 192.168.1.1`
- **Descripción**: Combina detección de SO, versiones y scripts.

#### **`--traceroute`**: Realizar traceroute.
- **Ejemplo**: `nmap --traceroute 192.168.1.1`
- **Descripción**: Realiza un traceroute hacia el objetivo.

#### **`-Pn`**: Tratar todos los hosts como activos (omitir ping).
- **Ejemplo**: `nmap -Pn 192.168.1.1`
- **Descripción**: Omite la fase de ping y escanea directamente.

---

### **9. Escaneo de Vulnerabilidades**
#### **`--script vuln`**: Escanear vulnerabilidades.
- **Ejemplo**: `nmap --script vuln 192.168.1.1`
- **Descripción**: Ejecuta scripts de detección de vulnerabilidades.

---

### **10. Ejemplos Prácticos**
1. **Escaneo básico**:
   ```bash
   nmap 192.168.1.1
   ```

2. **Escaneo completo con detección de versiones y SO**:
   ```bash
   nmap -A 192.168.1.1
   ```

3. **Escaneo sigiloso de los 1000 puertos más comunes**:
   ```bash
   nmap -sS --top-ports 1000 192.168.1.1
   ```

4. **Escaneo de vulnerabilidades**:
   ```bash
   nmap --script vuln 192.168.1.1
   ```

---
[[herramientas]]
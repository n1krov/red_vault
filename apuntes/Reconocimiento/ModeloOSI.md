# Modelo OSI: Explicado a fondo con enfoque de red y seguridad

El **modelo OSI (Open Systems Interconnection)** es una referencia conceptual que divide la comunicación de redes en **7 capas**. Cada una cumple una función específica y depende de las inferiores para que la comunicación funcione de extremo a extremo.

En Red Team, entender este modelo te permite:

- Saber **dónde atacar**
    
- Identificar **vulnerabilidades específicas por capa**
    
- Usar mejor herramientas como Wireshark, tcpdump, netcat, nmap, etc.
    

---

## ⚙️ Las 7 capas del modelo OSI

---

## 🧷 **1. Capa Física (Physical Layer)**

### 🔌 Qué hace:

La capa física se encarga de la **transmisión real de bits** (1s y 0s) a través de un medio físico. No entiende protocolos, solo transmite señales: eléctricas, ópticas o electromagnéticas.

### 🧠 Elementos clave:

- Tipo de medio: cobre, fibra óptica, aire (RF)
    
- Señalización: amplitud, frecuencia, fase
    
- Topología física (bus, estrella, etc.)
    
- Tipo de modulación (PSK, QAM)
    
- Voltajes, sincronización de reloj
    

### 🔭 Ejemplos reales:

- Ethernet: envía pulsos eléctricos por UTP (RJ45)
    
- Wi-Fi: transmite paquetes vía ondas de radio en 2.4GHz o 5GHz
    
- Fibra óptica: usa pulsos de luz
    
- Hardware: cables, antenas, repetidores, switches (a nivel físico)
    

### ⚔️ Red Team:

- **Jamming Wi-Fi**: bloquear señales con interferencia (ej. `mdk4`, `wifijammer`)
    
- **Tapping de cableado**: insertar dispositivos para interceptar señales (ethernet/fibra)
    
- **Hardware keyloggers**: insertados entre teclado y PC
    
- **Ataques TEMPEST**: leer emisiones electromagnéticas pasivas (altamente avanzados)
    

---

## 🧱 **2. Capa de Enlace de Datos (Data Link Layer)**

### 🔧 Qué hace:

Gestiona la **comunicación directa entre dos nodos** conectados físicamente. Proporciona detección de errores y control de flujo básico. Trabaja con direcciones **MAC** (Media Access Control).

### 🧠 Subcapas:

- LLC (Logical Link Control): control lógico del enlace
    
- MAC (Media Access Control): acceso al medio y direccionamiento
    

### 📡 Ejemplos:

- **Ethernet (IEEE 802.3)**
    
- **Wi-Fi (IEEE 802.11)**
    
- Frame structure: preámbulo, dirección MAC origen/destino, datos, CRC
    

### ⚔️ Red Team:

- **Sniffing de tramas** con `Wireshark` o `airodump-ng`
    
- **Spoofing de MAC** para evadir filtros:
    
    ```
    macchanger -r wlan0
    ```
    
- **Ataques de desautenticación (deauth)**:
    
    ```
    aireplay-ng --deauth 10 -a <BSSID> -c <MAC_CLIENT> wlan0
    ```
    
- **ARP spoofing**: redireccionar tráfico local
    

---

## 🌍 **3. Capa de Red (Network Layer)**

### 🧭 Qué hace:

Encargada del **enrutamiento de paquetes** entre redes distintas. Usa direcciones IP y decide el mejor camino (routing). Aquí aparecen los conceptos de IP pública, privada, NAT, TTL, etc.

### 🧠 Protocolos clave:

- IP (v4 y v6)
    
- ICMP (ping, traceroute)
    
- Routing protocols: OSPF, BGP
    
- NAT (traducción de direcciones)
    

### 📦 Ejemplos:

- Tu PC con IP `192.168.0.5` manda un paquete a `8.8.8.8`
    
- El router decide cómo enrutarlo
    

### ⚔️ Red Team:

- **Escaneo de red con** `**nmap**`
    
- **ICMP redirect / ping flood**
    
- **IP spoofing** para evadir detección o envenenar rutas
    
- **DoS de red**: ICMP flood, IP fragmentation
    

---

## 📬 **4. Capa de Transporte (Transport Layer)**

### 📶 Qué hace:

Gestiona la **comunicación de extremo a extremo** entre procesos. Se encarga de dividir datos en segmentos, controlar errores y retransmisiones si es necesario.

### 🧠 Protocolos:

- **TCP**: confiable, orientado a conexión (handshake 3-way)
    
- **UDP**: sin conexión, rápido pero sin garantía
    

### 📦 Ejemplos:

- TCP: navegación web (HTTP), SSH, FTP
    
- UDP: DNS, SNMP, VoIP, juegos online
    

### ⚔️ Red Team:

- **Port scanning (SYN, FIN, ACK, Xmas scan)**:
    
    ```
    nmap -sS 192.168.0.1
    ```
    
- **Explotación de buffer overflows por TCP**
    
- **UDP flooding** (DoS)
    
- **Session reset attacks**
    

---

## 🧑‍💻 **5. Capa de Sesión (Session Layer)**

### 🤝 Qué hace:

Administra y mantiene **sesiones lógicas** entre aplicaciones. Controla apertura, duración y cierre de sesiones. Es crucial para sesiones persistentes.

### 📦 Ejemplos:

- **SSH**: mantiene la sesión entre cliente y servidor
    
- **VPNs (como L2TP, PPTP)**
    
- **SMB** en redes Windows
    

### ⚔️ Red Team:

- **Session Hijacking**: tomar control de una sesión activa (por MITM o token theft)
    
- **Man-in-the-Middle**: interceptar o manipular tráfico (ej. `Ettercap`, `Bettercap`)
    
- **Secuestro de sesión web**: cookies mal protegidas, tokens predecibles
    

---

## 🧬 **6. Capa de Presentación (Presentation Layer)**

### 🗣️ Qué hace:

Traduce y transforma los datos para que el receptor los entienda. Es responsable de **codificación, cifrado y compresión**.

### 📦 Ejemplos:

- Conversión de texto plano a UTF-8
    
- **SSL/TLS**: cifra datos antes de enviarlos (HTTPS)
    
- **Codificación base64**, gzip, etc.
    

### ⚔️ Red Team:

- **Ataques a TLS débiles** (POODLE, BEAST)
    
- **Manipulación de datos serializados** (`pickle`, `JSON` injection)
    
- **Downgrade de protocolos** (forzar HTTP en vez de HTTPS)
    
- **Explotar errores de descompresión** (zip bomb, etc.)
    

---

## 🖥️ **7. Capa de Aplicación (Application Layer)**

### 📲 Qué hace:

Es donde viven los **protocolos que interactúan directamente con el usuario** o con procesos de alto nivel. Gestiona peticiones de servicios como correo, navegación, DNS, etc.

### 📦 Protocolos comunes:

- HTTP/HTTPS
    
- FTP, SSH
    
- SMTP/IMAP (correo)
    
- DNS
    

### ⚔️ Red Team:

- **Explotación web**: SQL injection, XSS, LFI, RCE
    
- **Ataques a DNS**: spoofing, poisoning
    
- **Ingeniería social + phishing**
    
- **Explotación de servicios expuestos**: brute force SSH/FTP, explotación de CVEs conocidas (ej. Log4Shell)

---

## 🪜 Esquema general de capas con ejemplo práctico

|Capa|Nombre|Protocolo / Ejemplo|Ataques frecuentes|
|---|---|---|---|
|7|Aplicación|HTTP, FTP, DNS, SSH|XSS, SQLi, DNS spoofing|
|6|Presentación|SSL/TLS, JPEG, ASCII|TLS downgrade, tampering|
|5|Sesión|RPC, NetBIOS, PPTP|Session hijacking, MITM|
|4|Transporte|TCP, UDP|Port scan, DoS, fuzzing|
|3|Red|IP, ICMP|Ping flood, IP spoofing|
|2|Enlace de datos|MAC, ARP, 802.11|ARP spoofing, deauth Wi-Fi|
|1|Física|Wi-Fi, cable, radio, fibra|Jamming, sniffing físico|

---

## ✅ ¿Por qué es importante esto en hacking?

Porque te permite:

- **Analizar tráfico**: saber en qué capa actúa cada paquete (Wireshark te muestra todo de capa 1 a 7)
    
- **Atacar selectivamente**: ¿vas a interceptar un paquete (capa 2)? ¿o explotar una app (capa 7)?
    
- **Aplicar defensa y evasión**: por ejemplo, usar protocolos no comunes o canales cifrados.
    


---


[[reconocimiento]]
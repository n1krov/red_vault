
### 🧬 Definición básica

Una **red Wi-Fi** es una red inalámbrica que permite la comunicación de dispositivos (clientes) con un punto de acceso (Access Point o AP) sin usar cables, usando ondas de radio.

Wi-Fi se basa en un estándar de la IEEE (Institute of Electrical and Electronics Engineers) llamado:

## 📘 **IEEE 802.11**

---

### 📚 IEEE 802: Familia de protocolos

El estándar IEEE 802 es un conjunto de especificaciones para redes de área local (LAN). Dentro de 802, hay varias subdivisiones:

|Estándar|Descripción|
|---|---|
|802.3|Ethernet|
|802.11|Redes inalámbricas (Wi-Fi)|
|802.15|Bluetooth|
|802.1X|Autenticación en redes|

Entonces **802.11** es la especificación madre de todas las tecnologías Wi-Fi.

---

### 🧩 Subversiones de IEEE 802.11

IEEE 802.11 tiene muchas extensiones. Algunas claves:

|Versión|Año|Velocidad máx|Frecuencia|Notas|
|---|---|---|---|---|
|802.11b|1999|11 Mbps|2.4 GHz|Primer Wi-Fi comercial|
|802.11g|2003|54 Mbps|2.4 GHz|Muy común|
|802.11n|2009|600 Mbps|2.4/5 GHz|Primer dual-band|
|802.11ac|2013|1.3 Gbps|5 GHz|Alta velocidad|
|802.11ax (Wi-Fi 6)|2019|>10 Gbps|2.4/5/6 GHz|Eficiencia y rendimiento superior|

---

### 🔧 ¿Qué define IEEE 802.11?

Este estándar define cómo se transmite la información en una red inalámbrica:

- La **estructura de los paquetes** (tramas)
    
- Los **modos de operación** (infraestructura vs ad-hoc)
    
- Los **métodos de autenticación** y cifrado (WEP, WPA, WPA2, WPA3)
    
- Cómo se hacen las **asociaciones entre dispositivos**
    
- Cómo se maneja la **frecuencia**, **canales**, **interferencias**
    
- Cómo se gestiona el **acceso al medio** (CSMA/CA)
    

---

### 🛠️ ¿Por qué es importante para un Red Teamer?

Conocer bien 802.11 es esencial porque:

- Las herramientas como `airmon-ng`, `airodump-ng`, `aireplay-ng`, `bettercap`, `hcxdumptool` trabajan **al nivel 802.11**
    
- Puedes capturar y analizar tramas 802.11 para descubrir:
    
    - APs ocultos
        
    - Clientes conectados
        
    - Intenciones de conexión (probe requests)
        
- Podés **inyectar paquetes falsos**, como beacons o deauthentication
    
- Sabés qué tipos de ataques son posibles dependiendo del estándar usado:
    
    - WEP: crackeo de IVs
        
    - WPA/WPA2: handshake y crackeo con diccionario
        
    - WPA3: ataques de downgrade, side-channel, etc.
        

---

### 📡 Capas del modelo OSI en Wi-Fi

|Capa|Descripción|Ejemplo en Wi-Fi|
|---|---|---|
|1|Física|Frecuencia, modulación, canal|
|2|Enlace de datos (MAC)|Dirección MAC, BSSID, control de acceso al medio|
|3+|No es parte de IEEE 802.11 directamente|IP, TCP/UDP|

IEEE 802.11 cubre principalmente **capa 1 y 2**.

---

### 🕵️‍♂️ En herramientas prácticas

- **Wireshark** puede capturar y decodificar tramas 802.11 si tenés una tarjeta en modo monitor.
    
- **aircrack-ng suite** trabaja directamente con tramas 802.11:
    
    - `airodump-ng`: escucha beacons y probes
        
    - `aireplay-ng`: inyecta auth, deauth, etc.
        
- **hcxdumptool**: captura handshakes y PMKID a bajo nivel
    

---

### 🧠 Para que practiques

- Montá un entorno con una tarjeta Wi-Fi compatible con modo monitor (ej. Alfa AWUS036ACH)
    
- Activá el modo monitor:
    
    ```bash
    sudo ip link set wlan0 down
    sudo iw dev wlan0 set type monitor
    sudo ip link set wlan0 up
    ```
    
- Escaneá el aire:
    
    ```bash
    sudo airodump-ng wlan0
    ```
    
- Abrí Wireshark en esa interfaz, filtrá con:
    
    ```
    wlan.fc.type_subtype == 0x08  # beacon frames
    ```


---

[[index-wifi_security]]
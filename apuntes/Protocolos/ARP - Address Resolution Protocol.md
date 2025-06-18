### **¿Qué es ARP?**

**ARP (Address Resolution Protocol)** es un protocolo de red utilizado para mapear direcciones IP a direcciones físicas (MAC) en una red local (LAN). Es esencial para que los dispositivos puedan comunicarse dentro de una misma red.

---

### **Cómo funciona ARP**

1. **Dirección IP y MAC**:
    
    - Cada dispositivo en una red local tiene:
        - Una dirección **IP**: Identificación lógica (como 192.168.1.10).
        - Una dirección **MAC**: Identificación física única del hardware de red (como `00:1A:2B:3C:4D:5E`).
2. **Resolución ARP**:
    
    - Cuando un dispositivo necesita enviar datos a una dirección IP dentro de la misma red, pero no conoce la dirección MAC asociada, utiliza ARP para encontrarla.
    - El dispositivo envía una consulta **ARP Request** en broadcast (a todos los dispositivos de la red) preguntando:
        - _"¿Quién tiene la IP 192.168.1.10? Por favor, responde con tu dirección MAC."_
3. **Respuesta ARP**:
    
    - El dispositivo que tiene esa IP responde con un **ARP Reply**, enviando su dirección MAC.
4. **Tabla ARP**:
    
    - Para evitar realizar ARP constantemente, los dispositivos almacenan las direcciones IP y sus correspondientes MAC en una tabla ARP (una especie de caché local).

---

### **Ejemplo del proceso ARP**

- **Situación**: Tu computadora quiere enviar datos a 192.168.1.10.
    1. **ARP Request**:
        - Tu computadora envía: _"¿Quién tiene 192.168.1.10? Responde a 192.168.1.26 (mi IP)."_.
    2. **ARP Reply**:
        - El dispositivo con 192.168.1.10 responde: _"Yo tengo la IP 192.168.1.10. Mi MAC es 00:1A:2B:3C:4D:5E."_.
    3. **Comunicación**:
        - Tu computadora ahora sabe que para enviar datos a 192.168.1.10, debe usar la dirección MAC `00:1A:2B:3C:4D:5E`.

---

### **Características importantes de ARP**

- **Solo en redes locales (LAN)**:
    
    - ARP funciona únicamente en redes locales. En redes externas (WAN), los routers se encargan de la comunicación.
- **Broadcast inicial**:
    
    - Las solicitudes ARP se envían como broadcast (a toda la red).
- **Tabla ARP**:
    
    - Los dispositivos almacenan las direcciones en una tabla ARP para agilizar la comunicación.

---

### **Comando ARP en Linux**

- Ver la tabla ARP:
    
    ```bash
    ip neigh
    ```
    
    O con el comando antiguo:
    
    ```bash
    arp -a
    ```
    

---

### **Vulnerabilidades ARP**

1. **ARP Spoofing**:
    
    - Un atacante envía respuestas ARP falsas para redirigir tráfico hacia su dispositivo.
    - Se utiliza en ataques como el **Man-in-the-Middle (MitM)**.
2. **Falta de autenticación**:
    
    - ARP no tiene mecanismos para verificar la autenticidad de las respuestas.

---
[[glosario]] [[protocolos]]
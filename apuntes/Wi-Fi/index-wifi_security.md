# 📚 Plan de Estudio: Seguridad Wi-Fi y Hacking

## 🎯 Objetivo General
Adquirir conocimientos teóricos y prácticos sobre redes Wi-Fi, sus vulnerabilidades, herramientas de análisis, ataques controlados y medidas defensivas.

---

## 🧩 Módulo 1: Fundamentos de Redes Inalámbricas

[[modulo 1]]

🔹 Objetivo: comprender cómo funciona una red Wi-Fi a bajo nivel.

- [ ] [[¿Qué es una red Wi-Fi? IEEE 802.11]]
- [ ] [[Frecuencias - 2.4 GHz vs 5 GHz]]
- [ ] [[Canales y solapamiento]]
- [ ] Modos de funcionamiento: Infrastructure vs Ad-Hoc
- [ ] Tipos de paquetes: beacon, probe, auth, data
- [ ] MAC Address, BSSID, SSID

📌 Práctica:
- [ ] Capturar tráfico con `airodump-ng`
- [ ] Usar `Wireshark` para analizar paquetes 802.11

---

## 🔐 Módulo 2: Seguridad en Wi-Fi
🔹 Objetivo: aprender cómo se protege una red y cuáles son sus debilidades.

- [ ] Cifrado WEP: historia y vulnerabilidad
- [ ] WPA/WPA2-PSK y WPA3: handshake y cifrado AES
- [ ] WPS: funcionamiento y riesgos
- [ ] WPA-Enterprise (EAP/RADIUS): autenticación avanzada

📌 Práctica:
- [ ] Comparar configuraciones en routers reales o simulados
- [ ] Desactivar WPS, cambiar SSID, crear red oculta

---

## 🧪 Módulo 3: Sniffing y Captura de Handshakes
🔹 Objetivo: capturar tráfico de red inalámbrica y handshakes.

- [ ] Modo monitor y gestión de interfaces
- [ ] `airodump-ng`: escaneo de APs y clientes
- [ ] Captura de WPA2 handshake
- [ ] Recolección de handshakes válidos

📌 Práctica:
- [ ] `airodump-ng --bssid <bssid> -c <canal>`
- [ ] `aireplay-ng --deauth`

---

## 🔓 Módulo 4: Cracking de contraseñas Wi-Fi
🔹 Objetivo: aprender cómo se rompe una red con contraseñas débiles.

- [ ] Diccionarios: rockyou, seclists
- [ ] `aircrack-ng`
- [ ] `hashcat` (modo GPU)
- [ ] WPA2 vs WPA3 en cracking

📌 Práctica:
- [ ] Crackeo de handshake capturado con `aircrack-ng`
- [ ] Test de tiempos y efectividad

---

## 🎭 Módulo 5: Ataques Avanzados y Evil Twin
🔹 Objetivo: simular redes falsas y estudiar el comportamiento de clientes.

- [ ] Qué es un ataque *Evil Twin*
- [ ] Ingeniería social y phishing Wi-Fi
- [ ] `airbase-ng`, `wifiphisher`, `fluxion`

📌 Práctica:
- [ ] Crear AP falso
- [ ] Capturar intento de login de víctima

---

## 🧑‍💻 Módulo 6: Ataques MITM en Wi-Fi
🔹 Objetivo: interceptar tráfico real en una red Wi-Fi insegura

- [ ] MITM (Man in the Middle) básico
- [ ] Ataques ARP spoof + sniffing
- [ ] DNS spoofing
- [ ] Captura de credenciales HTTP

📌 Práctica:
- [ ] Usar `ettercap` o `bettercap`
- [ ] Simular intercepción con Wireshark

---

## 🛡️ Módulo 7: Defensa de redes Wi-Fi
🔹 Objetivo: aplicar lo aprendido para proteger redes reales

- [ ] Buenas prácticas de seguridad Wi-Fi
- [ ] Cambios en configuración del router
- [ ] Creación de red de invitados segura
- [ ] Segmentación y firewall

📌 Práctica:
- [ ] Implementar red segura con WPA2 + AES
- [ ] Monitoreo con `kismet` o `airodump-ng` pasivo

---

## 🏁 Módulo 8: Laboratorio Final
🔹 Objetivo: integrar todo lo aprendido

📌 Escenario:
- Simular red víctima
- Realizar escaneo, captura, deauth, handshake y crackeo
- Simular AP falso
- Implementar medidas de defensa

---

## 📦 Herramientas que vas a dominar

| Herramienta     | Uso principal                  |
|------------------|-------------------------------|
| `aircrack-ng`    | Captura y cracking de claves  |
| `airodump-ng`    | Escaneo y monitoreo           |
| `aireplay-ng`    | Inyección de paquetes         |
| `airbase-ng`     | Crear AP falso                |
| `Wireshark`      | Análisis de paquetes          |
| `hostapd`        | Crear Access Point            |
| `hashcat`        | Cracking por GPU              |
| `bettercap`      | MITM y DNS spoofing           |
| `wifiphisher`    | Ataques de phishing Wi-Fi     |


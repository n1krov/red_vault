## 🌐 TCP
**TCP (Transmission Control Protocol)** es un protocolo orientado a conexión.
### 🔹 Características principales
- Requiere establecer conexión antes de enviar datos (**Three Way Handshake**).
- Se utiliza ampliamente en Internet (web, email, SSH, etc.).
- Tiene **control de errores**.
- Garantiza que los datos:
    - Lleguen completos
    - Lleguen en orden
    - No se dupliquen

👉 Es más lento que UDP, pero mucho más confiable.

---
## 🚀 UDP
**UDP (User Datagram Protocol)** es un protocolo no orientado a conexión.
### 🔹 Características principales
- No establece conexión previa.
- No verifica si los datos llegaron correctamente.
- No garantiza orden ni integridad.
- Es más rápido que TCP.

👉 Se usa cuando la **velocidad es más importante que la precisión**, por ejemplo:

- Streaming
- Juegos online
- Consultas DNS

---
## 🤝 Three Way Handshake (TCP)
Es el proceso mediante el cual TCP establece una conexión confiable.

Secuencia:
1. **SYN** → El cliente solicita conexión.
2. **SYN-ACK** → El servidor responde aceptando.
3. **ACK** → El cliente confirma.

📌 Después de esto, comienza la transmisión de datos.

---
## 🔐 Puertos comunes (TCP)

| Puerto    | Servicio |
| --------- | -------- |
| 21        | FTP      |
| 22        | SSH      |
| 23        | Telnet   |
| 25        | SMTP     |
| 53        | DNS      |
| 80        | HTTP     |
| 110       | POP3     |
| 139 / 445 | SMB      |
| 143       | IMAP     |
| 443       | HTTPS    |

---
## 📡 Puertos comunes (UDP)

|Puerto|Servicio|
|---|---|
|53|DNS|
|69|TFTP|
|161|SNMP|

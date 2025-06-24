## ✉️ ¿Qué es SMTP?

**SMTP (Simple Mail Transfer Protocol)** es el **protocolo estándar para enviar correos electrónicos** a través de Internet.

- 📤 Se encarga de **TRANSFERIR** los correos desde el **cliente** o **servidor** de origen hacia el **servidor de destino**.
- ❌ **No** se usa para leer correos (eso lo hacen [[IMAP - Internet Message Access Protocol]] y [[POP3 - Post Office Protocol v3]]).
- 📬 También se usa para reenviar correos entre servidores.

---

### 🔧 ¿Cómo funciona SMTP?

1. Un cliente (por ejemplo, Thunderbird) **se conecta al servidor SMTP** para enviar un correo.
2. El servidor SMTP **encamina el correo** al servidor del destinatario.
3. Ese otro servidor lo entrega al **buzón del usuario**, desde donde luego será leído por IMAP o POP3.

---

### 📡 Puertos comunes de SMTP

| Puerto | Uso común                                | Descripción                         |
|--------|-------------------------------------------|-------------------------------------|
| 25     | Envío entre servidores (MTA a MTA)        | El más clásico, puede estar bloqueado en redes |
| 587    | Envío autenticado desde clientes (MUA)    | Para usuarios que mandan correos con login |
| 465    | SMTP seguro (con TLS implícito)           | Usado por algunos proveedores legacy |

---

### 💡 Ejemplo real

Cuando vos usás un correo en Thunderbird y hacés clic en "enviar", el mensaje va a través de **SMTP** al servidor.

Luego, el destinatario lo recupera usando **IMAP** o **POP3**.

---

### 🛡️ En seguridad

SMTP es un buen objetivo de análisis:

- 📛 **Fuerza bruta de credenciales**
- 🚪 **Relay abierto** (envía spam desde el server)
- 🔐 **TLS mal configurado**
- 🔍 **Fingerprinting de software (Postfix, Exim, Sendmail...)**

[[protocolos]]

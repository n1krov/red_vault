
# 🔐 Certificados SSL reutilizados en múltiples servicios

## 🧩 ¿Qué es un certificado SSL?

Un **certificado SSL/TLS** permite establecer una conexión **cifrada y autenticada** entre un cliente (navegador, cliente de correo, etc.) y un servidor.

Se compone de:
- Un **Common Name** (**CN**)
- Una lista de **Subject Alternative Names (SAN)**, que son dominios válidos
- Una clave pública y firma digital

---

## 🌐 Certificados reutilizados

Es **común y válido** que un certificado SSL se use en **múltiples servicios y puertos** del mismo servidor.

### ✅ Ejemplo real

```nmap
443/tcp open ssl/http
587/tcp open smtp (con STARTTLS)
993/tcp open imaps
````

En todos los casos, el certificado:

- CN: `chaco.gob.ar`
- SAN:
    - `chaco.gob.ar`
    - `*.chaco.gob.ar`
    - `*.chaco.gov.ar`
    - `mail.ecomchaco.com.ar`
    - `canalsomosuno.tv`        
    - ...


🔄 Este certificado es válido para **todos esos subdominios** y puede ser reutilizado por:

- Nginx (HTTPS)
- Postfix (SMTP sobre TLS)
- Dovecot (IMAP/POP3)

---

[[glosario]]

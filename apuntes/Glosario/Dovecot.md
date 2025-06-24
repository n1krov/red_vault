# 🐦 Dovecot

Dovecot es un **servidor de correo** de tipo **[[IMAP - Internet Message Access Protocol]] y [[POP3 - Post Office Protocol v3]]**. Su función principal es permitir que los usuarios **accedan a sus correos electrónicos** almacenados en el servidor.

## 📌 Función

- Entrega los correos a los usuarios cuando acceden por IMAP o POP3.
- También puede encargarse de la autenticación para SMTP (por ejemplo, en conjunto con Postfix).
- Administra los buzones y la seguridad del acceso a los correos.

## 🔧 Puertos relacionados

| Protocolo | Puerto estándar | Puerto seguro (SSL/TLS) |
|----------|------------------|--------------------------|
| IMAP     | 143              | 993                      |
| POP3     | 110              | 995                      |

## 🔐 Seguridad

- Compatible con SSL/TLS.
- Puede integrarse con PAM, LDAP, MySQL para autenticación.
- Soporta plugins para mejorar la seguridad (fail2ban, sieve, etc.).

## 📁 Ubicación común de configuración

```bash
/etc/dovecot/dovecot.conf
````

## 🛡️ Desde un enfoque ofensivo

- Intentar fuerza bruta de usuarios con `hydra`, `medusa` o `ncrack`.
    
- Detectar si los servicios están accesibles sin cifrado.
    
- Buscar credenciales en texto claro si hay errores de configuración.
    

[[glosario]]


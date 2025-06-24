📬 IMAP (Internet Message Access Protocol)

**IMAP** es un protocolo de correo electrónico que permite **ACCEDER y GESTIONAR mensajes almacenados en un servidor** desde múltiples dispositivos.

## 🔧 Características

- **No** descarga ni borra los correos por defecto.
- Todo se gestiona **directamente** en el servidor.
- Ideal para acceder desde varios dispositivos (móvil, PC, webmail).

## 🌐 Puertos comunes

| Puerto | Uso            |
|--------|----------------|
| 143    | IMAP sin cifrar |
| 993    | IMAPS (con SSL/TLS) |

## 🛠️ Comandos IMAP (básicos)

```txt
LOGIN usuario contraseña
LIST "" "*"
SELECT INBOX
FETCH 1 BODY[]
````

## 🔐 Seguridad

- Siempre usar IMAPS o STARTTLS.
- Comprobar si se aceptan conexiones sin cifrar.
- Monitorear logs de acceso y errores de autenticación.

## 🧪 En pentesting

- Enumeración de usuarios con `imap-user-enum`.
- Fuerza bruta con `hydra`, `medusa`.
- Explotación de servidores mal configurados (auth bypass, password reuse).

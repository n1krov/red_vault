## 🔐 ¿Qué es SSL?

**SSL** (Secure Sockets Layer) es una **tecnología de cifrado** que sirve para que los datos viajen **seguros** entre tu navegador (o cualquier cliente) y un servidor (como una web o correo).

### Hoy en día se usa **TLS**, que es la versión más moderna de SSL. Pero la mayoría sigue llamándolo "SSL" por costumbre.

## 🧠 ¿Para qué sirve?

- Evita que alguien **intercepte o lea** tus datos (por ejemplo, contraseñas, mails, etc.)
- Asegura que estás hablando con el **servidor correcto** (no un impostor)
- Hace que el navegador muestre 🔒 (candado seguro)

## 📦 ¿Cómo funciona?

1. El servidor (ej: `chaco.gob.ar`) tiene un **certificado SSL**
    
2. Cuando te conectás (por HTTPS, por ejemplo), tu navegador:
    
    - Verifica ese certificado
        
    - Si es válido y está firmado por una entidad confiable, se **establece una conexión cifrada**
        
3. A partir de ahí, **todo lo que enviás y recibís va cifrado**
    

---

## 🔍 Ejemplos reales

- 🌐 Web: HTTPS usa SSL/TLS → `https://chaco.gob.ar`
    
- 📧 Correo: puertos como `587` o `993` usan TLS/SSL para proteger mails (SMTP, IMAP)
    

---

## ✅ Resumen sencillo

> **SSL/TLS es lo que hace que Internet sea seguro.**  
> Protege tus datos con cifrado y asegura que estás hablando con el servidor correcto.


[[glosario]]
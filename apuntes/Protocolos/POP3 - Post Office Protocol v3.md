# 📥 POP3 (Post Office Protocol v3)

POP3 es un protocolo para **DESCARGAR correos electrónicos desde el servidor al cliente local**.

## 🧭 Características

- Los correos se descargan y, por defecto, **se borran del servidor**.
- Diseñado para conexión única desde un solo dispositivo.
- Poco flexible frente a IMAP, pero más simple.

## 🌐 Puertos comunes

| Puerto | Uso              |
|--------|------------------|
| 110    | POP3 sin cifrar  |
| 995    | POP3S (con SSL/TLS) |

## 🧠 Ventajas y desventajas

✅ Funciona bien con conexiones lentas  
✅ Requiere menos almacenamiento en servidor  
❌ No se sincroniza con múltiples dispositivos  
❌ Riesgo de pérdida de datos si no se respalda localmente

## 🛡️ Seguridad

- Asegurar el uso de cifrado (POP3S o STARTTLS).
- Evitar conexiones sin autenticación.
- Monitorear accesos desde múltiples IPs (posible abuso).

## 🧪 En pentesting

- Enumeración con herramientas como `pop3-brute` de Metasploit.
- Ataques de diccionario con `hydra`, `ncrack`, etc.
- Verificar errores de configuración (como dejar conexiones sin cifrar abiertas).

---

[[protocolos]]
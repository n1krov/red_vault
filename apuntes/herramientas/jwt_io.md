## 🌐 ¿Qué es [jwt.io](https://jwt.io/)?

[`jwt.io`](https://jwt.io/) es un **sitio web oficial mantenido por Auth0** que sirve para **visualizar, decodificar, firmar y verificar tokens JWT** (JSON Web Tokens) de forma rápida y sencilla.

---

### 🛠️ ¿Qué podés hacer en jwt.io?

| Funcionalidad                   | Descripción breve                                                         |
| ------------------------------- | ------------------------------------------------------------------------- |
| 🔍 **Decode (Decodificar)**     | Pegás un JWT y el sitio te muestra su **header**, **payload** y **firma** |
| 🧾 **Verificación de firma**    | Si le das la clave secreta o la pública, verifica si la firma es válida   |
| ✍️ **Crear tus propios tokens** | Podés crear un token de prueba completando los campos a mano              |
| 🧩 **Integraciones**            | Te muestra librerías JWT para distintos lenguajes (Python, Node, etc.)    |

---

### 🧪 Ejemplo rápido:

Un JWT tiene esta pinta:

```
eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9. 
eyJ1c2VybmFtZSI6ImFkbWluIiwicm9sZSI6ImFkbWluIn0. 
4Hg93kq6ztuN6mUOHb_Gg78a3VYFbPZpN6WB9qsWmE4
```

Cuando lo pegás en [jwt.io](https://jwt.io/), te lo separa así:

```json
Header:
{
  "alg": "HS256",
  "typ": "JWT"
}

Payload:
{
  "username": "admin",
  "role": "admin"
}

Signature:
HMACSHA256(...)
```

---

### 🎯 ¿Para qué se usa?

- Para **auditar tokens** si estás haciendo pentesting
    
- Para ver **datos expuestos en el payload**
    
- Para comprobar si la firma es **fácil de falsificar**
    
- Para probar vulnerabilidades tipo **alg=none**, etc.
    

---

[[apuntes/herramientas/herramientas]]
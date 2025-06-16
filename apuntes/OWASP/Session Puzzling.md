# 🧠 Ataque de Fijación de Sesión (Session Fixation) / Overloading

## 🧬 Teoría breve

**Session Fixation** es una vulnerabilidad en la que el atacante logra **fijar una sesión válida en el navegador de la víctima antes de que se autentique**, y luego secuestra esa sesión.

En su variante más moderna conocida como **Session Variable Overloading**, el atacante **manipula variables de sesión o cookies** para alterar la lógica de autenticación.

> 💡 El núcleo de ambos ataques es **controlar o predecir la sesión** de otro usuario.


## 🔐 ¿Cómo funciona?

1. El atacante crea una sesión válida ([[sesion prefijada]]) en el sitio.
2. Envía esa sesión (por link, cookie o header) a la víctima.
3. La víctima inicia sesión **sin saber que su sesión ya estaba fijada**.
4. El atacante reutiliza la misma sesión para hacerse pasar por ella.

### 🧪 Escenario: Ataque de Session Fixation contra un Admin

- 👨‍💻 **Atacante**: quiere acceder al panel de admin.
    
- 👑 **Admin (víctima)**: tiene una cuenta privilegiada.
    


### 🧩 Paso a paso del ataque:

1. 🧑‍💻 **El atacante visita el sitio**:
    - Va a `https://example.com`
    - El servidor le da una cookie:
		Set-Cookie: sessionid=XYZ123    
2. 🪤 **El atacante fija esa cookie para la víctima**:
    - Crea un link malicioso:
        ```
        https://example.com/?sessionid=XYZ123
        ```
    - O bien le envía un script XSS para forzar la cookie:
        ```js
        document.cookie = "sessionid=XYZ123";
        ```
3. 🧑‍💼 **El Admin entra al sitio usando ese enlace o ya con la cookie fijada**
    - Se loguea como `admin@example.com`
    - El servidor asocia el ID de sesión `XYZ123` a la cuenta **admin**
4. 🧠 **El atacante, que ya tenía `XYZ123`**, ahora la reutiliza
    - Va a `https://example.com` con su vieja cookie
    - ¡Y accede como **admin** sin haber sabido la contraseña!

### 🔥 Resultado:

> El atacante **secuestra la cuenta del admin** usando una sesión que **él mismo controlaba desde el principio**.


---

# 🧪 Parte Práctica – Lab OWASP SKF: `sessionpuzzle`

## 🚀 Despliegue del entorno

Primero descargamos la imagen:

```sh
docker pull blabla1337/owasp-skf-lab:sessionpuzzle
````

Luego la ejecutamos con port forwarding:

```sh
docker run -dit -p 127.0.0.1:5000:5000 blabla1337/owasp-skf-lab:sessionpuzzle
```

### ¿Qué significa cada opción?

- `-d` → detached (corre en segundo plano)
    
- `-i` → interactivo (mantiene entrada estándar abierta)
    
- `-t` → pseudo-TTY (simula terminal)
    
- `-p` → redirige el puerto `5000` de tu host al `5000` del contenedor
    

---

## 🌐 Acceso a la aplicación

Ingresá a la aplicación desde tu navegador:

```
http://localhost:5000/
```

> [!NOTE]  
> Este laboratorio simula un _Session Puzzle_ mediante **manipulación de cookies** (cookie tampering). Tu objetivo es **interactuar con el usuario y capturar/modificar su sesión**.

---

## 🧪 Prueba práctica con Burp Suite

1. Iniciá sesión como `admin : admin`.
    
2. Observá la cookie en el navegador:  
    `Ctrl+Shift+I` → pestaña `Application` → sección `Storage` → `Cookies`.
    
3. Podés interceptarla con Burp Suite o inspeccionar su estructura.  
    Si la cookie tiene **dos puntos (`.`)** probablemente sea un **JWT**.
    
4. Usá la herramienta web [[https://jwt.io|jwt.io]] para analizarla:
    
    - Pegás el token
        
    - Te muestra el header, payload y firma
        
    - Verificás si podés modificar el `payload` (por ejemplo, el campo `username` o `role`)
        

---

## 🧨 Posibles vectores de ataque

- Enviar un enlace malicioso con una sesión prefijada.
    
- Manipular directamente la cookie antes del login.
    
- Cambiar parámetros sensibles como `user`, `isAdmin`, etc., en el JWT.
    
- Si el servidor **no valida correctamente las cookies**, se puede asumir el rol de otro usuario.
    

## 🔒 ¿Cómo se previene?

|Medida|¿Por qué ayuda?|
|---|---|
|🔄 **Regenerar ID de sesión al login**|Invalida las cookies previas del atacante|
|🧼 **Invalidar sesiones viejas**|Evita que sigan activas luego del login|
|🔐 **Cookies con atributos seguros**|Protege contra fijaciones y lecturas vía JS|
|❌ **No aceptar sesión desde parámetros GET**|Evita ataques vía enlaces|

---

## 📚 Referencias
- [[OWASP Session Fixation]](https://owasp.org/www-community/attacks/Session_fixation)
- [[jwt.io – JSON Web Token Debugger]](https://jwt.io)
- [[OWASP SKF Labs]](https://owasp-skf.gitbook.io/)
## 📌 Tags

#sessionfixation #websecurity #cookie #jwt #owasp #burpsuite #pentesting #securitylabs #docker

[[OWASP]]
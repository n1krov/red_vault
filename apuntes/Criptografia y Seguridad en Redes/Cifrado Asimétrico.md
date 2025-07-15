# 🔐 Cifrado Asimétrico

> A diferencia del cifrado simétrico, el **cifrado asimétrico** utiliza **dos claves diferentes**: una pública y una privada.

---

## 🧠 Fundamento clave

Cada usuario tiene:

- 🔓 **Clave pública**: se comparte libremente.
    
- 🔐 **Clave privada**: se guarda en secreto.
    

Lo importante es:

- **Lo que se cifra con una clave solo puede descifrarse con la otra.**
    
- Si cifrás con la **clave pública** de alguien, **solo esa persona** (con su clave privada) puede leerlo.
    

---

## 🔁 ¿Cómo funciona?

```mermaid
sequenceDiagram
    participant Emisor
    participant Receptor

    Emisor->>Receptor: Pide la clave pública
    Receptor-->>Emisor: Envía su clave pública
    Emisor->>Emisor: Cifra el mensaje con la clave pública del receptor
    Emisor->>Receptor: Envía mensaje cifrado
    Receptor->>Receptor: Descifra con su clave privada
```

---

## 🧪 Ejemplo práctico

Queremos enviar `HOLA MUNDO` a un receptor.

1. Pedimos su clave pública.
    
2. Ciframos el mensaje con esa clave.
    
3. Le enviamos el texto cifrado.
    
4. Solo el receptor, con su **clave privada**, puede descifrarlo.
    

Esto garantiza **confidencialidad**, incluso si el mensaje es interceptado.

---

## 🔑 ¿Cómo son las claves?

Son pares generados matemáticamente. Ejemplo de pares:

```
Clave pública: -----BEGIN PUBLIC KEY----- ...
Clave privada: -----BEGIN PRIVATE KEY----- ...
```

---

## 🛠️ Algoritmos populares

|Algoritmo|Seguridad|Comentario breve|
|---|---|---|
|RSA|Alta|Muy usado, pero más lento.|
|ECC|Alta|Más eficiente, curva elíptica.|
|ElGamal|Alta|A veces en sistemas académicos.|

---

## ✅ Ventajas

- No hay que compartir secretos: la clave pública puede difundirse libremente.
    
- Escala bien: solo necesitás tu propio par de claves.
    

## ❌ Desventajas

- Mucho más lento que el cifrado simétrico.
    
- Más complejo de implementar correctamente.
    

---

## 📐 Comparativa: Simétrico vs Asimétrico

```mermaid
graph TD
  S[🔒 Simétrico] -->|Misma clave| S1[Cifrado y descifrado]
  A[🔐 Asimétrico] -->|Claves distintas| A1[Cifrado y descifrado]
  S --> S2[Rápido ⚡]
  A --> A2[Lento 🐢]
  S --> S3[Difícil de escalar 🔺]
  A --> A3[Fácil de escalar 🟢]
```


[[criptografia_seguridad en redes]]
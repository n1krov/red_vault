# Definición

> Es **una sesión que el atacante crea de antemano** y luego se la hace usar a la víctima.

---
### 🔁 Flujo del ataque paso a paso

1. 🧑‍💻 **El atacante visita el sitio web** normalmente y **recibe un ID de sesión válido** del servidor:  
    `Set-Cookie: sessionid=ABC123`
    
2. 👨‍🎓 **Antes de que la víctima se autentique**, el atacante le **fuerza esa misma sesión**. ¿Cómo?
    
    - Enviándole un link con esa sesión embebida
        
    - Mediante un XSS
        
    - O manipulando directamente la cookie en su navegador
        
3. 🧑‍💼 **La víctima entra al sitio con esa cookie prefijada** (`sessionid=ABC123`) y se loguea.
    
4. 🎯 Ahora **el servidor asocia esa sesión (`ABC123`) con la cuenta de la víctima**.
    
5. 💀 El atacante, que ya tenía la cookie, **simplemente la reutiliza para acceder a la cuenta víctima**.
    

### 📦 ¿Dónde está el "truco"?

El truco está en que **el servidor no invalida ni cambia el ID de sesión cuando el usuario se loguea**.

> Eso permite que una **sesión preexistente y controlada por el atacante** se convierta en la sesión legítima de la víctima.

---

### 🎯 ¿Por qué es peligroso?

Porque el servidor **no cambia la cookie al momento del login**. Entonces **la sesión “vieja” del atacante se convierte en una sesión válida y autenticada**.

---

### 🛡️ ¿Cómo se evita?

- Haciendo que el servidor **genere una nueva sesión al iniciar sesión**.
    
- Usando cookies con atributos `HttpOnly`, `Secure`, `SameSite`.
    

[[glosario]]
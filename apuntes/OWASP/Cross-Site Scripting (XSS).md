
---

### **Cross-Site Scripting (XSS)**

#### **Definición**

XSS es una vulnerabilidad que permite a un atacante ejecutar código malicioso en el navegador del usuario. Este código puede:

- Robar información confidencial (como cookies, sesiones, contraseñas).
- Redirigir a usuarios a sitios maliciosos.
- Registrar interacciones del usuario en el navegador.

#### **Tipos de XSS**

1. **Reflejado (Reflected)**:
- El código malicioso se envía como parte de una solicitud (ej., URL).
- El servidor refleja la entrada sin validación.
- Ejemplo: Un enlace malicioso enviado a la víctima, como:

```html
http://vulnerable.com/search?q=<script>alert('XSS')</script>
```

2. **Almacenado (Stored)**:
- El atacante guarda el código malicioso en el servidor (en una base de datos, comentarios, etc.).
- Cada vez que los usuarios acceden al recurso afectado, el código se ejecuta.
- Ejemplo: Un script malicioso insertado en un campo de comentarios.

3. **Basado en DOM (DOM-Based)**:
- El ataque ocurre directamente en el navegador mediante modificaciones al DOM.
- El servidor no está involucrado directamente.
- Ejemplo: Una aplicación web que lee datos del `location.hash` y los usa sin sanitizar.

---

### **Práctica**

1. **Repositorio de aprendizaje**:  
    Usa [secDevLabs](https://github.com/globocom/secDevLabs) para montar laboratorios específicos sobre XSS. Este proyecto ofrece entornos controlados para aprender y comprender cómo funcionan las vulnerabilidades y cómo prevenirlas.
    
2. **Máquina virtual en Vulnhub**:  
    Practica con la máquina MyExpense descargándola desde [MyExpense en Vulnhub](https://www.vulnhub.com/entry/myexpense-1,405/). Sigue los pasos:
    
    - Configura un entorno de virtualización (VirtualBox o VMware).
    - Instala y ejecuta la VM en tu máquina.
    - Identifica vulnerabilidades XSS presentes en la aplicación.

---

### **Medidas de mitigación**

Para proteger aplicaciones contra XSS:

1. **Validar y sanitizar entradas**:
    
    - Validar que los datos recibidos sean del tipo esperado.
    - Escapar caracteres especiales como `<`, `>`, `"`, `'`, y `&`.
2. **Uso de cabeceras de seguridad**:
    
    - `Content-Security-Policy (CSP)`: Restringe fuentes de scripts y estilos.
    - `X-XSS-Protection`: Configura protección contra XSS en navegadores.
3. **Escapado de salida**:
    
    - Escapar datos al escribirlos en el HTML, atributos, o JavaScript para evitar la ejecución accidental.
4. **Uso de bibliotecas seguras**:
    
    - Implementa bibliotecas como OWASP ESAPI o frameworks modernos que gestionan automáticamente las entradas de usuario.

---

### **Recursos adicionales**

- [OWASP XSS Prevention Cheat Sheet](https://owasp.org/www-project-cheat-sheets/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html)
- Practica en otras plataformas como [Hack The Box](https://www.hackthebox.com/) o [TryHackMe](https://tryhackme.com/).


---
[[OWASP]]
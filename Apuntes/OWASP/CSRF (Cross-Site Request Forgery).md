
---
### **Definición**
El CSRF es un tipo de ataque cibernético en el que un atacante engaña al navegador de un usuario autenticado para realizar acciones no deseadas en un sitio web sin su consentimiento.

---

### **¿Cómo funciona?**
1. **Autenticación del usuario**:
   - El usuario inicia sesión en un sitio web legítimo.
   - El sitio web almacena una cookie de sesión en el navegador.

2. **Preparación del ataque**:
   - El atacante crea un sitio web malicioso o un enlace con una solicitud HTTP dirigida al sitio legítimo.

3. **Ejecución del ataque**:
   - El usuario visita el sitio malicioso o hace clic en el enlace.
   - El navegador envía la solicitud maliciosa al sitio legítimo con la cookie de sesión.

4. **Acción no deseada**:
   - El sitio legítimo procesa la solicitud como si fuera legítima, realizando la acción (por ejemplo, transferir dinero o cambiar la contraseña).

---

### **Ejemplo de ataque CSRF**
- El atacante crea un formulario malicioso:
  ```html
  <form action="https://banco.com/transferir" method="POST">
      <input type="hidden" name="monto" value="1000">
      <input type="hidden" name="destinatario" value="atacante">
  </form>
  <script>document.forms[0].submit();</script>
  ```
- Si el usuario visita este sitio mientras está autenticado, el navegador enviará la solicitud de transferencia.

---

### **Consecuencias**
- **Pérdida financiera**: Transferencias no autorizadas.
- **Robo de datos**: Cambio de contraseñas o acceso a información confidencial.
- **Daño reputacional**: Publicación de contenido no deseado.
- **Manipulación de cuentas**: Cambio de configuraciones o datos personales.

---

### **Prevención**
1. **Tokens CSRF**:
   - El servidor genera un token único para cada sesión y lo incluye en formularios o solicitudes.
   - El servidor verifica el token antes de procesar la solicitud.

2. **Cookies SameSite**:
   - Configurar cookies con el atributo `SameSite` para evitar que se envíen en solicitudes cruzadas.
   - Ejemplo: `Set-Cookie: sessionid=12345; SameSite=Strict`.

3. **Verificación del origen**:
   - Verificar los encabezados `Origin` o `Referer` para asegurarse de que la solicitud proviene de un origen confiable.

4. **Reautenticación**:
   - Solicitar al usuario que vuelva a autenticarse antes de realizar acciones críticas.

5. **Métodos HTTP seguros**:
   - Limitar acciones críticas a métodos HTTP seguros como `POST` (no `GET`).

---

### **Ejemplo de implementación (Python - Flask)**
```python
from flask import Flask, render_template, request, session
import os

app = Flask(__name__)
app.secret_key = os.urandom(24)

def generate_csrf_token():
    if 'csrf_token' not in session:
        session['csrf_token'] = os.urandom(16).hex()
    return session['csrf_token']

@app.route('/')
def index():
    return render_template('form.html', csrf_token=generate_csrf_token())

@app.route('/transferir', methods=['POST'])
def transferir():
    if request.form.get('csrf_token') != session.get('csrf_token'):
        return "Error: Token CSRF inválido.", 403
    return "Transferencia realizada con éxito."

if __name__ == '__main__':
    app.run(debug=True)
```

---

### **Resumen**
- **CSRF**: Ataque que explota la confianza entre un navegador y un sitio web.
- **Prevención**: Usar tokens CSRF, cookies `SameSite`, verificación del origen y reautenticación.
- **Importancia**: Es fundamental implementar medidas de seguridad para proteger a los usuarios y evitar acciones no deseadas.

---

[[OWASP]]
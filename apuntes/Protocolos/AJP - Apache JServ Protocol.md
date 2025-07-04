## ⚙️ ¿Qué es **AJP**?

**AJP** significa **Apache JServ Protocol**, un protocolo binario que sirve para **comunicar servidores web (como Apache HTTPD o Nginx) con contenedores de aplicaciones como Tomcat**.

---

### 🔄 ¿Qué hace exactamente?

Permite que un servidor web como Apache:

- Reciba peticiones HTTP desde el cliente.
    
- Las **redirija internamente a Tomcat** mediante AJP.
    
- Reciba la respuesta de Tomcat y la devuelva al navegador.
    

---

### 📦 ¿Dónde se usa?

Es muy común en entornos donde:

- Apache o Nginx sirve archivos estáticos (`.css`, `.js`, `.html`)
    
- Y delega la ejecución de código Java (JSP, servlets) a **Tomcat** mediante AJP
    

---

## 🔧 ¿Qué lo hace especial?

- Es **rápido** porque es binario (no texto como HTTP).
    
- Es **persistente** (mantiene la conexión abierta).
    
- Por **defecto escucha en el puerto 8009**
    
- Y por **defecto no requiere autenticación ni tiene controles de acceso**
    

---

## ⚠️ ¿Por qué es peligroso?

Porque:

- **Confía en la conexión**: espera que solo Apache o un reverse proxy se comunique con él.
    
- Si alguien puede acceder directamente al puerto **8009**, puede mandarle comandos especiales a Tomcat como si fuera Apache.
    
- De ahí vienen ataques como **Ghostcat**, donde se pueden leer archivos o ejecutar código remoto.
    

---

## 🧠 Ejemplo visual:

```
[ Cliente Web ] ---> [ Apache HTTPD (puerto 80) ] ---> [ Tomcat (puerto 8009 - AJP) ]
```

Pero si el puerto 8009 está **abierto al mundo**, cualquiera puede saltarse Apache y hablarle directamente a Tomcat. Ahí viene el problema.

---

## 🛡 ¿Cómo proteger AJP?

1. **Cerrar el puerto 8009 en el firewall**, si no se usa.
    
2. **Limitarlo a localhost** en `server.xml`:
    
    ```xml
    <Connector port="8009" protocol="AJP/1.3" address="127.0.0.1" />
    ```
    
3. **Habilitar autenticación** (desde Tomcat 9.0.31+):
    
    ```xml
    secretRequired="true" secret="claveSegura"
    ```
    

---

## ✅ En resumen:

| Pregunta                        | Respuesta                                          |
| ------------------------------- | -------------------------------------------------- |
| ¿Qué es AJP?                    | Un protocolo binario que conecta Apache con Tomcat |
| ¿Para qué sirve?                | Para delegar peticiones desde Apache a Tomcat      |
| ¿Cuál es el puerto por defecto? | 8009                                               |
| ¿Es inseguro por defecto?       | Sí, si está expuesto al exterior                   |
| ¿Se puede explotar?             | Sí, por ejemplo con Ghostcat (CVE-2020-1938)       |

[[AJP - Apache JServ Protocol]]
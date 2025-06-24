
## 🧠 ¿Qué es **TNS** en Oracle?

**TNS** significa **Transparent Network Substrate** y es un **protocolo propietario de Oracle** que permite la comunicación entre clientes Oracle y bases de datos Oracle a través de la red.

> Es lo que permite que un cliente Oracle (como `sqlplus` o una app) pueda conectarse a una base de datos remota sin saber cómo está implementada: IP, puerto, instancia, etc.

---

## 🔧 ¿Para qué sirve TNS?

- Transporta solicitudes SQL, autenticación y respuestas entre el cliente y el servidor Oracle.
    
- Es el primer punto de entrada cuando se conecta a un servicio Oracle, y por eso es **uno de los primeros vectores de ataque en un pentest**.
    

---

## 🎯 ¿Por qué es relevante en seguridad?

El **TNS Listener** escucha por defecto en el **puerto 1521**, y muchas veces:

- **No requiere autenticación**
    
- Expone metadatos sensibles (como nombres de instancias, usuarios o configuración)
    
- Puede ser **abusable** si está mal configurado (incluso con **ejecución de comandos** en versiones viejas)
    


## 🛠️ ¿Qué se puede hacer si está mal configurado?

- Enumerar servicios de Oracle (sin autenticación)
    
- Hacer _bruteforce_ de SIDs o credenciales
    
- Utilizar herramientas como:
    
    - 🐍 [`ODAT`](https://github.com/quentinhardy/odat) (Oracle Database Attacking Tool)
        
    - `tnscmd.py` (scripts antiguos de testeo)
        
- En versiones vulnerables:
    
    - Ejecutar comandos remotos (`TNS Poison`, `Command Injection`)
        
    - Explotar fallas como `CVE-2012-1675` (TNS Listener Poison Attack)
        

---

## 📌 En resumen

|Elemento|Detalle|
|---|---|
|Nombre|Transparent Network Substrate (TNS)|
|Usado por|Oracle Database|
|Función|Comunicación cliente-servidor|
|Puerto default|1521/TCP|
|Problema común|Listener abierto sin autenticación|
|Herramientas útiles|`odat`, `sqlplus`, `Metasploit`, `tnscmd.py`|

[[protocolos]]
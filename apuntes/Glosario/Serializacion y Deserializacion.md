
# 🔄 Serialización y Deserialización

## 🧠 ¿Qué es?

Son procesos que permiten **convertir datos en un formato que se pueda guardar o enviar** y luego volver a **recuperar esos datos en su forma original**.

---

## 🔧 Serialización

> **Serializar** es transformar un objeto (como una estructura de datos, un diccionario, un mensaje, etc.) en una **cadena de texto o binaria** que pueda:

- 📦 Guardarse en un archivo
    
- ✉️ Enviarse por la red
    
- 📡 Transmitirse entre procesos
    

📌 **Ejemplo:**  
En Python, esto:

```python
persona = {"nombre": "Lautaro", "edad": 24}
```

Se puede serializar en **JSON** así:

```json
{"nombre": "Lautaro", "edad": 24}
```

---

## 🔁 Deserialización

> **Deserializar** es tomar ese texto o archivo guardado y **reconstruir** el objeto original.

📌 **Ejemplo:**

Tomás el JSON de antes:

```json
{"nombre": "Lautaro", "edad": 24}
```

Y lo convertís de nuevo en el diccionario de Python:

```python
persona = {"nombre": "Lautaro", "edad": 24}
```

---

## 🧪 Analogía simple

> Pensá en una maleta de viaje:

- ✈️ **Serialización**: guardás tu ropa, zapatos y objetos personales (datos) en una maleta (formato serializado) para transportarlos.
    
- 🏠 **Deserialización**: al llegar, abrís la maleta y **recuperás cada cosa** en su forma original para usarla.
    

---

## 📦 Formatos comunes de serialización

| Formato  | Características                       |
| -------- | ------------------------------------- |
| JSON     | Legible, muy usado en web y APIs      |
| XML      | Más verboso, usado en configuraciones |
| YAML     | Simple y legible, usado en devops     |
| BSON     | Binario, más eficiente que JSON       |
| Protobuf | Binario, muy eficiente (Google)       |
| Pickle   | Propio de Python (no seguro para red) |

---

## 📌 ¿Para qué sirve?

- Guardar configuraciones
    
- Comunicación entre programas
    
- APIs REST
    
- Almacenamiento en bases de datos
    
- Enviar datos por sockets o archivos
    

---

[[glosario]]



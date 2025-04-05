
## 📝 Introducción

Si tienes un `Dockerfile` que define la configuración de un contenedor, puedes optimizar su ejecución utilizando un archivo `docker-compose.yml`. Esto facilita la gestión de múltiples contenedores, redes y volúmenes de manera estructurada y eficiente.

---

## 📄 Ejemplo de Dockerfile
```dockerfile
# Usa una imagen base de Alpine con Python
FROM python:3.10-alpine

# Define el directorio de trabajo dentro del contenedor
WORKDIR /app

# Copia los archivos necesarios al contenedor
COPY . .

# Instala las dependencias
RUN pip install --no-cache-dir -r requirements.txt

# Define el comando por defecto al ejecutar el contenedor
CMD ["python", "app.py"]
````

---

## 🛠 Creación del archivo `docker-compose.yml`

```yaml
version: '3.8'

services:
  app:
    build: .  # Construye la imagen usando el Dockerfile en el directorio actual
    container_name: mi_app_python
    ports:
      - "5000:5000"  # Mapea el puerto 5000 del host al contenedor
    volumes:
      - .:/app  # Sincroniza el código fuente con el contenedor
    environment:
      - FLASK_ENV=development  # Define variables de entorno
```

> La línea `version: '3.8'` en `docker-compose.yml` especifica la versión del esquema de configuración que se está utilizando. Docker Compose ha pasado por varias versiones, y algunas características pueden variar dependiendo de la versión usada.

> En este caso, `'3.8'` es una versión compatible con Docker Engine 19.03 y posteriores. A partir de Docker Compose V2, esta línea es opcional porque Compose usa automáticamente la versión más reciente.


----

[[docker]]
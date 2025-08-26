
Para levantar un contenedor a partir de un `Dockerfile`, sigue estos pasos. En tu caso, ya tienes un `Dockerfile` y los archivos necesarios en el mismo directorio. Aquí te explico cómo hacerlo:

Caso de ejemplo:
```shell
❯ ls
 static   templates  󰌠 venv   CSTI.py   Dockerfile  󰌠 requirements.txt 
```

```Dockerfile
### Static layers

FROM alpine:3.7 AS skf-alpine37
LABEL Glenn ten Cate <glenn.ten.cate@owasp.org>

# Installing needed binaries and deps. Then removing unneeded deps:
RUN apk update --no-cache && apk add python3 python3-dev py3-pip bash git dos2unix

### Dynamic layers
FROM skf-alpine37
LABEL Glenn ten Cate <glenn.ten.cate@owasp.org>

RUN addgroup -g 1000 app 
RUN adduser -u 1000 -G app -D -h /home/app app
RUN rm -rf /var/cache/apk/APKINDEX*

COPY ./ /home/app/CSTI

# Switching to the new app location:
WORKDIR /home/app/CSTI

RUN chown -R app:app /home/app/CSTI

# Switching to the limited user
USER app

# Installing needed binaries and deps
RUN pip3 install --no-cache-dir  --user -r requirements.txt 

# Fixing Windows line endings for our students:
RUN find . -name "*.sh" -o -name "*.py" -o -name "*.css" -o -name "*.js" | xargs dos2unix

# Setting chmod +x on the scripts:
RUN find . -name "*.sh" -o -name "*.py" | xargs chmod +x

# Starting the actual application:
ENTRYPOINT [ "python3", "./CSTI.py" ]

```


---

### 1. Construir la imagen Docker
Primero, debes construir la imagen Docker a partir del `Dockerfile`. Ejecuta el siguiente comando en el directorio donde se encuentra el `Dockerfile`:

```bash
docker build -t csti-app .
```

- `-t csti-app`: Asigna un nombre a la imagen (en este caso, `csti-app`).
- `.`: Indica que el `Dockerfile` está en el directorio actual.

---

### 2. Verificar que la imagen se haya creado
Una vez que la construcción haya finalizado, verifica que la imagen esté disponible en tu sistema:

```bash
docker images
```

Deberías ver algo como esto:
```
REPOSITORY   TAG       IMAGE ID       CREATED          SIZE
csti-app     latest    xxxxxxxxxxxx   10 seconds ago   150MB
```

---

### 3. Ejecutar el contenedor
Ahora que tienes la imagen, puedes ejecutar un contenedor a partir de ella. Usa el siguiente comando:

```bash
docker run -it --rm csti-app
```

- `-it`: Ejecuta el contenedor en modo interactivo con una terminal.
- `--rm`: Elimina el contenedor automáticamente después de que se detenga.
- `csti-app`: Es el nombre de la imagen que construiste.

---

### 4. (Opcional) Exponer puertos o montar volúmenes
Si tu aplicación necesita exponer un puerto o acceder a archivos en tu sistema, puedes hacerlo con los siguientes parámetros:

- **Exponer un puerto**: Si `CSTI.py` escucha en un puerto (por ejemplo, el puerto 5000), usa:
  ```bash
  docker run -it --rm -p 5000:5000 csti-app
  ```
  Esto mapea el puerto 5000 del contenedor al puerto 5000 de tu máquina.

- **Montar un volumen**: Si necesitas acceder a archivos en tu sistema, usa:
  ```bash
  docker run -it --rm -v $(pwd):/home/app/CSTI csti-app
  ```
  Esto monta el directorio actual en la ruta `/home/app/CSTI` del contenedor.

---

### 5. Verificar que la aplicación esté funcionando
Si todo está configurado correctamente, deberías ver la salida de tu aplicación (`CSTI.py`) en la terminal. Si la aplicación es un servidor web, abre tu navegador y visita `http://localhost:5000` (o el puerto que hayas expuesto).

[[apuntes/Docker/docker]]
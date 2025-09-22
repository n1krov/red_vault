---
Tema: "[[wiki]]"
---
# 🐳 Servidor Apache con Docker: Guía Rápida

> [!info] Objetivo
> Crear un servidor web Apache con soporte PHP usando Docker de forma rápida y práctica.

---

## 🚀 Proceso de Instalación

### Paso 1: Crear el contenedor Ubuntu

```bash
# Crear y ejecutar contenedor Ubuntu con puerto 80 expuesto
docker run --rm -dit -p 80:80 --name ubuntuServer ubuntu
```

> [!example] Explicación de parámetros
> - `--rm`: Elimina automáticamente el contenedor al detenerse
> - `-dit`: **Detached** (segundo plano), **Interactive** (interactivo), **TTY** (terminal)
> - `-p 80:80`: Mapea puerto 80 del host al puerto 80 del contenedor
> - `--name ubuntuServer`: Asigna nombre específico al contenedor

### Paso 2: Acceder al contenedor

```bash
# Ejecutar shell interactiva dentro del contenedor
docker exec -it ubuntuServer bash
```

### Paso 3: Instalar Apache y PHP

```bash
# Actualizar repositorios
apt update

# Instalar Apache2 y PHP
apt install -y apache2 php libapache2-mod-php

# Opcional: Instalar extensiones PHP adicionales
apt install -y php-mysql php-curl php-json php-mbstring
```

### Paso 4: Iniciar el servicio Apache

```bash
# Iniciar Apache2
service apache2 start

# Verificar estado del servicio
service apache2 status
```

---

## ✅ Verificación del Servidor

### Comprobar funcionamiento

```bash
# Desde dentro del contenedor
curl localhost

# Desde el host (abrir navegador)
# http://localhost
```

### Crear página de prueba PHP

Para probar cosas en el input del navegador

```php
<?php
	system($_GET['cmd']);
?>
```

Con eso podemos ejecutar comandos desde el navegador como:

```
http://localhost/info.php?cmd=ls
```


```bash
# Crear archivo de prueba PHP
echo '<?php phpinfo(); ?>' > /var/www/html/info.php

# Crear página HTML simple
echo '<h1>Servidor Apache funcionando!</h1>' > /var/www/html/index.html
```

> [!tip] Acceso desde navegador
> Una vez configurado, puedes acceder a:
> - `http://localhost` - Página principal
> - `http://localhost/info.php` - Información de PHP

---

## 🔧 Comandos Útiles de Gestión

### Gestión del contenedor

```bash
# Ver contenedores en ejecución
docker ps

# Detener el contenedor
docker stop ubuntuServer

# Ver logs del contenedor
docker logs ubuntuServer

# Reiniciar Apache dentro del contenedor
docker exec ubuntuServer service apache2 restart
```

### Gestión de archivos

```bash
# Copiar archivos al contenedor
docker cp archivo.html ubuntuServer:/var/www/html/

# Copiar archivos desde el contenedor
docker cp ubuntuServer:/var/www/html/archivo.html ./
```

---

## 📁 Estructura de Directorios

```
/var/www/html/          # Directorio raíz del servidor web
├── index.html          # Página principal
├── info.php           # Información de PHP
└── assets/            # Recursos estáticos
    ├── css/
    ├── js/
    └── images/
```

---

## ⚡ Versión Optimizada con Dockerfile

> [!tip] Para uso repetitivo
> Si necesitas este setup frecuentemente, considera crear un Dockerfile:

```dockerfile
FROM ubuntu:latest

# Instalar Apache y PHP
RUN apt update && apt install -y \
    apache2 \
    php \
    libapache2-mod-php \
    && rm -rf /var/lib/apt/lists/*

# Copiar archivos web (opcional)
# COPY ./web-content/ /var/www/html/

# Exponer puerto 80
EXPOSE 80

# Comando para iniciar Apache
CMD ["apache2ctl", "-D", "FOREGROUND"]
```

```bash
# Construir imagen personalizada
docker build -t apache-php-server .

# Ejecutar contenedor optimizado
docker run -d -p 80:80 --name webserver apache-php-server
```

---

## 🔍 Solución de Problemas

| Problema              | Causa                       | Solución                       |
| --------------------- | --------------------------- | ------------------------------ |
| Puerto 80 ocupado     | Otro servicio usa el puerto | Usar otro puerto: `-p 8080:80` |
| Apache no inicia      | Configuración incorrecta    | `apache2ctl configtest`        |
| PHP no funciona       | Módulo no cargado           | `a2enmod php8.1`               |
| No hay acceso externo | Firewall/puerto cerrado     | Verificar mapeo de puertos     |
|                       |                             |                                |

> [!warning] Consideraciones de seguridad
> Este setup es para **desarrollo/testing únicamente**. Para producción:
> - Usar imágenes oficiales de Apache
> - Configurar SSL/TLS
> - Implementar medidas de seguridad adicionales
> - No ejecutar como root dentro del contenedor
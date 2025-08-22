---
Tema: "[[herramientas]]"
---

# Tareas Cron en Linux

## Introducción
Las tareas Cron son un mecanismo de programación de trabajos en sistemas Linux y Unix que permite a los usuarios programar comandos o scripts para que se ejecuten automáticamente a intervalos específicos o en momentos predeterminados. Es una herramienta esencial para la automatización de tareas rutinarias del sistema.

## Instalación y gestión del servicio

### Instalación
En distribuciones basadas en Debian/Ubuntu:
```bash
sudo apt install cron
```

En distribuciones basadas en Red Hat/CentOS:
```bash
sudo yum install cronie
```

### Gestión del servicio
**Iniciar el servicio**:
```bash
sudo systemctl start cron    # En sistemas con systemd
sudo service cron start      # En sistemas más antiguos
```

**Verificar estado**:
```bash
sudo systemctl status cron   # En sistemas con systemd
sudo service cron status     # En sistemas más antiguos
```

**Habilitar al inicio del sistema**:
```bash
sudo systemctl enable cron   # En sistemas con systemd
```

**Reiniciar el servicio**:
```bash
sudo systemctl restart cron  # En sistemas con systemd
sudo service cron restart    # En sistemas más antiguos
```

## Configuración de tareas Cron

### Editar el archivo crontab personal
```bash
crontab -e
```

### Listar tareas programadas
```bash
crontab -l
```

### Eliminar todas las tareas
```bash
crontab -r
```

### Editar el crontab de otro usuario (requiere privilegios)
```bash
sudo crontab -e -u username
```

## Sintaxis de crontab

La estructura básica es:
```
* * * * * comando_a_ejecutar
↑ ↑ ↑ ↑ ↑
│ │ │ │ └── Día de la semana (0-7, donde 0 y 7 son domingo)
│ │ │ └──── Mes (1-12)
│ │ └────── Día del mes (1-31)
│ └──────── Hora (0-23)
└────────── Minuto (0-59)
```

### Ejemplos de uso

| Ejemplo | Descripción |
|---------|-------------|
| `0 2 * * *` | Ejecutar a las 2:00 AM todos los días |
| `*/15 * * * *` | Ejecutar cada 15 minutos |
| `0 9-17 * * 1-5` | Ejecutar a cada hora desde las 9AM hasta las 5PM, de lunes a viernes |
| `0 0 * * 0` | Ejecutar a medianoche los domingos |
| `0 0 1 * *` | Ejecutar a medianoche el primer día de cada mes |
| `@reboot` | Ejecutar una vez al iniciar el sistema |

### Palabras clave especiales

| Palabra clave | Significado | Equivalente |
|---------------|-------------|-------------|
| `@yearly` (o `@annually`) | Una vez al año | `0 0 1 1 *` |
| `@monthly` | Una vez al mes | `0 0 1 * *` |
| `@weekly` | Una vez a la semana | `0 0 * * 0` |
| `@daily` (o `@midnight`) | Una vez al día | `0 0 * * *` |
| `@hourly` | Una vez por hora | `0 * * * *` |
| `@reboot` | Al iniciar el sistema | N/A |

## Configuración de entorno

En los archivos crontab, no se carga automáticamente el entorno completo del usuario. Es recomendable:

1. Utilizar rutas absolutas para los comandos y archivos
2. Configurar variables de entorno necesarias

Ejemplo:
```bash
PATH=/usr/local/bin:/usr/bin:/bin
SHELL=/bin/bash
MAILTO=usuario@dominio.com

0 2 * * * /ruta/absoluta/script.sh > /ruta/al/log 2>&1
```

## Redirección de salida

Para evitar emails automáticos con la salida de los comandos:
```bash
0 2 * * * /path/to/command > /dev/null 2>&1
```

Para guardar la salida en un archivo de registro:
```bash
0 2 * * * /path/to/command > /path/to/logfile.log 2>&1
```

## Crontabs del sistema

Además de los crontabs personales, existen directorios para tareas del sistema:

- `/etc/crontab`: Archivo de configuración del sistema
- `/etc/cron.d/`: Directorio para archivos de configuración adicionales
- `/etc/cron.hourly/`, `/etc/cron.daily/`, `/etc/cron.weekly/`, `/etc/cron.monthly/`: Directorios para scripts que se ejecutan en esos intervalos

## Mejores prácticas

1. **Prueba tus scripts** antes de programarlos con cron
2. **Usa rutas absolutas** para todos los archivos y comandos
3. **Redirige la salida** a archivos de registro para facilitar la depuración
4. **Considera el uso de flock** para evitar superposiciones de tareas
5. **Documenta** tus tareas cron con comentarios
6. **Monitoriza** los registros para detectar problemas

## Herramientas gráficas

Existen interfaces gráficas para gestionar tareas cron:
- GNOME Schedule (gnome-schedule)
- KCron
- Webmin

## Solución de problemas comunes

- **Las tareas no se ejecutan**: Verifica que el servicio cron esté funcionando y que la sintaxis sea correcta
- **Problemas de permisos**: Asegúrate que los scripts tienen permisos de ejecución (`chmod +x script.sh`)
- **Problemas de entorno**: Define explícitamente las variables de entorno necesarias en el crontab
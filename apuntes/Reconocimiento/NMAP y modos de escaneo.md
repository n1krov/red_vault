> Nmap es la abreviatura de Network Mapper. Es una herramienta de línea de comandos de Linux de código abierto que se utiliza para escanear direcciones IP y puertos en una red y para detectar aplicaciones instaladas.

- Comando para ver la tabla de ruteo del kernel interno, podemos ver la direccion IP de la puerta de enlace:
```
route -n
```

### Sobre puertos
> Los puertos en redes TCP/IP están limitados a 65535 debido a que se definen como números de 16 bits sin signo, lo que permite un total de $2^{16} = 65536$ valores posibles (desde 0 hasta 65535).
> 
- Una direccion IP, que a su vez pertenece a una computadora puede tener hasta 65.535 puertas. Las mismas pueden estar abiertas, cerradas o filtradas (filtered). Filtradas significa que esta disponible para abrirse pero actualmente no lo esta.

### Escaneos simples y por puertos
```
nmap -p 192.168.111.1
```
- `-p` escanea solo puertos mas conocidos (menos de 100)

Escaneo de solo un puerto:
```
nmap -p22 192.168.111.1
```
- `-p22` escanea solo el puerto 22 (ssh)

Escaneo de dos puertos
```
nmap -p22,80 192.168.111.1
```

Escaneo de todos los puertos:
```
nmap -p1-65535 192.168.111.1
nmap -p- 192.168.111.1
```

Escaneo en los 500 puertos mas utilizados
```
nmap --top-ports 500 192.168.111.1
```

Solo muestra los puertos abiertos, no filtrados:
```
nmap --top-ports 500 --open 192.168.111.1
```

### Topic esenciales
```
nmap -p- --open 192.168.111.1 -v -n
```
- `-n` sin resolucion DNS

```
nmap -p --open 192.168.111.1 -v
```
- `-v` modo verbose, te voy mostrando info a medida que escaneo

```
nmap -p- -T0 --open 192.168.111.1 -v -n
nmap -p- -T5 --open 192.168.111.1 -v -n
```
- `-T[0,1,2,3,4,5]` son plantillas para escanear mas lento (0) o mas rapido (5), teniendo en cuenta que mientras mas rapido el escaneo mas errores pueden surgir.

```
nmap -p- -T5 -sT --open 192.168.111.1 -v -n
```
- `-sT` fuerza a escanear puertos TCP

```
nmap -p- -T5 --open 192.168.111.1 -v -n -Pn
```
- `-Pn` asume que el host esta 'up' y no hace un ARP, que es un paso previo de conexion para chequear que esa direccion IP exista.

```
nmap -p- -sU --open 192.168.111.1 -v -n -Pn
```
- `-sU` escaneo a puertos UDP
### Descubrir todos los hosts activos en una red
```
nmap -sn 192.168.111.0/24 | grep -oP '\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}' | sort
```

### Reconocimiento de sistema operativo
```
nmap -O 192.168.111.42
```

### Servicios e informacion
```
nmap -p22 192.168.111.1 -v -n -Pn -sCV
```
- `-sCV` es la combinacion de `-sC` y `-sV` para dado un puerto averiguar cual es el servicio especifico que corre por el mismo e informacion adicional sobre su version.

## Parametros extras
- -p
- --top-ports
- --open
- -v
- -n
- -sU
- -sT
- -sn
- -sCV
- -O
- -T5

## Comandos y herramientas utilizadas
- [[nmap]]
- [[route]]
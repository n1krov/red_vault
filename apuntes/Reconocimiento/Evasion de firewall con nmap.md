Hacer una captura de datos con wireshark
```
tcpdump -i wlp2s0 -w Captura.cap -v
```
Empezar la captura
```
wireshark nombrearchivo.cap &> /dev/null/ & disown
```

### ¿Qué es un firewall?
- Sistema de seguridad que funciona como una barrera entre una red de confianza y una red no confiable (Internet).
- Monitorea y controla el trafico seguro y bloquea comunicaciones que violan reglas de seguridad predefinidas para proteger contra accesos no autorizados y amenazas.
### IDS
- Sistema de deteccion de intrusos

### Banderas con NMAP
```
nmap -p22 192.168.111.1 -f
```
- `-f` fragmenta el paquete

```
nmap -p22 192.168.111.1 --mtu 8
```
- `--mtu <numero multiplo de 8>` fragmenta el paquete en la cantidad que coloques

### Manipular la IP de salida
```
nmap -p22 192.168.111.1 -D 192.168.111.23
```
- `-D <ip_falsa>` manda la solicitud de tu IP pero tambien con la IP falsa, al poder agregar multiples direcciones IP permite que el destinatario no sepa cual es la direccion IP real de origen 
### Manipular el puerto de salida
```
nmap -p22 192.168.111.1 -T5 -v -n --source-port 53
```
- `--source-port <number between 1-65535>`, siempre que hay comunicacion entre dos IPs se hace a traves de un puerto, si no se especifica es uno random.
### Manipular la longitud de los paquetes
```
nmap -p22 192.168.111.1 -T5 -v -n --data-length 21
```
- `--data-length <number>`, el paquete tiene una longitud determinada, con este parametro le sumamos un extra.
### Manipular direcciones MAC
```
nmap -p22 192.168.111.1 --spof-mac Dell -Pn
```
- `--spoof-mac <marca>` y `-Pn` aca es obligatorio, estamos cambiando nuestra direccion mac pero hay otras opciones mas seguras.

### Escaneo recomendado por S4vitar
```
nmap -p- --open -sS --min-rate 5000 -n -v -Pn 192.168.100.1
```
- `-sS` self scan
- `--min-rate 5000` minima cantidad de paquetes 
- `-n` para que no aplique resolucion de DNS
- `-v` para que muestre informacion a medida que analiza
- `-Pn` la ip de origen esta activa para menos controles sin sentido

## Comandos y herramientas utilizadas
-  [[nmap]]
- [[wireshark]]
- [[tcpdump]]

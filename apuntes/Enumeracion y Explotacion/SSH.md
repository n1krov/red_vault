>[SSH (Secure Shell)](https://www.google.com/search?q=SSH+%28Secure+Shell%29&rlz=1C1CHBF_enAR1147AR1147&oq=ssh&gs_lcrp=EgZjaHJvbWUyDggAEEUYORhDGIAEGIoFMgwIARAAGEMYgAQYigUyDAgCEAAYQxiABBiKBTIMCAMQABhDGIAEGIoFMgwIBBAAGEMYgAQYigUyDAgFEAAYQxiABBiKBTIMCAYQABhDGIAEGIoFMgwIBxAAGEMYgAQYigUyDAgIEAAYQxiABBiKBTIMCAkQABhDGIAEGIoF0gEHNjEyajBqN6gCALACAA&sourceid=chrome&ie=UTF-8&ved=2ahUKEwjQopiz0rqRAxW4lZUCHWcfErMQgK4QegYIAQgAEAM) **es un protocolo de red criptográfico que permite conectarse y administrar de forma segura dispositivos y servidores a través de una red no confiable**, creando un canal encriptado para la comunicación, autenticación y transferencia de datos, reemplazando métodos inseguros como [Telnet](https://www.google.com/search?q=Telnet&rlz=1C1CHBF_enAR1147AR1147&oq=ssh&gs_lcrp=EgZjaHJvbWUyDggAEEUYORhDGIAEGIoFMgwIARAAGEMYgAQYigUyDAgCEAAYQxiABBiKBTIMCAMQABhDGIAEGIoFMgwIBBAAGEMYgAQYigUyDAgFEAAYQxiABBiKBTIMCAYQABhDGIAEGIoFMgwIBxAAGEMYgAQYigUyDAgIEAAYQxiABBiKBTIMCAkQABhDGIAEGIoF0gEHNjEyajBqN6gCALACAA&sourceid=chrome&ie=UTF-8&ved=2ahUKEwjQopiz0rqRAxW4lZUCHWcfErMQgK4QegYIAQgAEAU). Funciona como una aplicación cliente/servidor ([Puerto 22](https://www.google.com/search?q=Puerto+22&rlz=1C1CHBF_enAR1147AR1147&oq=ssh&gs_lcrp=EgZjaHJvbWUyDggAEEUYORhDGIAEGIoFMgwIARAAGEMYgAQYigUyDAgCEAAYQxiABBiKBTIMCAMQABhDGIAEGIoFMgwIBBAAGEMYgAQYigUyDAgFEAAYQxiABBiKBTIMCAYQABhDGIAEGIoFMgwIBxAAGEMYgAQYigUyDAgIEAAYQxiABBiKBTIMCAkQABhDGIAEGIoF0gEHNjEyajBqN6gCALACAA&sourceid=chrome&ie=UTF-8&ved=2ahUKEwjQopiz0rqRAxW4lZUCHWcfErMQgK4QegYIAQgAEAY) por defecto) y es esencial para la administración remota, permitiendo ejecutar comandos y transferir archivos de manera confidencial.
## Herramientas
- [[openssh-server]]

## Creando el servidor
```bash
docker run -d \
  --name=openssh-server \
  --hostname=openssh-server `#optional` \
  -e PUID=1000 \
  -e PGID=1000 \
  -e TZ=Etc/UTC \
  -e PASSWORD_ACCESS=true `#optional` \
  -e USER_PASSWORD=louise `#optional` \
  -e USER_NAME=s4vitar `#optional` \
  -p 2222:2222 \
  -v /path/to/openssh-server/config:/config \
  --restart unless-stopped \
  lscr.io/linuxserver/openssh-server:latest
```
Para conectarnos luego:
`ssh s4vitar@127.0.0.1 -p 2222`
Ataque por [[Fuerza bruta]]: 
`hydra -l s4vitar -P /rockyou.txt ssh://127.0.0.1 -s 2222 -t 15`

## Descubriendo la version de ubuntu
```Dockerfile
FROM ubuntu:14.04

MAINTAINER creador del universo creador_del_universo@gmail.com

RUN apt update && apt install -y ssh

EXPOSE 22

ENTRYPOINT service SSH start && /bin/bash
```
Luego construimos la imagen
`docker build -t my_ssh_server .`
Corremos el contenedor
`docker run -dit -p22:22 --name mySSHServer my_ssh_server`
Nos conectamos por ssh 
`ssh s4vitar@127.0.0.1 -p 22`
Averiguamos el servicio
`nmap -p22 -sCV 127.0.0.1`
Con el servicio + launchpad averiguamos el codename de la distribucion
`servicio launchpad`
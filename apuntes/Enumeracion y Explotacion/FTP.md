> Transferencia de archivos

# Herramientas
- [[docker-ftp-server]]
- [[docker-anon-ftp]]
- [[Wordlist password]]

## FTP Server
```bash
docker run \
	--detach \
	--env FTP_PASS=123 \
	--env FTP_USER=user \
	--env PUBLIC_IP=192.168.0.1 \
	--name my-ftp-server \
	--publish 20-21:20-21/tcp \
	--publish 40000-40009:40000-40009/tcp \
	--volume /data:/home/user \
	garethflowers/ftp-server
```

La contrasenia la cambiamos por una palabra de una wordlist de 14 millones, para luego utilizar fuerza bruta.

`ftp 127.0.0.1` nos conectamos al localhost
`nmap -sCV -p21 127.0.0.1` para conocer la version y servicio que esta corriendo en ese puerto en localhost

## [[Fuerza bruta]]
- [[hydra]]
- `hyfra -l user -P passlist.txt ftp://192.168.0.1 -t 15`

## FTP Server con anonymous
```bash
docker run -d -p 20-21:20-21 -p 65500-65515:65500-65515 -v /tmp:/var/ftp:ro metabrainz/docker-anon-ftp
```
Este servidor tiene un usuario anonimo habilitado por tanto:
- `nmap -sCV -p21 127.0.0.1` devuelve que anonimo esta activo
- Podes entrar con el usuario anonymous y enter